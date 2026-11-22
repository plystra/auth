package authorization

import (
	"context"
	"slices"

	"github.com/plystra/auth/internal/apierr"
	"github.com/plystra/auth/internal/authz/delta"
	"github.com/plystra/auth/internal/db"
)

// HumanActorUserID identifies the verified account that configured automation.
// Persisting both identities prevents a revoked shared binding from continuing
// to exercise another user's authority through that automation.
func HumanActorUserID(ctx context.Context, memberID string) string {
	actor, _ := ctx.Value(humanActorKey{}).(humanActor)
	if actor.memberID == memberID {
		return actor.userID
	}
	return ""
}

// LockProvisioningTx stabilizes provisioning targets before the directory lock.
// Match account -> member/owner -> Space/group order used by governance writes.
// This only acquires locks; the directory credential and positive delta must be
// checked separately in the same transaction.
func LockProvisioningTx(ctx context.Context, q *db.Queries, spaceID string, userIDs, memberIDs []string) error {
	if err := lockProvisioningUsersTx(ctx, q, userIDs); err != nil {
		return err
	}
	if err := lockAuthorizationMembersTx(ctx, q, memberIDs...); err != nil {
		return err
	}
	return lockAuthorizationNodesTx(ctx, q, spaceID, "")
}

func lockProvisioningUsersTx(ctx context.Context, q *db.Queries, userIDs []string) error {
	users := slices.Clone(userIDs)
	slices.Sort(users)
	for _, id := range slices.Compact(users) {
		if id != "" {
			if _, err := q.LockUserForAuthorization(ctx, db.LockUserForAuthorizationParams{ID: id}); err != nil {
				return err
			}
		}
	}
	return nil
}

// ApplyDirectoryAuthorityTx uses the ordinary before/after evaluator for both
// group synchronization and binding reactivation. Callers already hold every
// affected account/member and governing node lock. Preview the deterministic
// database-only mutation under a savepoint, then restore it before checking the
// configurator: automation cannot use newly acquired authority to cover itself.
// Apply once more only after coverage succeeds. No configurator is invented
// for old directories: any positive delta then fails closed.
func (s *Service) ApplyDirectoryAuthorityTx(ctx context.Context, q *db.Queries, actorID, spaceID, groupID string, memberIDs []string, mutate func() error) error {
	before := make(map[string]delta.Snapshot, len(memberIDs))
	kinds := make(map[string]string, len(memberIDs))
	for _, id := range memberIDs {
		m, err := q.GetMemberForAuthorization(ctx, db.GetMemberForAuthorizationParams{ID: id})
		if err != nil {
			return err
		}
		kinds[id] = m.Type
		snapshot, err := s.provisioningAuthoritySnapshotTx(ctx, q, id, spaceID, kinds[id])
		if err != nil {
			return err
		}
		before[id] = snapshot
	}
	if err := q.BeginDirectoryAuthorityPreview(ctx); err != nil {
		return err
	}
	if err := mutate(); err != nil {
		return err
	}
	changes := make(map[string]delta.Result, len(memberIDs))
	for _, id := range memberIDs {
		after, err := s.provisioningAuthoritySnapshotTx(ctx, q, id, spaceID, kinds[id])
		if err != nil {
			return err
		}
		change, err := delta.Evaluate(before[id], after, delta.Graph{})
		if err != nil {
			return err
		}
		changes[id] = change
	}
	if err := q.RestoreDirectoryAuthorityPreview(ctx); err != nil {
		return err
	}
	for _, id := range memberIDs {
		change := changes[id]
		if len(change.Permissions) == 0 && len(change.Rights) == 0 {
			continue
		}
		if actorID == "" {
			return apierr.New("AUTHORITY_DELTA_NOT_COVERED", "rotate the directory token to establish a current configurator before granting authority")
		}
		if err := s.authorizeGroupTx(ctx, q, actorID, "auth.connections:manage", spaceID, ""); err != nil {
			return err
		}
		if groupID == "" {
			if err := s.authorizeGroupTx(ctx, q, actorID, "auth.bindings:manage", spaceID, ""); err != nil {
				return err
			}
		}
		if len(change.Permissions) != 0 {
			if err := s.authorizeGroupTx(ctx, q, actorID, "auth.grants:assign", spaceID, groupID); err != nil {
				return err
			}
		}
		if len(change.Rights) != 0 {
			if err := s.authorizeGroupTx(ctx, q, actorID, "auth.assign_rights:manage", spaceID, groupID); err != nil {
				return err
			}
		}
		if err := s.coverPositiveGrantDeltaTx(ctx, q, change, actorID, id, kinds[id], spaceID); err != nil {
			return err
		}
	}
	if err := mutate(); err != nil {
		return err
	}
	return q.EndDirectoryAuthorityPreview(ctx)
}

func (s *Service) provisioningAuthoritySnapshotTx(ctx context.Context, q *db.Queries, memberID, spaceID, kind string) (delta.Snapshot, error) {
	snapshot, err := s.grantAuthoritySnapshotTx(ctx, q, memberID, spaceID, kind)
	if err != nil {
		return delta.Snapshot{}, err
	}
	if kind == "human" {
		count, err := q.CountActiveMemberBindings(ctx, db.CountActiveMemberBindingsParams{MemberID: memberID})
		if err != nil {
			return delta.Snapshot{}, err
		}
		if count == 0 {
			return snapshot, nil
		}
	}
	snapshot.Rights, err = s.assignmentRightsSnapshotTx(ctx, q, memberID)
	return snapshot, err
}
