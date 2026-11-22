package authorization

import (
	"context"
	"errors"
	"maps"
	"slices"

	"github.com/jackc/pgx/v5"
	"github.com/plystra/auth/internal/apierr"
	"github.com/plystra/auth/internal/authz/delta"
	"github.com/plystra/auth/internal/authz/engine"
	"github.com/plystra/auth/internal/db"
)

// CheckSSOConnectionCreateTx authorizes the connection and its prospective
// role grants. First login creates a human in the connection's own Space,
// even when descendants inherit its discovery route.
func (s *Service) CheckSSOConnectionCreateTx(ctx context.Context, q *db.Queries, actorID, spaceID, connectionID string, mappings map[string]string) error {
	if err := lockHumanActorAccountTx(ctx, q, actorID); err != nil {
		return err
	}
	roleIDs := slices.Compact(slices.Sorted(maps.Values(mappings)))
	missing := false
	for _, id := range roleIDs {
		_, err := q.LockRoleInSpace(ctx, db.LockRoleInSpaceParams{SpaceID: spaceID, ID: id})
		if errors.Is(err, pgx.ErrNoRows) {
			missing = true
		} else if err != nil {
			return err
		}
	}
	// Acquire role locks before member and node locks, but disclose no role
	// information until the caller's current management authority is proven.
	decision, err := s.CheckMutationTx(ctx, q, CheckRequest{MemberID: actorID, Permission: "auth.connections:manage", ResourceSpace: spaceID})
	if err != nil {
		return err
	}
	if decision.Effect != engine.Allow {
		return &apierr.Error{Code: decision.Code, Message: "The authorization engine denied this operation."}
	}
	if missing {
		return apierr.New("validation_failed", "role mapping references a role outside this Space")
	}
	position := delta.Node{Kind: delta.Space, ID: spaceID}
	scope := delta.Scope{Kind: delta.SpaceOnly, Anchor: spaceID}
	var after delta.Snapshot
	for _, id := range roleIDs {
		if err := validateOrdinaryGrantRoleTx(ctx, q, id); err != nil {
			return err
		}
		permissions, err := q.ListRolePermissions(ctx, db.ListRolePermissionsParams{RoleID: id})
		if err != nil {
			return err
		}
		for _, permission := range permissions {
			after.Permissions = append(after.Permissions, delta.Permission{Subject: connectionID, Position: position, Scope: scope, Key: permission.Key})
		}
	}
	change, err := delta.Evaluate(delta.Snapshot{}, after, delta.Graph{})
	if err != nil || len(change.Permissions) == 0 {
		return err
	}
	if err := s.authorizeGroupTx(ctx, q, actorID, "auth.grants:assign", spaceID, ""); err != nil {
		return err
	}
	// The future human has no member ID yet. The receiving Space and grant
	// anchor are already known and remain the same for every mapped role.
	return s.coverPositiveGrantDeltaTx(ctx, q, change, actorID, "", "human", spaceID)
}
