package authorization

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"
	"github.com/plystra/auth/internal/apierr"
	"github.com/plystra/auth/internal/audit"
	"github.com/plystra/auth/internal/authz/delta"
	"github.com/plystra/auth/internal/authz/engine"
	"github.com/plystra/auth/internal/db"
)

// AddMemberToGroup applies the group-membership change and its authority
// delta in one transaction. The target group is a resource fact for both
// management checks, so a group-scoped manager cannot widen its authority by
// choosing a different member target.
func (s *Service) AddMemberToGroup(ctx context.Context, actorMemberID, spaceID, groupID, memberID string) error {
	if actorMemberID == "" || spaceID == "" || groupID == "" || memberID == "" {
		return apierr.New("VALIDATION_FAILED", "group membership fields are required")
	}
	return s.Store.InTx(ctx, func(q *db.Queries) error {
		if err := lockAuthorizationMembersTx(ctx, q, actorMemberID, memberID); err != nil {
			return err
		}
		group, err := q.LockGroupInSpaceForAuthorization(ctx, db.LockGroupInSpaceForAuthorizationParams{ID: groupID, SpaceID: spaceID})
		if errors.Is(err, pgx.ErrNoRows) {
			return apierr.New("NOT_FOUND", "group was not found in this Space")
		}
		if err != nil {
			return err
		}
		member, err := q.LockMemberInSpace(ctx, db.LockMemberInSpaceParams{ID: memberID, SpaceID: spaceID})
		if errors.Is(err, pgx.ErrNoRows) {
			return apierr.New("NOT_FOUND", "member was not found in this Space")
		}
		if err != nil {
			return err
		}
		if group.Kind == "agents" {
			return apierr.New("PERMISSION_DENIED", "Agent-owned groups cannot be edited manually")
		}
		if group.Status != "active" {
			return apierr.New("GROUP_INACTIVE", "group is not active")
		}
		if member.Status != "active" {
			return apierr.New("ACTOR_MEMBER_INACTIVE", "member is not active")
		}
		if err := lockAuthorizationNodesTx(ctx, q, spaceID, groupID); err != nil {
			return err
		}
		if err := s.authorizeGroupTx(ctx, q, actorMemberID, "auth.groups:manage", spaceID, groupID); err != nil {
			return err
		}
		_, membershipErr := q.GetGroupMember(ctx, db.GetGroupMemberParams{GroupID: groupID, MemberID: memberID})
		if membershipErr == nil {
			return nil
		}
		if !errors.Is(membershipErr, pgx.ErrNoRows) {
			return membershipErr
		}

		before, err := s.grantAuthoritySnapshotAtPositionTx(ctx, q, member.ID, spaceID, member.Type, delta.Node{Kind: delta.Space, ID: spaceID})
		if err != nil {
			return err
		}
		if err := q.AddGroupMember(ctx, db.AddGroupMemberParams{GroupID: groupID, MemberID: memberID, SpaceID: spaceID, Source: "manual"}); err != nil {
			return normalizeDBError(err)
		}
		after, err := s.grantAuthoritySnapshotAtPositionTx(ctx, q, member.ID, spaceID, member.Type, delta.Node{Kind: delta.Space, ID: spaceID})
		if err != nil {
			return err
		}
		change, err := delta.Evaluate(before, after, delta.Graph{})
		if err != nil {
			return err
		}
		if len(change.Permissions) != 0 || len(change.Rights) != 0 {
			if err := s.authorizeGroupTx(ctx, q, actorMemberID, "auth.grants:assign", spaceID, groupID); err != nil {
				return err
			}
			if err := s.coverPositiveGrantDeltaTx(ctx, q, change, actorMemberID, member.ID, member.Type, spaceID); err != nil {
				return err
			}
		}
		return auditGroupMembership(ctx, q, actorMemberID, memberID, groupID)
	})
}

func (s *Service) authorizeGroupTx(ctx context.Context, q *db.Queries, actorMemberID, permission, spaceID, groupID string) error {
	decision, err := s.CheckTx(ctx, q, CheckRequest{
		MemberID: actorMemberID, Permission: permission, ResourceSpace: spaceID, ResourceGroup: groupID,
	})
	if err != nil {
		return err
	}
	if decision.Effect == engine.Allow {
		return nil
	}
	return &apierr.Error{Code: decision.Code, Message: "The authorization engine denied this operation.", Details: map[string]string{"permission": permission, "group_id": groupID}}
}

func auditGroupMembership(ctx context.Context, q *db.Queries, actorMemberID, memberID, groupID string) error {
	return audit.Write(ctx, q, "member", actorMemberID, "group.member.add", memberID+"/"+groupID, "success")
}
