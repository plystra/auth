package authorization

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/plystra/auth/internal/apierr"
	"github.com/plystra/auth/internal/audit"
	"github.com/plystra/auth/internal/db"
	"github.com/plystra/auth/internal/member"
)

// RevokeOwnBinding removes only this user's binding. Authorization uses the
// member's current position inside the same transaction as subtree suspension.
func (s *Service) RevokeOwnBinding(ctx context.Context, userID, memberID string) error {
	ctx = WithHumanActor(ctx, memberID, userID)
	return s.Store.InTx(ctx, func(q *db.Queries) error {
		// Lock the account before members, matching invitation acceptance. NO KEY
		// UPDATE permits Agent creation's foreign-key checks while it holds owners.
		user, err := q.LockUserForAuthorization(ctx, db.LockUserForAuthorizationParams{ID: userID})
		if errors.Is(err, pgx.ErrNoRows) || err == nil && user.Status != "active" {
			return apierr.New("UNAUTHENTICATED", "the acting user is not active")
		}
		if err != nil {
			return err
		}
		if err := lockAuthorizationMembersTx(ctx, q, memberID); err != nil {
			return err
		}
		binding, err := q.LockUserMemberBinding(ctx, db.LockUserMemberBindingParams{UserID: userID, MemberID: memberID})
		if errors.Is(err, pgx.ErrNoRows) || err == nil && (binding.Status != "active" || binding.RevokedAt.Valid || binding.ExpiresAt.Valid && !binding.ExpiresAt.Time.After(time.Now().UTC())) {
			return apierr.New("UNAUTHENTICATED", "the acting user is no longer bound to this member")
		}
		if err != nil {
			return err
		}
		if err := s.authorizeMemberMutationTx(ctx, q, memberID, memberID, "self:read"); err != nil {
			return err
		}
		if err := suspendBindingAgentsTx(ctx, q, memberID, userID, memberID, userID); err != nil {
			return err
		}
		if err := q.RevokeUserMember(ctx, db.RevokeUserMemberParams{UserID: userID, MemberID: memberID}); err != nil {
			return err
		}
		current, err := q.GetMemberForAuthorization(ctx, db.GetMemberForAuthorizationParams{ID: memberID})
		if err != nil {
			return err
		}
		if _, err := q.BumpPolicyVersion(ctx, db.BumpPolicyVersionParams{ID: current.SpaceID}); err != nil {
			return err
		}
		return audit.WriteSecurityEvent(ctx, q, audit.SecurityEvent{
			ActorType: "member", ActorID: memberID, Action: "member.binding.self_revoke", Outcome: "success", MemberID: memberID,
			UserID: userID, Permission: "self:read", Metadata: map[string]string{"binding_user_id": userID},
		})
	})
}

// The human member lock serializes this read with new direct Agents and with
// descendant creation, whose lock set includes every owner in the chain.
func suspendBindingAgentsTx(ctx context.Context, q *db.Queries, actorID, actorUserID, memberID, userID string) error {
	agents, err := q.ListAgentsCreatedByBinding(ctx, db.ListAgentsCreatedByBindingParams{
		UserID: pgtype.Text{String: userID, Valid: true}, MemberID: pgtype.Text{String: memberID, Valid: true},
	})
	if err != nil {
		return err
	}
	for _, id := range agents {
		if err := member.SetAgentSubtreeStatusTx(ctx, q, id, "suspended"); err != nil {
			return err
		}
		if err := audit.WriteSecurityEvent(ctx, q, audit.SecurityEvent{
			ActorType: "member", ActorID: actorID, Action: "agent.binding.suspend", Outcome: "success", MemberID: id,
			UserID: actorUserID, Metadata: map[string]string{"binding_user_id": userID, "binding_member_id": memberID},
		}); err != nil {
			return err
		}
	}
	return nil
}
