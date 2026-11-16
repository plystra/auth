package authorization

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/plystra/auth/internal/apierr"
	"github.com/plystra/auth/internal/db"
)

type agentGrantUserKey struct{}

type agentGrantUser struct {
	memberID string
	userID   string
}

// WithAgentGrantUser carries the verified account behind an acting human
// member. Shared ownership alone does not grant the Agent creator's rights.
func WithAgentGrantUser(ctx context.Context, memberID, userID string) context.Context {
	return context.WithValue(ctx, agentGrantUserKey{}, agentGrantUser{memberID: memberID, userID: userID})
}

func ownerGrantSystemRightTx(ctx context.Context, q *db.Queries, ownerID, creatorUserID string) (bool, error) {
	owner, err := q.GetMemberForAuthorization(ctx, db.GetMemberForAuthorizationParams{ID: ownerID})
	if err != nil {
		return false, err
	}
	if owner.Type != "human" || owner.BindingPolicy != "shared" {
		return true, nil
	}
	actor, ok := ctx.Value(agentGrantUserKey{}).(agentGrantUser)
	if !ok || actor.memberID != ownerID || actor.userID == "" {
		return false, nil
	}
	return actor.userID == creatorUserID, nil
}

// The member lock is held by the caller, so a binding revoked after HTTP
// authentication cannot retain grant-management rights inside this write.
func validateAgentGrantUserTx(ctx context.Context, q *db.Queries, actorMemberID string) error {
	actor, ok := ctx.Value(agentGrantUserKey{}).(agentGrantUser)
	if !ok || actor.userID == "" {
		return nil
	}
	if actor.memberID != actorMemberID {
		return apierr.New("UNAUTHENTICATED", "the acting user does not match this member")
	}
	binding, err := q.GetUserMemberBinding(ctx, db.GetUserMemberBindingParams{UserID: actor.userID, MemberID: actorMemberID})
	if errors.Is(err, pgx.ErrNoRows) || err == nil && (binding.Status != "active" || binding.RevokedAt.Valid || binding.ExpiresAt.Valid && !binding.ExpiresAt.Time.After(time.Now().UTC())) {
		return apierr.New("UNAUTHENTICATED", "the acting user is no longer bound to this member")
	}
	if err != nil {
		return err
	}
	user, err := q.GetUserByID(ctx, db.GetUserByIDParams{ID: actor.userID})
	if errors.Is(err, pgx.ErrNoRows) || err == nil && user.Status != "active" {
		return apierr.New("UNAUTHENTICATED", "the acting user is not active")
	}
	if err != nil {
		return err
	}
	return nil
}
