package authorization

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/plystra/auth/internal/apierr"
	"github.com/plystra/auth/internal/db"
)

type humanActorKey struct{}

type humanActor struct {
	memberID string
	userID   string
}

// WithHumanActor carries the verified account behind an acting human member.
// Shared ownership alone does not grant the Agent creator's rights.
func WithHumanActor(ctx context.Context, memberID, userID string) context.Context {
	return context.WithValue(ctx, humanActorKey{}, humanActor{memberID: memberID, userID: userID})
}

func ownerGrantSystemRightTx(ctx context.Context, q *db.Queries, ownerID, creatorUserID string) (bool, error) {
	owner, err := q.GetMemberForAuthorization(ctx, db.GetMemberForAuthorizationParams{ID: ownerID})
	if err != nil {
		return false, err
	}
	if owner.Type != "human" || owner.BindingPolicy != "shared" {
		return true, nil
	}
	actor, ok := ctx.Value(humanActorKey{}).(humanActor)
	if !ok || actor.memberID != ownerID || actor.userID == "" {
		return false, nil
	}
	return actor.userID == creatorUserID, nil
}

// Lock accounts before members, matching binding revocation and invitation
// acceptance. NO KEY UPDATE permits foreign-key checks in Agent creation.
func lockHumanActorAccountTx(ctx context.Context, q *db.Queries, actorMemberID string) error {
	actor, ok := ctx.Value(humanActorKey{}).(humanActor)
	if !ok || actor.userID == "" {
		return nil
	}
	if actor.memberID != actorMemberID {
		return apierr.New("UNAUTHENTICATED", "the acting user does not match this member")
	}
	user, err := q.LockUserForAuthorization(ctx, db.LockUserForAuthorizationParams{ID: actor.userID})
	if errors.Is(err, pgx.ErrNoRows) || err == nil && user.Status != "active" {
		return apierr.New("UNAUTHENTICATED", "the acting user is not active")
	}
	return err
}

// Governance writes acquire the caller's account before any member or target
// locks, and retain both identity locks until the mutation commits.
func lockAuthorizationActorTx(ctx context.Context, q *db.Queries, actorMemberID string, targetMemberIDs ...string) error {
	if err := lockHumanActorAccountTx(ctx, q, actorMemberID); err != nil {
		return err
	}
	if err := lockAuthorizationMembersTx(ctx, q, append([]string{actorMemberID}, targetMemberIDs...)...); err != nil {
		return err
	}
	return validateHumanActorTx(ctx, q, actorMemberID)
}

// The member lock is held by the caller, so a binding revoked after HTTP
// authentication cannot retain management rights inside this write.
func validateHumanActorTx(ctx context.Context, q *db.Queries, actorMemberID string) error {
	actor, ok := ctx.Value(humanActorKey{}).(humanActor)
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
