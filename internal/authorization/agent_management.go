package authorization

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"
	"github.com/plystra/auth/internal/apierr"
	"github.com/plystra/auth/internal/authz/engine"
	"github.com/plystra/auth/internal/db"
)

// AuthorizeAgentMutationTx resolves the current target after the lifecycle
// service has locked the actor, target, and their owner chains. It uses the
// same current facts as Check; an HTTP preflight is never an authorization.
func (s *Service) AuthorizeAgentMutationTx(ctx context.Context, q *db.Queries, actorID, targetID, permission string) error {
	if s == nil {
		return apierr.New("UNAVAILABLE", "Agent management authorization is unavailable")
	}
	return s.authorizeMemberMutationTx(ctx, q, actorID, targetID, permission)
}

func (s *Service) authorizeMemberMutationTx(ctx context.Context, q *db.Queries, actorID, targetID, permission string) error {
	if err := lockAuthorizationMembersTx(ctx, q, actorID, targetID); err != nil {
		return err
	}
	if err := validateAgentGrantUserTx(ctx, q, actorID); err != nil {
		return err
	}
	target, err := q.GetMemberForAuthorization(ctx, db.GetMemberForAuthorizationParams{ID: targetID})
	if errors.Is(err, pgx.ErrNoRows) {
		return apierr.New("NOT_FOUND", "management target was not found")
	}
	if err != nil {
		return err
	}
	if err := lockAuthorizationNodesTx(ctx, q, target.SpaceID, ""); err != nil {
		return err
	}
	groupID, err := resourceGroupForMemberTx(ctx, q, target.ID, target.SpaceID)
	if err != nil {
		return err
	}
	if err := lockAuthorizationNodesTx(ctx, q, target.SpaceID, groupID); err != nil {
		return err
	}
	decision, err := s.CheckTx(ctx, q, CheckRequest{
		MemberID: actorID, Permission: permission, ResourceSpace: target.SpaceID, ResourceGroup: groupID, ResourceOwner: target.ID,
	})
	if err != nil {
		return err
	}
	if decision.Effect != engine.Allow {
		return &apierr.Error{Code: decision.Code, Message: "The authorization engine denied this member operation.", Details: map[string]string{"permission": permission}}
	}
	return nil
}
