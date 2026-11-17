package agent

import (
	"context"

	"github.com/plystra/auth/internal/apierr"
	"github.com/plystra/auth/internal/db"
)

// MutationAuthorizer evaluates current authority in the lifecycle transaction.
// Provisioning and OAuth consent have separate callers and authorization rules;
// principal management must provide this dependency rather than a prior allow.
type MutationAuthorizer interface {
	AuthorizeAgentMutationTx(ctx context.Context, q *db.Queries, actorID, targetID, permission string) error
}

func (s *Service) CreateManaged(ctx context.Context, in CreateInput, authority MutationAuthorizer) (Agent, string, error) {
	if authority == nil {
		return Agent{}, "", apierr.New("UNAVAILABLE", "Agent management authorization is unavailable")
	}
	return s.create(ctx, in, true, authority)
}

func (s *Service) RotateManaged(ctx context.Context, actorID, userID, targetID string, authority MutationAuthorizer) (string, error) {
	if authority == nil {
		return "", apierr.New("UNAVAILABLE", "Agent management authorization is unavailable")
	}
	return s.rotate(ctx, actorID, userID, targetID, authority)
}

func (s *Service) StopManaged(ctx context.Context, actorID, targetID string, authority MutationAuthorizer) error {
	if authority == nil {
		return apierr.New("UNAVAILABLE", "Agent management authorization is unavailable")
	}
	return s.mutate(ctx, actorID, targetID, "stop", "suspended", authority, "auth.agents:create")
}

func (s *Service) DeleteManaged(ctx context.Context, actorID, targetID string, authority MutationAuthorizer) error {
	if authority == nil {
		return apierr.New("UNAVAILABLE", "Agent management authorization is unavailable")
	}
	return s.mutate(ctx, actorID, targetID, "delete", "removed", authority, "auth.agents:create")
}

func (s *Service) RemoveSelf(ctx context.Context, actorID string, authority MutationAuthorizer) error {
	if authority == nil {
		return apierr.New("UNAVAILABLE", "Agent management authorization is unavailable")
	}
	return s.mutate(ctx, actorID, actorID, "delete", "removed", authority, "self:read")
}
