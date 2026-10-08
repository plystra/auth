package stepup

import (
	"context"

	"github.com/plystra/auth/internal/db"
)

type Requirement struct {
	SessionID string
	Operation string
	Digest    []byte
}

type requirementKey struct{}

func WithRequirement(ctx context.Context, requirement Requirement) context.Context {
	return context.WithValue(ctx, requirementKey{}, Requirement{
		SessionID: requirement.SessionID,
		Operation: requirement.Operation,
		Digest:    append([]byte(nil), requirement.Digest...),
	})
}

func RequirementFromContext(ctx context.Context) (Requirement, bool) {
	requirement, ok := ctx.Value(requirementKey{}).(Requirement)
	if !ok {
		return Requirement{}, false
	}
	return requirement, true
}

type Consumer interface {
	ConsumeStepUpTx(context.Context, *db.Queries) error
}
