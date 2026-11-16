package authorization

import (
	"context"
	"slices"
)

type tokenScopeKey struct{}

type tokenScope struct {
	memberID string
	keys     []string
}

// WithTokenScopes binds a verified credential restriction to its acting member.
// It follows the business transaction, but never restricts other members whose
// persisted authority is read for owner envelopes or authority-delta snapshots.
// A nil list is unrestricted; an explicit empty list excludes every permission.
func WithTokenScopes(ctx context.Context, memberID string, scopes []string) context.Context {
	if scopes == nil {
		return ctx
	}
	keys := tokenScopesFor(ctx, memberID, scopes)
	return context.WithValue(ctx, tokenScopeKey{}, tokenScope{memberID: memberID, keys: uniqueSorted(keys)})
}

func tokenScopesFor(ctx context.Context, memberID string, explicit []string) []string {
	bound, ok := ctx.Value(tokenScopeKey{}).(tokenScope)
	if !ok || bound.memberID != memberID {
		return explicit
	}
	if explicit == nil {
		return bound.keys
	}
	intersection := make([]string, 0)
	for _, key := range explicit {
		if slices.Contains(bound.keys, key) {
			intersection = append(intersection, key)
		}
	}
	return intersection
}
