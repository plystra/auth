package authorization

import (
	"context"
	"slices"
	"sort"
	"strings"

	"github.com/plystra/auth/internal/apierr"
	"github.com/plystra/auth/internal/authz/delta"
	"github.com/plystra/auth/internal/db"
)

// G8's assignment-right coverage is not available yet. Until it is, G6
// binding writes may commit only when the new user/member identity has no
// positive authority delta (auth-docs/roadmap.md, G6 and G8).
func (s *Service) requireEmptyBindingDeltaTx(ctx context.Context, q *db.Queries, memberID, userID, spaceID string) error {
	assignments, _, err := s.assignmentsQueries(ctx, q, memberID)
	if err != nil {
		return err
	}
	newIdentity := userID + "\x00" + memberID
	after := delta.Snapshot{Permissions: make([]delta.Permission, 0, len(assignments))}
	for _, assignment := range assignments {
		if len(assignment.PrincipalKinds) > 0 && !slices.Contains(assignment.PrincipalKinds, "human") {
			continue
		}
		scope := delta.Scope{Kind: delta.ScopeKind(assignment.Scope.Kind), Anchor: assignment.Scope.Anchor}
		if scope.Kind == delta.Self || scope.Kind == delta.Global {
			scope.Anchor = ""
		}
		for _, permission := range assignment.Envelope {
			after.Permissions = append(after.Permissions, delta.Permission{
				Subject: newIdentity, Position: delta.Node{Kind: delta.Space, ID: spaceID},
				Key: permission, Scope: scope,
			})
		}
	}
	change, err := delta.Evaluate(delta.Snapshot{}, after, delta.Graph{})
	if err != nil {
		return err
	}
	if len(change.Permissions) == 0 && len(change.Rights) == 0 {
		return nil
	}
	uncovered := make([]string, 0, len(change.Permissions))
	for _, permission := range change.Permissions {
		uncovered = append(uncovered, permission.Key+"@"+string(permission.Scope.Kind)+":"+permission.Scope.Anchor)
	}
	sort.Strings(uncovered)
	return &apierr.Error{
		Code: "AUTHORITY_DELTA_NOT_COVERED", Message: "The binding would transfer authority without assignment-right coverage.",
		Details: map[string]string{"uncovered": strings.Join(uncovered, ", ")},
	}
}
