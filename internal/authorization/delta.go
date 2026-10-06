package authorization

import (
	"context"
	"slices"
	"sort"
	"strings"

	"github.com/plystra/auth/internal/apierr"
	"github.com/plystra/auth/internal/authz/delta"
	"github.com/plystra/auth/internal/authz/engine"
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
	position, err := memberPositionTx(ctx, q, memberID, spaceID)
	if err != nil {
		return err
	}
	after := permissionSnapshot(assignments, newIdentity, position, "human")
	change, err := delta.Evaluate(delta.Snapshot{}, after, delta.Graph{})
	if err != nil {
		return err
	}
	return rejectUncoveredDelta(change, "The binding would transfer authority without assignment-right coverage.")
}

func permissionSnapshot(assignments []engine.Assignment, subject string, position delta.Node, principalKind string) delta.Snapshot {
	snapshot := delta.Snapshot{Permissions: make([]delta.Permission, 0, len(assignments))}
	for _, assignment := range assignments {
		if len(assignment.PrincipalKinds) > 0 && !slices.Contains(assignment.PrincipalKinds, principalKind) {
			continue
		}
		scope := delta.Scope{Kind: delta.ScopeKind(assignment.Scope.Kind), Anchor: assignment.Scope.Anchor}
		if scope.Kind == delta.Self || scope.Kind == delta.Global {
			scope.Anchor = ""
		}
		for _, permission := range assignment.Envelope {
			snapshot.Permissions = append(snapshot.Permissions, delta.Permission{
				Subject: subject, Position: position,
				Key: permission, Scope: scope,
			})
		}
	}
	return snapshot
}

// G8's complete assignment-right and Agent owner-envelope coverage remains
// pending (auth-docs/roadmap.md, G8). Human member grants check the available
// positive permission delta against the actor's effective assignment rights.
func (s *Service) coverGrantDeltaTx(ctx context.Context, q *db.Queries, before delta.Snapshot, actorMemberID, memberID, spaceID, principalKind string) error {
	after, err := s.grantAuthoritySnapshotTx(ctx, q, memberID, spaceID, principalKind)
	if err != nil {
		return err
	}
	change, err := delta.Evaluate(before, after, delta.Graph{})
	if err != nil {
		return err
	}
	return s.coverPositiveGrantDeltaTx(ctx, q, change, actorMemberID, principalKind, spaceID)
}

func (s *Service) grantAuthoritySnapshotTx(ctx context.Context, q *db.Queries, memberID, spaceID, principalKind string) (delta.Snapshot, error) {
	if principalKind == "human" {
		bindings, err := q.CountActiveMemberBindings(ctx, db.CountActiveMemberBindingsParams{MemberID: memberID})
		if err != nil {
			return delta.Snapshot{}, err
		}
		if bindings == 0 {
			return delta.Snapshot{}, nil
		}
	}
	assignments, _, err := s.assignmentsQueries(ctx, q, memberID)
	if err != nil {
		return delta.Snapshot{}, err
	}
	position, err := memberPositionTx(ctx, q, memberID, spaceID)
	if err != nil {
		return delta.Snapshot{}, err
	}
	return permissionSnapshot(assignments, memberID, position, principalKind), nil
}

func memberPositionTx(ctx context.Context, q *db.Queries, memberID, spaceID string) (delta.Node, error) {
	groupID, err := resourceGroupForMemberTx(ctx, q, memberID, spaceID)
	if err != nil {
		return delta.Node{}, err
	}
	if groupID != "" {
		return delta.Node{Kind: delta.Group, ID: groupID}, nil
	}
	return delta.Node{Kind: delta.Space, ID: spaceID}, nil
}

func rejectUncoveredDelta(change delta.Result, message string) error {
	if len(change.Permissions) == 0 && len(change.Rights) == 0 {
		return nil
	}
	uncovered := make([]string, 0, len(change.Permissions))
	for _, permission := range change.Permissions {
		uncovered = append(uncovered, permission.Key+"@"+string(permission.Scope.Kind)+":"+permission.Scope.Anchor)
	}
	sort.Strings(uncovered)
	return &apierr.Error{
		Code: "AUTHORITY_DELTA_NOT_COVERED", Message: message,
		Details: map[string]string{"uncovered": strings.Join(uncovered, ", ")},
	}
}
