package authorization

import (
	"context"
	"encoding/json"
	"slices"
	"sort"
	"strings"

	"github.com/plystra/auth/internal/apierr"
	"github.com/plystra/auth/internal/authz/delta"
	"github.com/plystra/auth/internal/authz/engine"
	"github.com/plystra/auth/internal/db"
)

func (s *Service) bindingAuthorityDeltaTx(ctx context.Context, q *db.Queries, memberID, userID, spaceID string) (delta.Result, error) {
	assignments, _, err := s.assignmentsQueries(ctx, q, memberID)
	if err != nil {
		return delta.Result{}, err
	}
	newIdentity := userID + "\x00" + memberID
	position, err := memberPositionTx(ctx, q, memberID, spaceID)
	if err != nil {
		return delta.Result{}, err
	}
	after := permissionSnapshot(assignments, newIdentity, position, "human")
	rights, err := s.assignmentRightsSnapshotTx(ctx, q, memberID)
	if err != nil {
		return delta.Result{}, err
	}
	after.Rights = rights
	change, err := delta.Evaluate(delta.Snapshot{}, after, delta.Graph{})
	if err != nil {
		return delta.Result{}, err
	}
	return change, nil
}

func (s *Service) assignmentRightsSnapshotTx(ctx context.Context, q *db.Queries, memberID string) ([]delta.Right, error) {
	member, err := q.GetMemberForAuthorization(ctx, db.GetMemberForAuthorizationParams{ID: memberID})
	if err != nil {
		return nil, err
	}
	rows, err := q.LockActiveAssignRightsForHolder(ctx, db.LockActiveAssignRightsForHolderParams{HolderMemberID: memberID})
	if err != nil {
		return nil, err
	}
	position := delta.Node{Kind: delta.Space, ID: member.SpaceID}
	rights := make([]delta.Right, 0, len(rows))
	for _, row := range rows {
		var permissions []string
		if err := json.Unmarshal(row.PermissionKeys, &permissions); err != nil {
			return nil, err
		}
		right := delta.Right{
			Holder: memberID, Position: position, Permissions: permissions,
			Descendants: row.CoversSubtree, Delegate: row.CanRedelegate,
		}
		if row.ExpiresAt.Valid {
			right.ExpiresAt = row.ExpiresAt.Time.UTC()
		}
		if row.AnchorSpaceID.Valid {
			right.Anchor = delta.Node{Kind: delta.Space, ID: row.AnchorSpaceID.String}
		} else if row.AnchorGroupID.Valid {
			right.Anchor = delta.Node{Kind: delta.Group, ID: row.AnchorGroupID.String}
		} else {
			return nil, apierr.New("INVALID_RESOURCE", "assignment right has no anchor")
		}
		rights = append(rights, right)
	}
	return rights, nil
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

// G8 applies the same positive-delta evaluator to human and Agent grants and
// binding authority. Application-recipient coverage remains explicitly
// tracked as unfinished G8 work in auth-docs/roadmap.md.
func (s *Service) coverGrantDeltaTx(ctx context.Context, q *db.Queries, before delta.Snapshot, actorMemberID, memberID, spaceID, principalKind string) error {
	after, err := s.grantAuthoritySnapshotTx(ctx, q, memberID, spaceID, principalKind)
	if err != nil {
		return err
	}
	change, err := delta.Evaluate(before, after, delta.Graph{})
	if err != nil {
		return err
	}
	return s.coverPositiveGrantDeltaTx(ctx, q, change, actorMemberID, memberID, principalKind, spaceID)
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

func (s *Service) grantAuthoritySnapshotAtPositionTx(ctx context.Context, q *db.Queries, memberID, spaceID, principalKind string, position delta.Node) (delta.Snapshot, error) {
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
	for _, right := range change.Rights {
		uncovered = append(uncovered, delta.FormatRight(right))
	}
	sort.Strings(uncovered)
	return &apierr.Error{
		Code: "AUTHORITY_DELTA_NOT_COVERED", Message: message,
		Details: map[string]string{"uncovered": strings.Join(uncovered, ", ")},
	}
}
