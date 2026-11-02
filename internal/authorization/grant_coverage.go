package authorization

import (
	"context"
	"encoding/json"
	"errors"
	"slices"

	"github.com/jackc/pgx/v5"
	"github.com/plystra/auth/internal/apierr"
	"github.com/plystra/auth/internal/authz/delta"
	"github.com/plystra/auth/internal/authz/engine"
	"github.com/plystra/auth/internal/db"
)

func validateMemberGrantAnchorTx(ctx context.Context, q *db.Queries, memberSpaceID, scope, anchorSpaceID string) error {
	if scope == "self" && anchorSpaceID != memberSpaceID {
		return apierr.New("SCOPE_OUT_OF_BOUNDS", "self grants must be anchored at the member's Space")
	}
	ancestors, err := spaceAncestorsQueries(ctx, q, anchorSpaceID)
	if errors.Is(err, errSpaceInactive) {
		return apierr.New("SCOPE_OUT_OF_BOUNDS", "grant anchor is not an active Space")
	}
	if err != nil {
		return err
	}
	if anchorSpaceID != memberSpaceID && !slices.Contains(ancestors, memberSpaceID) {
		return apierr.New("SCOPE_OUT_OF_BOUNDS", "grant anchor is outside the member's Space subtree")
	}
	return nil
}

func (s *Service) coverPositiveGrantDeltaTx(ctx context.Context, q *db.Queries, change delta.Result, actorMemberID, memberID, principalKind, spaceID string) error {
	if len(change.Permissions) != 0 {
		if err := s.coverPositiveGrantDeltaForActorTx(ctx, q, delta.Result{Permissions: change.Permissions}, actorMemberID, memberID, principalKind, spaceID, false, map[string]struct{}{}); err != nil {
			return err
		}
	}
	if len(change.Rights) != 0 {
		if err := s.coverPositiveAssignmentDeltaForActorTx(ctx, q, delta.Result{Rights: change.Rights}, actorMemberID, memberID, spaceID, map[string]struct{}{}); err != nil {
			return err
		}
	}
	return nil
}

// CoverApplicationInstallationTx evaluates the complete authority gained by an
// activated installation member. Only this path may cover an application recipient;
// ordinary grants to application members remain blocked by G8.
func (s *Service) CoverApplicationInstallationTx(ctx context.Context, q *db.Queries, actorMemberID, memberID, spaceID string) error {
	after, err := s.grantAuthoritySnapshotTx(ctx, q, memberID, spaceID, "application")
	if err != nil {
		return err
	}
	change, err := delta.Evaluate(delta.Snapshot{}, after, delta.Graph{})
	if err != nil {
		return err
	}
	if len(change.Permissions) == 0 && len(change.Rights) == 0 {
		return nil
	}
	if err := s.authorizeTargetTx(ctx, q, actorMemberID, "auth.grants:assign", spaceID, memberID, spaceID); err != nil {
		return err
	}
	return s.coverPositiveGrantDeltaForActorTx(ctx, q, change, actorMemberID, memberID, "application", spaceID, true, map[string]struct{}{})
}

func (s *Service) coverPositiveGrantDeltaForActorTx(ctx context.Context, q *db.Queries, change delta.Result, actorMemberID, memberID, principalKind, spaceID string, applicationInstallation bool, seen map[string]struct{}) error {
	if len(change.Permissions) == 0 {
		return nil
	}
	actor, err := q.GetMemberForAuthorization(ctx, db.GetMemberForAuthorizationParams{ID: actorMemberID})
	if err != nil {
		return err
	}
	if _, ok := seen[actorMemberID]; ok {
		return apierr.New("OWNER_INACTIVE", "the Agent owner chain contains a cycle")
	}
	seen[actorMemberID] = struct{}{}
	defer delete(seen, actorMemberID)
	if principalKind == "agent" {
		change.Permissions, err = s.filterAgentOwnerPermissionsTx(ctx, q, change.Permissions, memberID, spaceID)
		if err != nil {
			return err
		}
	}
	if len(change.Permissions) == 0 {
		return nil
	}
	if actor.Type == "application" || (principalKind == "application" && !applicationInstallation) {
		return rejectUncoveredDelta(change, "The grant would increase authority without owner-envelope coverage.")
	}
	if actor.Type == "agent" {
		agent, ownerErr := q.GetAgentMember(ctx, db.GetAgentMemberParams{MemberID: actorMemberID})
		if ownerErr != nil {
			if errors.Is(ownerErr, pgx.ErrNoRows) {
				return apierr.New("OWNER_INACTIVE", "the Agent owner record was not found")
			}
			return ownerErr
		}
		if !agent.OwnerMemberID.Valid || agent.OwnerMemberID.String == "" {
			return apierr.New("OWNER_INACTIVE", "the Agent owner record was not found")
		}
		owner, ownerErr := q.GetMemberForAuthorization(ctx, db.GetMemberForAuthorizationParams{ID: agent.OwnerMemberID.String})
		if ownerErr != nil {
			if errors.Is(ownerErr, pgx.ErrNoRows) {
				return apierr.New("OWNER_INACTIVE", "the Agent owner member is not active")
			}
			return ownerErr
		}
		if owner.Status != "active" {
			return apierr.New("OWNER_INACTIVE", "the Agent owner member is not active")
		}
		if err := s.authorizeTargetTx(ctx, q, owner.ID, "auth.grants:assign", spaceID, memberID); err != nil {
			return err
		}
		if err := s.coverPositiveGrantDeltaForActorTx(ctx, q, change, owner.ID, memberID, principalKind, spaceID, applicationInstallation, seen); err != nil {
			return err
		}
	}
	rights, err := q.LockActiveAssignRightsForHolder(ctx, db.LockActiveAssignRightsForHolderParams{HolderMemberID: actorMemberID})
	if err != nil {
		return err
	}
	graph := delta.Graph{SpaceParent: map[string]string{}, GroupParent: map[string]string{}, GroupSpace: map[string]string{}}
	if err := addCoverageSpaceTx(ctx, q, spaceID, &graph); err != nil {
		return err
	}
	for _, permission := range change.Permissions {
		if permission.Position.Kind == delta.Group {
			if err := addCoverageGroupTx(ctx, q, permission.Position.ID, spaceID, &graph); err != nil {
				return err
			}
		}
		if permission.Scope.Kind == delta.SpaceOnly || permission.Scope.Kind == delta.SpaceTree {
			if err := addCoverageSpaceTx(ctx, q, permission.Scope.Anchor, &graph); err != nil {
				return err
			}
		}
	}
	validRights := make([]db.AssignRight, 0, len(rights))
	for _, right := range rights {
		if right.AnchorSpaceID.Valid {
			if err := addCoverageSpaceTx(ctx, q, right.AnchorSpaceID.String, &graph); err != nil {
				if errors.Is(err, errSpaceInactive) {
					continue
				}
				return err
			}
		} else if right.AnchorGroupID.Valid {
			if err := addCoverageGroupTx(ctx, q, right.AnchorGroupID.String, spaceID, &graph); err != nil {
				if errors.Is(err, errGroupInactive) {
					continue
				}
				return err
			}
		}
		validRights = append(validRights, right)
	}
	envelopes := newEnvelopeFacts(q)
	uncovered := make([]delta.Permission, 0)
	for _, permission := range change.Permissions {
		catalog, err := q.GetPermissionByKey(ctx, db.GetPermissionByKeyParams{Key: permission.Key})
		if errors.Is(err, pgx.ErrNoRows) {
			uncovered = append(uncovered, permission)
			continue
		}
		if err != nil {
			return err
		}
		if catalog.Status != "active" {
			uncovered = append(uncovered, permission)
			continue
		}
		mode, err := envelopes.grantMode(ctx, permission.Position, spaceID, permission.Key, catalog.Delegable)
		if err != nil {
			return err
		}
		if mode < 2 {
			uncovered = append(uncovered, permission)
			continue
		}
		if permission.Scope.Kind == delta.SpaceOnly || permission.Scope.Kind == delta.SpaceTree {
			mode, err = envelopes.grantMode(ctx, delta.Node{Kind: delta.Space, ID: permission.Scope.Anchor}, permission.Scope.Anchor, permission.Key, catalog.Delegable)
			if err != nil {
				return err
			}
			if mode < 2 {
				uncovered = append(uncovered, permission)
				continue
			}
		}
		covered := false
		for _, row := range validRights {
			var keys []string
			if err := json.Unmarshal(row.PermissionKeys, &keys); err != nil {
				return err
			}
			right := delta.Right{Holder: actorMemberID, Position: delta.Node{Kind: delta.Space, ID: actor.SpaceID}, Permissions: keys, Descendants: row.CoversSubtree, Delegate: row.CanRedelegate}
			if row.AnchorSpaceID.Valid {
				right.Anchor = delta.Node{Kind: delta.Space, ID: row.AnchorSpaceID.String}
			} else if row.AnchorGroupID.Valid {
				right.Anchor = delta.Node{Kind: delta.Group, ID: row.AnchorGroupID.String}
			}
			allows, err := delta.CoversGrant(right, permission, graph)
			if err != nil {
				return err
			}
			if allows {
				covered = true
				break
			}
		}
		if !covered {
			uncovered = append(uncovered, permission)
		}
	}
	return rejectUncoveredDelta(delta.Result{Permissions: uncovered}, "The grant exceeds the administrator's assignment rights.")
}

func (s *Service) coverPositiveAssignmentDeltaForActorTx(ctx context.Context, q *db.Queries, change delta.Result, actorMemberID, targetMemberID, spaceID string, seen map[string]struct{}) error {
	if len(change.Rights) == 0 {
		return nil
	}
	actor, err := q.GetMemberForAuthorization(ctx, db.GetMemberForAuthorizationParams{ID: actorMemberID})
	if err != nil {
		return err
	}
	if _, ok := seen[actorMemberID]; ok {
		return apierr.New("OWNER_INACTIVE", "the Agent owner chain contains a cycle")
	}
	seen[actorMemberID] = struct{}{}
	defer delete(seen, actorMemberID)
	if actor.Type == "application" {
		return rejectUncoveredDelta(change, "The assignment-right delta requires human or Agent delegation coverage.")
	}
	target, err := q.GetMemberForAuthorization(ctx, db.GetMemberForAuthorizationParams{ID: targetMemberID})
	if err != nil {
		return err
	}
	if target.Type == "application" {
		return rejectUncoveredDelta(change, "Application assignment-right deltas are not yet supported.")
	}
	if actor.Type == "agent" {
		agent, ownerErr := q.GetAgentMember(ctx, db.GetAgentMemberParams{MemberID: actorMemberID})
		if ownerErr != nil {
			if errors.Is(ownerErr, pgx.ErrNoRows) {
				return apierr.New("OWNER_INACTIVE", "the Agent owner record was not found")
			}
			return ownerErr
		}
		if !agent.OwnerMemberID.Valid || agent.OwnerMemberID.String == "" {
			return apierr.New("OWNER_INACTIVE", "the Agent owner record was not found")
		}
		owner, ownerErr := q.GetMemberForAuthorization(ctx, db.GetMemberForAuthorizationParams{ID: agent.OwnerMemberID.String})
		if ownerErr != nil {
			if errors.Is(ownerErr, pgx.ErrNoRows) {
				return apierr.New("OWNER_INACTIVE", "the Agent owner member is not active")
			}
			return ownerErr
		}
		if owner.Status != "active" {
			return apierr.New("OWNER_INACTIVE", "the Agent owner member is not active")
		}
		if err := s.authorizeTargetTx(ctx, q, owner.ID, "auth.assign_rights:manage", spaceID, targetMemberID); err != nil {
			return err
		}
		if err := s.coverPositiveAssignmentDeltaForActorTx(ctx, q, change, owner.ID, targetMemberID, spaceID, seen); err != nil {
			return err
		}
	}
	rows, err := q.LockActiveAssignRightsForHolder(ctx, db.LockActiveAssignRightsForHolderParams{HolderMemberID: actorMemberID})
	if err != nil {
		return err
	}
	graph := delta.Graph{SpaceParent: map[string]string{}, GroupParent: map[string]string{}, GroupSpace: map[string]string{}}
	if err := addCoverageSpaceTx(ctx, q, actor.SpaceID, &graph); err != nil {
		return err
	}
	for _, candidate := range change.Rights {
		if candidate.Position.Kind == delta.Space {
			if err := addCoverageSpaceTx(ctx, q, candidate.Position.ID, &graph); err != nil {
				return err
			}
		} else if err := addCoverageGroupTx(ctx, q, candidate.Position.ID, spaceID, &graph); err != nil {
			return err
		}
		if candidate.Anchor.Kind == delta.Space {
			if err := addCoverageSpaceTx(ctx, q, candidate.Anchor.ID, &graph); err != nil {
				return err
			}
		} else if err := addCoverageGroupTx(ctx, q, candidate.Anchor.ID, spaceID, &graph); err != nil {
			return err
		}
	}
	for _, row := range rows {
		if row.AnchorSpaceID.Valid {
			if err := addCoverageSpaceTx(ctx, q, row.AnchorSpaceID.String, &graph); err != nil {
				if errors.Is(err, errSpaceInactive) {
					continue
				}
				return err
			}
		} else if row.AnchorGroupID.Valid {
			if err := addCoverageGroupTx(ctx, q, row.AnchorGroupID.String, spaceID, &graph); err != nil {
				if errors.Is(err, errGroupInactive) {
					continue
				}
				return err
			}
		}
	}
	uncovered := make([]delta.Right, 0, len(change.Rights))
	for _, candidate := range change.Rights {
		_, _, covered, err := coveringAssignmentRight(rows, actorMemberID, actor.SpaceID, candidate, graph)
		if err != nil {
			return err
		}
		if !covered {
			uncovered = append(uncovered, candidate)
		}
	}
	return rejectUncoveredDelta(delta.Result{Rights: uncovered}, "The assignment-right delta exceeds the administrator's delegation authority.")
}

func (s *Service) filterAgentOwnerPermissionsTx(ctx context.Context, q *db.Queries, permissions []delta.Permission, agentMemberID, spaceID string) ([]delta.Permission, error) {
	agent, err := q.GetAgentMember(ctx, db.GetAgentMemberParams{MemberID: agentMemberID})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, apierr.New("OWNER_INACTIVE", "the Agent owner record was not found")
		}
		return nil, err
	}
	if !agent.OwnerMemberID.Valid || agent.OwnerMemberID.String == "" {
		return nil, apierr.New("OWNER_INACTIVE", "the Agent owner record was not found")
	}
	owner, err := q.GetMemberForAuthorization(ctx, db.GetMemberForAuthorizationParams{ID: agent.OwnerMemberID.String})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, apierr.New("OWNER_INACTIVE", "the Agent owner member is not active")
		}
		return nil, err
	}
	if owner.Status != "active" {
		return nil, apierr.New("OWNER_INACTIVE", "the Agent owner member is not active")
	}
	out := make([]delta.Permission, 0, len(permissions))
	for _, permission := range permissions {
		request := CheckRequest{MemberID: owner.ID, Permission: permission.Key, ResourceSpace: spaceID}
		switch permission.Position.Kind {
		case delta.Group:
			request.ResourceGroup = permission.Position.ID
		case delta.Space:
			request.ResourceSpace = permission.Position.ID
		}
		switch permission.Scope.Kind {
		case delta.Self:
			request.ResourceOwner = agentMemberID
		case delta.SpaceOnly, delta.SpaceTree:
			if permission.Scope.Anchor != "" {
				request.ResourceSpace = permission.Scope.Anchor
			}
		case delta.GroupOnly, delta.GroupTree:
			request.ResourceGroup = permission.Scope.Anchor
		}
		decision, err := s.CheckTx(ctx, q, request)
		if err != nil {
			return nil, err
		}
		if decision.Code == "OWNER_INACTIVE" {
			return nil, apierr.New("OWNER_INACTIVE", "the Agent owner chain is not active")
		}
		if decision.Effect == engine.Allow {
			out = append(out, permission)
		}
	}
	return out, nil
}

func addCoverageSpaceTx(ctx context.Context, q *db.Queries, spaceID string, graph *delta.Graph) error {
	current := spaceID
	seen := map[string]struct{}{}
	for range 64 {
		if _, ok := seen[current]; ok {
			return apierr.New("INVALID_RESOURCE", "Space hierarchy contains a cycle")
		}
		seen[current] = struct{}{}
		if _, ok := graph.SpaceParent[current]; ok {
			return nil
		}
		space, err := q.GetSpace(ctx, db.GetSpaceParams{ID: current})
		if errors.Is(err, pgx.ErrNoRows) {
			return errSpaceInactive
		}
		if err != nil {
			return err
		}
		if space.Status != "active" {
			return errSpaceInactive
		}
		parent := ""
		if space.ParentID.Valid {
			parent = space.ParentID.String
		}
		graph.SpaceParent[current] = parent
		if parent == "" {
			return nil
		}
		current = parent
	}
	return apierr.New("INVALID_RESOURCE", "Space hierarchy is too deep")
}

func addCoverageGroupTx(ctx context.Context, q *db.Queries, groupID, spaceID string, graph *delta.Graph) error {
	if err := addCoverageSpaceTx(ctx, q, spaceID, graph); err != nil {
		return err
	}
	current := groupID
	seen := map[string]struct{}{}
	for range 64 {
		if _, ok := seen[current]; ok {
			return apierr.New("INVALID_RESOURCE", "group hierarchy contains a cycle")
		}
		seen[current] = struct{}{}
		if _, ok := graph.GroupSpace[current]; ok {
			return nil
		}
		group, err := q.GetGroupInSpace(ctx, db.GetGroupInSpaceParams{ID: current, SpaceID: spaceID})
		if errors.Is(err, pgx.ErrNoRows) {
			return errGroupInactive
		}
		if err != nil {
			return err
		}
		if group.Status != "active" {
			return errGroupInactive
		}
		parent := ""
		if group.ParentID.Valid {
			parent = group.ParentID.String
		}
		graph.GroupSpace[current] = spaceID
		graph.GroupParent[current] = parent
		if parent == "" {
			return nil
		}
		current = parent
	}
	return apierr.New("INVALID_RESOURCE", "group hierarchy is too deep")
}
