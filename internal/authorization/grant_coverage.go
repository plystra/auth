package authorization

import (
	"context"
	"encoding/json"
	"errors"
	"slices"

	"github.com/jackc/pgx/v5"
	"github.com/plystra/auth/internal/apierr"
	"github.com/plystra/auth/internal/authz/delta"
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

func (s *Service) coverPositiveGrantDeltaTx(ctx context.Context, q *db.Queries, change delta.Result, actorMemberID, principalKind, spaceID string) error {
	if len(change.Permissions) == 0 && len(change.Rights) == 0 {
		return nil
	}
	// G8 still needs owner-chain filtering for Agent recipients and Agent
	// administrators. Until then, neither path may accept a positive delta.
	actor, err := q.GetMemberForAuthorization(ctx, db.GetMemberForAuthorizationParams{ID: actorMemberID})
	if err != nil {
		return err
	}
	if actor.Type != "human" || principalKind != "human" || len(change.Rights) != 0 {
		return rejectUncoveredDelta(change, "The grant would increase authority without owner-envelope coverage.")
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
