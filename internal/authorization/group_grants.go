package authorization

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"sort"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/plystra/auth/internal/apierr"
	"github.com/plystra/auth/internal/audit"
	"github.com/plystra/auth/internal/authz/delta"
	"github.com/plystra/auth/internal/db"
	"github.com/plystra/auth/internal/ids"
)

type GroupGrantInput struct {
	RoleID        string
	Permissions   []string
	Scope         string
	AnchorSpaceID string
	AnchorGroupID string
}

// CreateGroupGrant grants authority to the current group subtree. Later joins
// still pass the membership delta check; an empty group is not an authorization
// shortcut for admitting members after the assigner's rights have been revoked.
func (s *Service) CreateGroupGrant(ctx context.Context, actorMemberID, spaceID, groupID string, in GroupGrantInput) (Grant, error) {
	in.Permissions = uniqueSorted(in.Permissions)
	if actorMemberID == "" || spaceID == "" || groupID == "" || (in.RoleID == "") == (len(in.Permissions) == 0) || len(in.Permissions) > 256 {
		return Grant{}, apierr.New("VALIDATION_FAILED", "a group grant requires exactly one role or permission set")
	}
	if in.Scope == "" {
		in.Scope = "space"
	}
	switch in.Scope {
	case "self":
		if in.AnchorSpaceID != "" || in.AnchorGroupID != "" {
			return Grant{}, apierr.New("VALIDATION_FAILED", "self grants cannot have an anchor")
		}
	case "space", "space_tree":
		if in.AnchorGroupID != "" {
			return Grant{}, apierr.New("VALIDATION_FAILED", "Space grants cannot have a group anchor")
		}
		if in.AnchorSpaceID == "" {
			in.AnchorSpaceID = spaceID
		}
	case "group", "group_tree":
		if in.AnchorGroupID == "" || in.AnchorSpaceID != "" {
			return Grant{}, apierr.New("VALIDATION_FAILED", "group grants require only anchor_group_id")
		}
	default:
		return Grant{}, apierr.New("VALIDATION_FAILED", "unsupported group grant scope")
	}
	var out Grant
	err := s.Store.InTx(ctx, func(q *db.Queries) error {
		permissions := in.Permissions
		if in.RoleID != "" {
			role, err := q.LockRoleInSpace(ctx, db.LockRoleInSpaceParams{ID: in.RoleID, SpaceID: spaceID})
			if errors.Is(err, pgx.ErrNoRows) {
				return apierr.New("NOT_FOUND", "role was not found in this Space")
			}
			if err != nil {
				return err
			}
			if err := validateOrdinaryGrantRoleTx(ctx, q, role.ID); err != nil {
				return err
			}
			rows, err := q.ListRolePermissions(ctx, db.ListRolePermissionsParams{RoleID: role.ID})
			if err != nil {
				return err
			}
			permissions = make([]string, 0, len(rows))
			for _, row := range rows {
				permissions = append(permissions, row.Key)
			}
		}
		members, err := q.ListMembersInGroupSubtree(ctx, db.ListMembersInGroupSubtreeParams{GroupID: groupID, SpaceID: spaceID})
		if err != nil {
			return err
		}
		memberIDs := []string{actorMemberID}
		for _, member := range members {
			memberIDs = append(memberIDs, member.ID)
		}
		if err := lockAuthorizationMembersTx(ctx, q, memberIDs...); err != nil {
			return err
		}
		anchorSpace := in.AnchorSpaceID
		if in.AnchorGroupID != "" {
			anchorSpace, err = q.GetGroupSpaceForAuthorization(ctx, db.GetGroupSpaceForAuthorizationParams{ID: in.AnchorGroupID})
			if errors.Is(err, pgx.ErrNoRows) {
				return apierr.New("NOT_FOUND", "grant anchor group was not found")
			}
			if err != nil {
				return err
			}
		}
		if err := lockAuthorizationNodesTx(ctx, q, spaceID, "", anchorSpace); err != nil {
			return err
		}
		groupSpaces := map[string]string{groupID: spaceID}
		if in.AnchorGroupID != "" {
			groupSpaces[in.AnchorGroupID] = anchorSpace
		}
		if err := lockGroupGrantNodesTx(ctx, q, groupSpaces); err != nil {
			return err
		}
		if anchorSpace != "" {
			if err := validateMemberGrantAnchorTx(ctx, q, spaceID, "space", anchorSpace); err != nil {
				return err
			}
		}
		if err := s.authorizeGroupTx(ctx, q, actorMemberID, "auth.grants:assign", spaceID, groupID); err != nil {
			return err
		}
		// Membership writers lock the governing Space before changing the tree.
		// Re-read under that lock; abort if the set changed while acquiring the
		// member locks, rather than authorize an incomplete recipient snapshot.
		current, err := q.ListMembersInGroupSubtree(ctx, db.ListMembersInGroupSubtreeParams{GroupID: groupID, SpaceID: spaceID})
		if err != nil {
			return err
		}
		if !slices.EqualFunc(members, current, func(a, b db.ListMembersInGroupSubtreeRow) bool { return a.ID == b.ID }) {
			return apierr.New("CONFLICT", "group membership changed; retry the grant")
		}
		for _, key := range permissions {
			permission, err := q.GetPermissionByKey(ctx, db.GetPermissionByKeyParams{Key: key})
			if errors.Is(err, pgx.ErrNoRows) || err == nil && permission.Status != "active" {
				return &apierr.Error{Code: "AUTHORITY_DELTA_NOT_COVERED", Message: "The permission cannot be newly granted.", Details: map[string]string{"permission": key}}
			}
			if err != nil {
				return err
			}
		}
		position := delta.Node{Kind: delta.Group, ID: groupID}
		before := make(map[string]delta.Snapshot, len(current))
		for _, member := range current {
			snapshot, err := s.grantAuthoritySnapshotAtPositionTx(ctx, q, member.ID, spaceID, member.Type, position)
			if err != nil {
				return err
			}
			before[member.ID] = snapshot
		}
		var encoded []byte
		if in.RoleID == "" {
			encoded, err = json.Marshal(permissions)
			if err != nil {
				return err
			}
		}
		row, err := q.CreateGroupGrant(ctx, db.CreateGroupGrantParams{
			ID: string(ids.New[ids.GrantID]("grt")), SpaceID: spaceID, GrantedBy: actorMemberID,
			RoleID: pgtype.Text{String: in.RoleID, Valid: in.RoleID != ""}, PermissionKeys: encoded,
			GranteeGroupID: pgtype.Text{String: groupID, Valid: true}, Scope: in.Scope,
			AnchorSpaceID: pgtype.Text{String: in.AnchorSpaceID, Valid: in.AnchorSpaceID != ""},
			AnchorGroupID: pgtype.Text{String: in.AnchorGroupID, Valid: in.AnchorGroupID != ""},
		})
		if err != nil {
			return normalizeDBError(err)
		}
		for _, member := range current {
			after, err := s.grantAuthoritySnapshotAtPositionTx(ctx, q, member.ID, spaceID, member.Type, position)
			if err != nil {
				return err
			}
			graph, err := grantDeltaGraphTx(ctx, q, before[member.ID], after)
			if err != nil {
				return err
			}
			change, err := delta.Evaluate(before[member.ID], after, graph)
			if err != nil {
				return err
			}
			if err := s.coverPositiveGrantDeltaTx(ctx, q, change, actorMemberID, member.ID, member.Type, spaceID); err != nil {
				return err
			}
		}
		action := "grant.inline.create"
		if in.RoleID != "" {
			action = "grant.create"
		}
		if err := audit.WriteSecurityEvent(ctx, q, audit.SecurityEvent{
			ActorType: "member", ActorID: actorMemberID, MemberID: actorMemberID, Action: action, Outcome: "success",
			Resource: audit.Resource{Type: "grant", ID: row.ID, SpaceID: spaceID, GroupID: groupID}, Permission: "auth.grants:assign",
		}); err != nil {
			return err
		}
		out = Grant{ID: row.ID, SpaceID: spaceID, RoleID: in.RoleID, GranteeGroupID: groupID, Scope: in.Scope,
			AnchorSpaceID: in.AnchorSpaceID, AnchorGroupID: in.AnchorGroupID, GrantedBy: actorMemberID}
		if in.RoleID == "" {
			out.Permissions = permissions
		}
		return nil
	})
	return out, err
}

func lockGroupGrantNodesTx(ctx context.Context, q *db.Queries, groupSpaces map[string]string) error {
	nodes := map[string]string{}
	for groupID, spaceID := range groupSpaces {
		chain, err := authorizationGroupChainIDs(ctx, q, groupID, spaceID)
		if err != nil {
			return err
		}
		for _, id := range chain {
			nodes[id] = spaceID
		}
	}
	ordered := make([]string, 0, len(nodes))
	for id := range nodes {
		ordered = append(ordered, id)
	}
	sort.Strings(ordered)
	for _, id := range ordered {
		if _, err := q.LockGroupInSpaceForAuthorization(ctx, db.LockGroupInSpaceForAuthorizationParams{ID: id, SpaceID: nodes[id]}); err != nil {
			return err
		}
	}
	for groupID, spaceID := range groupSpaces {
		if _, err := q.GetGroupInSpace(ctx, db.GetGroupInSpaceParams{ID: groupID, SpaceID: spaceID}); errors.Is(err, pgx.ErrNoRows) {
			return apierr.New("NOT_FOUND", "grant group was not found")
		} else if err != nil {
			return err
		}
		if _, err := groupAncestorsQueries(ctx, q, groupID, spaceID); err != nil {
			if errors.Is(err, errGroupInactive) {
				return apierr.New("RESOURCE_GROUP_INACTIVE", "grant group is not active")
			}
			return err
		}
	}
	return nil
}

// Installation roles have an independent approval lifecycle. Reusing one in
// an ordinary grant would let later manifest approval wake unrelated subjects.
func validateOrdinaryGrantRoleTx(ctx context.Context, q *db.Queries, roleID string) error {
	installation, err := q.RoleIsApplicationInstallation(ctx, db.RoleIsApplicationInstallationParams{RoleID: roleID})
	if err != nil {
		return err
	}
	if installation {
		return apierr.New("VALIDATION_FAILED", "installation roles cannot be reused in ordinary grants")
	}
	return nil
}
