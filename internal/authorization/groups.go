package authorization

import (
	"context"
	"errors"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/plystra/auth/internal/apierr"
	"github.com/plystra/auth/internal/audit"
	"github.com/plystra/auth/internal/authz/delta"
	"github.com/plystra/auth/internal/authz/engine"
	"github.com/plystra/auth/internal/db"
	"github.com/plystra/auth/internal/ids"
)

const maxGroupDepth = 16

// CreateGroup creates a standard group in a Space. The Space or requested
// parent is resolved and locked before the authorization decision, so a
// caller cannot authorize one node and write another. Root creation is
// serialized by the Space row lock and backed by a partial unique index.
func (s *Service) CreateGroup(ctx context.Context, actorMemberID, spaceID, name, parentGroupID string) (Group, error) {
	actorMemberID = strings.TrimSpace(actorMemberID)
	spaceID = strings.TrimSpace(spaceID)
	name = strings.TrimSpace(name)
	parentGroupID = strings.TrimSpace(parentGroupID)
	if actorMemberID == "" || spaceID == "" || name == "" || len(name) > 128 {
		return Group{}, apierr.New("VALIDATION_FAILED", "group fields are invalid")
	}

	var out Group
	err := s.Store.InTx(ctx, func(q *db.Queries) error {
		if err := lockAuthorizationActorTx(ctx, q, actorMemberID); err != nil {
			return err
		}
		// Lock the governing Space and, when present, the complete parent chain
		// in the same stable order used by all authorization-backed mutations.
		if err := lockAuthorizationNodesTx(ctx, q, spaceID, parentGroupID); err != nil {
			return err
		}
		space, err := q.LockSpaceForAuthorization(ctx, db.LockSpaceForAuthorizationParams{ID: spaceID})
		if errors.Is(err, pgx.ErrNoRows) {
			return apierr.New("NOT_FOUND", "Space was not found")
		}
		if err != nil {
			return err
		}

		if parentGroupID != "" {
			parent, parentErr := q.LockGroupInSpaceForAuthorization(ctx, db.LockGroupInSpaceForAuthorizationParams{ID: parentGroupID, SpaceID: spaceID})
			if errors.Is(parentErr, pgx.ErrNoRows) {
				return apierr.New("NOT_FOUND", "parent group was not found in this Space")
			}
			if parentErr != nil {
				return parentErr
			}
			if parent.Kind != "standard" {
				return apierr.New("PERMISSION_DENIED", "Agent-owned groups cannot have manual child groups")
			}
			if parent.Status != "active" {
				return apierr.New("GROUP_INACTIVE", "parent group is not active")
			}
			depth, depthErr := groupDepthTx(ctx, q, parentGroupID, spaceID)
			if depthErr != nil {
				return depthErr
			}
			if depth >= maxGroupDepth {
				return apierr.New("VALIDATION_FAILED", "group tree exceeds the maximum depth")
			}
		} else {
			count, countErr := q.CountStandardRootGroups(ctx, db.CountStandardRootGroupsParams{SpaceID: spaceID})
			if countErr != nil {
				return countErr
			}
			if count != 0 {
				return apierr.New("CONFLICT", "the Space already has a standard root group")
			}
		}

		if err := s.authorizeGroupTx(ctx, q, actorMemberID, "auth.groups:manage", spaceID, parentGroupID); err != nil {
			return err
		}

		row, createErr := q.CreateStandardGroup(ctx, db.CreateStandardGroupParams{
			ID: string(ids.New[ids.GroupID]("grp")), SpaceID: space.ID, Name: name,
			ParentID: pgtype.Text{String: parentGroupID, Valid: parentGroupID != ""},
		})
		if createErr != nil {
			return normalizeDBError(createErr)
		}
		version, err := q.BumpPolicyVersion(ctx, db.BumpPolicyVersionParams{ID: space.ID})
		if err != nil {
			return err
		}
		if err := audit.WriteSecurityEvent(ctx, q, audit.SecurityEvent{
			ActorType: "member", ActorID: actorMemberID, MemberID: actorMemberID,
			Action: "group.create", Outcome: "success", Permission: "auth.groups:manage", PolicyVersion: version,
			Resource: audit.Resource{Type: "group", ID: row.ID, SpaceID: row.SpaceID, GroupID: row.ID},
			Metadata: map[string]string{"parent_group_id": parentGroupID},
		}); err != nil {
			return err
		}
		out = Group{ID: row.ID, SpaceID: row.SpaceID, Name: row.Name, Kind: row.Kind, Status: row.Status}
		if row.ParentID.Valid {
			out.ParentID = row.ParentID.String
		}
		return nil
	})
	return out, err
}

// AddMemberToGroup applies the group-membership change and its authority
// delta in one transaction. The target group is a resource fact for both
// management checks, so a group-scoped manager cannot widen its authority by
// choosing a different member target.
func (s *Service) AddMemberToGroup(ctx context.Context, actorMemberID, spaceID, groupID, memberID string) error {
	return s.changeGroupMembership(ctx, actorMemberID, spaceID, groupID, memberID, true)
}

// RemoveMemberFromGroup revokes inherited authority without changing the member
// identity or its other memberships. Both directions use the same before/after
// evaluator so removing a restrictive membership cannot bypass delta coverage.
func (s *Service) RemoveMemberFromGroup(ctx context.Context, actorMemberID, spaceID, groupID, memberID string) error {
	return s.changeGroupMembership(ctx, actorMemberID, spaceID, groupID, memberID, false)
}

func (s *Service) changeGroupMembership(ctx context.Context, actorMemberID, spaceID, groupID, memberID string, add bool) error {
	if actorMemberID == "" || spaceID == "" || groupID == "" || memberID == "" {
		return apierr.New("VALIDATION_FAILED", "group membership fields are required")
	}
	return s.Store.InTx(ctx, func(q *db.Queries) error {
		if err := lockAuthorizationActorTx(ctx, q, actorMemberID, memberID); err != nil {
			return err
		}
		group, err := q.LockGroupInSpaceForAuthorization(ctx, db.LockGroupInSpaceForAuthorizationParams{ID: groupID, SpaceID: spaceID})
		if errors.Is(err, pgx.ErrNoRows) {
			return apierr.New("NOT_FOUND", "group was not found in this Space")
		}
		if err != nil {
			return err
		}
		member, err := q.LockMemberInSpace(ctx, db.LockMemberInSpaceParams{ID: memberID, SpaceID: spaceID})
		if errors.Is(err, pgx.ErrNoRows) {
			return apierr.New("NOT_FOUND", "member was not found in this Space")
		}
		if err != nil {
			return err
		}
		if group.Kind == "agents" {
			return apierr.New("PERMISSION_DENIED", "Agent-owned groups cannot be edited manually")
		}
		if group.Status != "active" {
			return apierr.New("GROUP_INACTIVE", "group is not active")
		}
		if add && member.Status != "active" {
			return apierr.New("ACTOR_MEMBER_INACTIVE", "member is not active")
		}
		if err := lockAuthorizationNodesTx(ctx, q, spaceID, groupID); err != nil {
			return err
		}
		if err := s.authorizeGroupTx(ctx, q, actorMemberID, "auth.groups:manage", spaceID, groupID); err != nil {
			return err
		}
		_, membershipErr := q.GetGroupMember(ctx, db.GetGroupMemberParams{GroupID: groupID, MemberID: memberID})
		if add && membershipErr == nil || !add && errors.Is(membershipErr, pgx.ErrNoRows) {
			return nil
		}
		if membershipErr != nil && !errors.Is(membershipErr, pgx.ErrNoRows) {
			return membershipErr
		}

		before, err := s.grantAuthoritySnapshotAtPositionTx(ctx, q, member.ID, spaceID, member.Type, delta.Node{Kind: delta.Space, ID: spaceID})
		if err != nil {
			return err
		}
		if add {
			if err := q.AddGroupMember(ctx, db.AddGroupMemberParams{GroupID: groupID, MemberID: memberID, SpaceID: spaceID, Source: "manual"}); err != nil {
				return normalizeDBError(err)
			}
		} else {
			if err := q.RemoveGroupMember(ctx, db.RemoveGroupMemberParams{GroupID: groupID, MemberID: memberID, SpaceID: spaceID}); err != nil {
				return normalizeDBError(err)
			}
		}
		after, err := s.grantAuthoritySnapshotAtPositionTx(ctx, q, member.ID, spaceID, member.Type, delta.Node{Kind: delta.Space, ID: spaceID})
		if err != nil {
			return err
		}
		change, err := delta.Evaluate(before, after, delta.Graph{})
		if err != nil {
			return err
		}
		if len(change.Permissions) != 0 || len(change.Rights) != 0 {
			if len(change.Permissions) != 0 {
				if err := s.authorizeGroupTx(ctx, q, actorMemberID, "auth.grants:assign", spaceID, groupID); err != nil {
					return err
				}
			}
			if len(change.Rights) != 0 {
				if err := s.authorizeGroupTx(ctx, q, actorMemberID, "auth.assign_rights:manage", spaceID, groupID); err != nil {
					return err
				}
			}
			if err := s.coverPositiveGrantDeltaTx(ctx, q, change, actorMemberID, member.ID, member.Type, spaceID); err != nil {
				return err
			}
		}
		action := "group.member.remove"
		if add {
			action = "group.member.add"
		}
		return audit.WriteSecurityEvent(ctx, q, audit.SecurityEvent{
			ActorType: "member", ActorID: actorMemberID, MemberID: memberID, Action: action, Outcome: "success",
			Resource:   audit.Resource{Type: "group_membership", ID: memberID + "/" + groupID, SpaceID: spaceID, GroupID: groupID},
			Permission: "auth.groups:manage",
		})
	})
}

// MoveGroup changes a standard group's parent while evaluating every member
// in the moved subtree against the same before/after authorization snapshot.
// A positive permission delta must be covered before the transaction commits.
func (s *Service) MoveGroup(ctx context.Context, actorMemberID, spaceID, groupID, parentGroupID string) error {
	if strings.TrimSpace(actorMemberID) == "" || strings.TrimSpace(spaceID) == "" || strings.TrimSpace(groupID) == "" {
		return apierr.New("VALIDATION_FAILED", "group move fields are required")
	}
	parentGroupID = strings.TrimSpace(parentGroupID)
	return s.Store.InTx(ctx, func(q *db.Queries) error {
		members, err := q.ListMembersInGroupSubtree(ctx, db.ListMembersInGroupSubtreeParams{GroupID: groupID, SpaceID: spaceID})
		if err != nil {
			return err
		}
		memberIDs := make([]string, 0, len(members))
		for _, member := range members {
			memberIDs = append(memberIDs, member.ID)
		}
		if err := lockAuthorizationActorTx(ctx, q, actorMemberID, memberIDs...); err != nil {
			return err
		}
		groups, err := q.LockGroupSubtree(ctx, db.LockGroupSubtreeParams{GroupID: groupID, SpaceID: spaceID})
		if err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return apierr.New("NOT_FOUND", "group was not found in this Space")
			}
			return err
		}
		if len(groups) == 0 {
			return apierr.New("NOT_FOUND", "group was not found in this Space")
		}
		target := groups[0]
		if target.Kind == "agents" {
			return apierr.New("PERMISSION_DENIED", "Agent-owned groups cannot be moved manually")
		}
		if target.Status != "active" {
			return apierr.New("GROUP_INACTIVE", "group is not active")
		}
		inSubtree := make(map[string]struct{}, len(groups))
		for _, group := range groups {
			inSubtree[group.ID] = struct{}{}
		}
		if _, ok := inSubtree[parentGroupID]; ok {
			return apierr.New("VALIDATION_FAILED", "group cannot be moved below itself")
		}
		var parent db.LockGroupInSpaceForAuthorizationRow
		if parentGroupID != "" {
			parent, err = q.LockGroupInSpaceForAuthorization(ctx, db.LockGroupInSpaceForAuthorizationParams{ID: parentGroupID, SpaceID: spaceID})
			if errors.Is(err, pgx.ErrNoRows) {
				return apierr.New("NOT_FOUND", "new parent group was not found in this Space")
			}
			if err != nil {
				return err
			}
			if parent.Kind == "agents" {
				return apierr.New("PERMISSION_DENIED", "Agent-owned groups cannot be used as a manual parent")
			}
			if parent.Status != "active" {
				return apierr.New("GROUP_INACTIVE", "new parent group is not active")
			}
		}
		if err := s.authorizeGroupTx(ctx, q, actorMemberID, "auth.groups:manage", spaceID, groupID); err != nil {
			return err
		}
		if parentGroupID != "" {
			if err := s.authorizeGroupTx(ctx, q, actorMemberID, "auth.groups:manage", spaceID, parentGroupID); err != nil {
				return err
			}
		}
		if currentParent := nullableID(target.ParentID); currentParent == parentGroupID {
			return nil
		}
		height := 1
		for _, group := range groups {
			depth := 1
			for current := nullableID(group.ParentID); current != ""; {
				if _, ok := inSubtree[current]; !ok {
					break
				}
				depth++
				current = nullableParent(groups, current)
			}
			if depth > height {
				height = depth
			}
		}
		parentDepth := 0
		if parentGroupID != "" {
			parentDepth, err = groupDepthTx(ctx, q, parentGroupID, spaceID)
			if err != nil {
				return err
			}
		}
		if parentDepth+height > maxGroupDepth {
			return apierr.New("VALIDATION_FAILED", "group tree exceeds the maximum depth")
		}
		before := make(map[string]struct {
			typeName string
			snapshot delta.Snapshot
		}, len(members))
		for _, member := range members {
			snapshot, err := s.grantAuthoritySnapshotTx(ctx, q, member.ID, spaceID, member.Type)
			if err != nil {
				return err
			}
			before[member.ID] = struct {
				typeName string
				snapshot delta.Snapshot
			}{typeName: member.Type, snapshot: snapshot}
		}
		if err := q.UpdateGroupParent(ctx, db.UpdateGroupParentParams{GroupID: groupID, SpaceID: spaceID, ParentID: pgtype.Text{String: parentGroupID, Valid: parentGroupID != ""}}); err != nil {
			return normalizeDBError(err)
		}
		for _, member := range members {
			after, err := s.grantAuthoritySnapshotTx(ctx, q, member.ID, spaceID, member.Type)
			if err != nil {
				return err
			}
			prior := before[member.ID]
			change, err := delta.Evaluate(prior.snapshot, after, delta.Graph{})
			if err != nil {
				return err
			}
			if len(change.Permissions) == 0 && len(change.Rights) == 0 {
				continue
			}
			if err := s.authorizeTargetTx(ctx, q, actorMemberID, "auth.grants:assign", spaceID, member.ID); err != nil {
				return err
			}
			if err := s.coverPositiveGrantDeltaTx(ctx, q, change, actorMemberID, member.ID, prior.typeName, spaceID); err != nil {
				return err
			}
		}
		version, err := q.BumpPolicyVersion(ctx, db.BumpPolicyVersionParams{ID: spaceID})
		if err != nil {
			return err
		}
		return audit.WriteSecurityEvent(ctx, q, audit.SecurityEvent{
			ActorType: "member", ActorID: actorMemberID, MemberID: actorMemberID,
			Action: "group.move", Outcome: "success", Permission: "auth.groups:manage", PolicyVersion: version,
			Resource: audit.Resource{Type: "group", ID: groupID, SpaceID: spaceID, GroupID: groupID},
			Metadata: map[string]string{"previous_parent_group_id": nullableID(target.ParentID), "parent_group_id": parentGroupID},
		})
	})
}

func nullableID(value pgtype.Text) string {
	if value.Valid {
		return value.String
	}
	return ""
}

func nullableParent(groups []db.LockGroupSubtreeRow, id string) string {
	for _, group := range groups {
		if group.ID == id {
			return nullableID(group.ParentID)
		}
	}
	return ""
}

func groupDepthTx(ctx context.Context, q *db.Queries, groupID, spaceID string) (int, error) {
	depth := 0
	seen := map[string]struct{}{}
	for current := groupID; current != ""; {
		if _, ok := seen[current]; ok {
			return 0, apierr.New("INVALID_RESOURCE", "group hierarchy contains a cycle")
		}
		seen[current] = struct{}{}
		group, err := q.GetGroupInSpace(ctx, db.GetGroupInSpaceParams{ID: current, SpaceID: spaceID})
		if err != nil {
			return 0, err
		}
		depth++
		current = nullableID(group.ParentID)
		if depth > maxGroupDepth {
			return 0, apierr.New("VALIDATION_FAILED", "group tree exceeds the maximum depth")
		}
	}
	return depth, nil
}

func (s *Service) authorizeGroupTx(ctx context.Context, q *db.Queries, actorMemberID, permission, spaceID, groupID string) error {
	if err := validateHumanActorTx(ctx, q, actorMemberID); err != nil {
		return err
	}
	decision, err := s.CheckTx(ctx, q, CheckRequest{
		MemberID: actorMemberID, Permission: permission, ResourceSpace: spaceID, ResourceGroup: groupID,
	})
	if err != nil {
		return err
	}
	if decision.Effect == engine.Allow {
		return nil
	}
	return &apierr.Error{Code: decision.Code, Message: "The authorization engine denied this operation.", Details: map[string]string{"permission": permission, "group_id": groupID}}
}
