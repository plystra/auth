package authorization

import (
	"context"
	"encoding/json"
	"errors"
	"slices"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/plystra/auth/internal/apierr"
	"github.com/plystra/auth/internal/audit"
	"github.com/plystra/auth/internal/authz/delta"
	"github.com/plystra/auth/internal/authz/engine"
	"github.com/plystra/auth/internal/db"
	"github.com/plystra/auth/internal/ids"
)

// ReplaceAgentGroupGrants applies the same owner system assignment right to
// a group resource boundary. The group's actual Space is resolved before any
// permission decision; the Agent's home group is not the resource anchor.
func (s *Service) ReplaceAgentGroupGrants(ctx context.Context, actorMemberID, spaceID, granteeMemberID string, permissions []string, scope, anchorGroupID string) (Grant, error) {
	permissions = uniqueSorted(permissions)
	if len(permissions) == 0 || len(permissions) > 256 || anchorGroupID == "" || (scope != "group" && scope != "group_tree") {
		return Grant{}, apierr.New("VALIDATION_FAILED", "group grants require permissions, group/group_tree scope and anchor_group_id")
	}
	var out Grant
	err := s.Store.InTx(ctx, func(q *db.Queries) error {
		if err := lockAuthorizationActorTx(ctx, q, actorMemberID, granteeMemberID); err != nil {
			return err
		}
		agent, err := q.GetAgentMember(ctx, db.GetAgentMemberParams{MemberID: granteeMemberID})
		if errors.Is(err, pgx.ErrNoRows) || err == nil && agent.SpaceID != spaceID {
			return apierr.New("NOT_FOUND", "Agent was not found in this Space")
		}
		if err != nil {
			return err
		}
		if agent.Source.String == "oauth" {
			return apierr.New("VALIDATION_FAILED", "OAuth Agent grants can only be changed through consent")
		}
		if agent.Status != "active" || agent.GroupStatus != "active" {
			return apierr.New("OWNER_INACTIVE", "the Agent or its group is not active")
		}
		anchorSpaceID, err := q.GetGroupSpaceForAuthorization(ctx, db.GetGroupSpaceForAuthorizationParams{ID: anchorGroupID})
		if errors.Is(err, pgx.ErrNoRows) {
			return apierr.New("NOT_FOUND", "grant anchor group was not found")
		}
		if err != nil {
			return err
		}
		if err := lockAuthorizationNodesTx(ctx, q, anchorSpaceID, anchorGroupID, spaceID); err != nil {
			return err
		}
		if err := validateHumanActorTx(ctx, q, actorMemberID); err != nil {
			return err
		}
		if err := validateMemberGrantAnchorTx(ctx, q, spaceID, "space", anchorSpaceID); err != nil {
			return err
		}
		if _, err := groupAncestorsQueries(ctx, q, anchorGroupID, anchorSpaceID); err != nil {
			if errors.Is(err, errGroupInactive) {
				return apierr.New("RESOURCE_GROUP_INACTIVE", "grant anchor group is not active")
			}
			return err
		}
		systemOwner := agent.OwnerMemberID.Valid && agent.OwnerMemberID.String == actorMemberID
		if systemOwner {
			systemOwner, err = ownerGrantSystemRightTx(ctx, q, actorMemberID, agent.CreatedByUserID.String)
			if err != nil {
				return err
			}
		}
		if systemOwner {
			if err := s.coverOwnerGroupGrantTx(ctx, q, actorMemberID, permissions, scope, anchorSpaceID, anchorGroupID, map[string]bool{}); err != nil {
				return err
			}
		} else if err := s.authorizeTargetTx(ctx, q, actorMemberID, "auth.grants:assign", spaceID, granteeMemberID, anchorSpaceID); err != nil {
			return err
		}
		before, err := s.grantAuthoritySnapshotTx(ctx, q, granteeMemberID, spaceID, "agent")
		if err != nil {
			return err
		}
		if err := q.RevokeInlineGrantsForMember(ctx, db.RevokeInlineGrantsForMemberParams{GranteeMemberID: pgtype.Text{String: granteeMemberID, Valid: true}}); err != nil {
			return err
		}
		encoded, err := json.Marshal(permissions)
		if err != nil {
			return err
		}
		row, err := q.CreateGrant(ctx, db.CreateGrantParams{
			ID: string(ids.New[ids.GrantID]("grt")), SpaceID: spaceID, PermissionKeys: encoded,
			GranteeMemberID: pgtype.Text{String: granteeMemberID, Valid: true}, Scope: scope,
			AnchorGroupID: pgtype.Text{String: anchorGroupID, Valid: true}, GrantedBy: actorMemberID,
		})
		if err != nil {
			return normalizeDBError(err)
		}
		if !systemOwner {
			if err := s.coverGrantDeltaTx(ctx, q, before, actorMemberID, granteeMemberID, spaceID, "agent"); err != nil {
				return err
			}
		}
		if err := audit.WriteSecurityEvent(ctx, q, audit.SecurityEvent{
			ActorType: "member", ActorID: actorMemberID, Action: "grant.replace", Outcome: "success", MemberID: granteeMemberID,
			Resource: audit.Resource{Type: "grant", ID: row.ID},
		}); err != nil {
			return err
		}
		out = Grant{ID: row.ID, SpaceID: spaceID, GranteeMemberID: granteeMemberID, Permissions: permissions, Scope: scope, AnchorGroupID: anchorGroupID, GrantedBy: actorMemberID}
		return nil
	})
	return out, err
}

func (s *Service) coverOwnerGroupGrantTx(ctx context.Context, q *db.Queries, ownerID string, permissions []string, scope, spaceID, groupID string, seen map[string]bool) error {
	if seen[ownerID] || len(seen) >= 64 {
		return apierr.New("OWNER_INACTIVE", "the Agent owner chain is invalid")
	}
	seen[ownerID] = true
	owner, err := q.GetMemberForAuthorization(ctx, db.GetMemberForAuthorizationParams{ID: ownerID})
	if errors.Is(err, pgx.ErrNoRows) {
		return apierr.New("OWNER_INACTIVE", "the Agent owner member was not found")
	}
	if err != nil {
		return err
	}
	assignments, _, err := s.assignmentsQueries(ctx, q, ownerID)
	if err != nil {
		return err
	}
	position := delta.Node{Kind: delta.Space, ID: spaceID}
	before := permissionSnapshot(assignments, ownerID, position, owner.Type)
	after := delta.Snapshot{}
	for _, key := range permissions {
		catalog, err := q.GetPermissionByKey(ctx, db.GetPermissionByKeyParams{Key: key})
		if errors.Is(err, pgx.ErrNoRows) {
			return rejectOwnerGroupGrant(permissions, scope, groupID)
		}
		if err != nil {
			return err
		}
		var kinds []string
		if err := json.Unmarshal(catalog.PrincipalKinds, &kinds); err != nil {
			return err
		}
		if !slices.Contains(kinds, "agent") || owner.Type == "agent" && catalog.AgentApproval == "required" {
			return rejectOwnerGroupGrant(permissions, scope, groupID)
		}
		decision, err := s.CheckTx(ctx, q, CheckRequest{MemberID: ownerID, Permission: key, ResourceSpace: spaceID, ResourceGroup: groupID})
		if err != nil {
			return err
		}
		if decision.Effect != engine.Allow {
			if decision.Code == "OWNER_INACTIVE" || decision.Code == "ACTOR_MEMBER_INACTIVE" {
				return apierr.New("OWNER_INACTIVE", "the Agent owner chain is not active")
			}
			return rejectOwnerGroupGrant(permissions, scope, groupID)
		}
		after.Permissions = append(after.Permissions, delta.Permission{Subject: ownerID, Position: position, Key: key, Scope: delta.Scope{Kind: delta.ScopeKind(scope), Anchor: groupID}})
	}
	graph, err := grantDeltaGraphTx(ctx, q, before, after)
	if err != nil {
		return err
	}
	change, err := delta.Evaluate(before, after, graph)
	if err != nil {
		return err
	}
	if err := rejectUncoveredDelta(change, "The group scope exceeds the owner's current authority."); err != nil {
		return err
	}
	if owner.Type == "agent" {
		parent, err := q.GetAgentMember(ctx, db.GetAgentMemberParams{MemberID: ownerID})
		if errors.Is(err, pgx.ErrNoRows) {
			return apierr.New("OWNER_INACTIVE", "the Agent owner record was not found")
		}
		if err != nil {
			return err
		}
		return s.coverOwnerGroupGrantTx(ctx, q, parent.OwnerMemberID.String, permissions, scope, spaceID, groupID, seen)
	}
	return nil
}

func rejectOwnerGroupGrant(permissions []string, scope, groupID string) error {
	change := delta.Result{}
	for _, key := range permissions {
		change.Permissions = append(change.Permissions, delta.Permission{Key: key, Scope: delta.Scope{Kind: delta.ScopeKind(scope), Anchor: groupID}})
	}
	return rejectUncoveredDelta(change, "The Agent grant exceeds the owner's current authority.")
}
