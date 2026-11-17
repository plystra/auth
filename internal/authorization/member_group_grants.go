package authorization

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/plystra/auth/internal/apierr"
	"github.com/plystra/auth/internal/audit"
	"github.com/plystra/auth/internal/db"
	"github.com/plystra/auth/internal/ids"
)

// CreateMemberGroupGrant adds an ordinary grant without replacing existing
// authority. The member's position governs management and assignment coverage;
// a resource anchor never relocates the recipient into the resource group.
func (s *Service) CreateMemberGroupGrant(ctx context.Context, actorMemberID, spaceID, memberID string, in GrantInput) (Grant, error) {
	in.Permissions = uniqueSorted(in.Permissions)
	if actorMemberID == "" || spaceID == "" || memberID == "" || (in.RoleID == "") == (len(in.Permissions) == 0) || len(in.Permissions) > 256 {
		return Grant{}, apierr.New("VALIDATION_FAILED", "a member grant requires exactly one role or permission set")
	}
	if in.Scope != "group" && in.Scope != "group_tree" || in.AnchorGroupID == "" || in.AnchorSpaceID != "" {
		return Grant{}, apierr.New("VALIDATION_FAILED", "group scopes require only anchor_group_id")
	}
	var out Grant
	err := s.Store.InTx(ctx, func(q *db.Queries) error {
		if err := lockHumanActorAccountTx(ctx, q, actorMemberID); err != nil {
			return err
		}
		permissions, err := grantPermissionSourceTx(ctx, q, spaceID, in)
		if err != nil {
			return err
		}
		if err := lockAuthorizationMembersTx(ctx, q, actorMemberID, memberID); err != nil {
			return err
		}
		member, err := q.LockMemberInSpace(ctx, db.LockMemberInSpaceParams{ID: memberID, SpaceID: spaceID})
		if errors.Is(err, pgx.ErrNoRows) || err == nil && member.Status == "removed" {
			return apierr.New("NOT_FOUND", "grantee member was not found in this Space")
		}
		if err != nil {
			return err
		}
		anchorSpace, err := q.GetGroupSpaceForAuthorization(ctx, db.GetGroupSpaceForAuthorizationParams{ID: in.AnchorGroupID})
		if errors.Is(err, pgx.ErrNoRows) {
			return apierr.New("NOT_FOUND", "grant anchor group was not found")
		}
		if err != nil {
			return err
		}
		if err := lockAuthorizationNodesTx(ctx, q, spaceID, "", anchorSpace); err != nil {
			return err
		}
		targetGroup, err := resourceGroupForMemberTx(ctx, q, memberID, spaceID)
		if err != nil {
			return err
		}
		groupSpaces := map[string]string{in.AnchorGroupID: anchorSpace}
		if targetGroup != "" {
			groupSpaces[targetGroup] = spaceID
		}
		if err := lockGroupGrantNodesTx(ctx, q, groupSpaces); err != nil {
			return err
		}
		if err := validateMemberGrantAnchorTx(ctx, q, spaceID, "space", anchorSpace); err != nil {
			return err
		}
		if err := validateHumanActorTx(ctx, q, actorMemberID); err != nil {
			return err
		}
		if err := s.authorizeTargetTx(ctx, q, actorMemberID, "auth.grants:assign", spaceID, memberID, anchorSpace); err != nil {
			return err
		}
		if member.Type == "agent" {
			agent, err := q.GetAgentMember(ctx, db.GetAgentMemberParams{MemberID: memberID})
			if err != nil {
				return err
			}
			if agent.Source.String == "oauth" {
				return apierr.New("VALIDATION_FAILED", "OAuth Agent grants can only be changed through consent")
			}
		}
		if err := validateNewGrantPermissionsTx(ctx, q, permissions); err != nil {
			return err
		}
		before, err := s.grantAuthoritySnapshotTx(ctx, q, memberID, spaceID, member.Type)
		if err != nil {
			return err
		}
		var encoded []byte
		if in.RoleID == "" {
			encoded, err = json.Marshal(permissions)
			if err != nil {
				return err
			}
		}
		row, err := q.CreateGrant(ctx, db.CreateGrantParams{
			ID: string(ids.New[ids.GrantID]("grt")), SpaceID: spaceID, GrantedBy: actorMemberID,
			RoleID: pgtype.Text{String: in.RoleID, Valid: in.RoleID != ""}, PermissionKeys: encoded,
			GranteeMemberID: pgtype.Text{String: memberID, Valid: true}, Scope: in.Scope,
			AnchorGroupID: pgtype.Text{String: in.AnchorGroupID, Valid: true},
		})
		if err != nil {
			return normalizeDBError(err)
		}
		if err := s.coverGrantDeltaTx(ctx, q, before, actorMemberID, memberID, spaceID, member.Type); err != nil {
			return err
		}
		action := "grant.inline.create"
		if in.RoleID != "" {
			action = "grant.create"
		}
		if err := audit.WriteSecurityEvent(ctx, q, audit.SecurityEvent{
			ActorType: "member", ActorID: actorMemberID, MemberID: memberID, Action: action, Outcome: "success",
			Resource: audit.Resource{Type: "grant", ID: row.ID, SpaceID: spaceID, GroupID: targetGroup}, Permission: "auth.grants:assign",
			Metadata: map[string]string{"scope": in.Scope, "anchor_group_id": in.AnchorGroupID},
		}); err != nil {
			return err
		}
		out = Grant{ID: row.ID, SpaceID: spaceID, RoleID: in.RoleID, GranteeMemberID: memberID, Scope: in.Scope,
			AnchorGroupID: in.AnchorGroupID, GrantedBy: actorMemberID}
		if in.RoleID == "" {
			out.Permissions = permissions
		}
		return nil
	})
	return out, err
}
