package authorization

import (
	"context"
	"encoding/json"
	"errors"
	"maps"
	"slices"

	"github.com/jackc/pgx/v5"
	"github.com/plystra/auth/internal/apierr"
	"github.com/plystra/auth/internal/authz/delta"
	"github.com/plystra/auth/internal/authz/engine"
	"github.com/plystra/auth/internal/db"
)

// CheckSSOConnectionCreateTx authorizes the connection and its prospective
// role grants. First login creates a human in the connection's own Space,
// even when descendants inherit its discovery route.
func (s *Service) CheckSSOConnectionCreateTx(ctx context.Context, q *db.Queries, actorID, spaceID, connectionID string, mappings map[string]string) error {
	if err := lockHumanActorAccountTx(ctx, q, actorID); err != nil {
		return err
	}
	mapped := slices.Compact(slices.Sorted(maps.Values(mappings)))
	var roles []db.LockSSOMappingRolesRow
	if len(mapped) > 0 {
		var err error
		roles, err = q.LockSSOMappingRoles(ctx, db.LockSSOMappingRolesParams{SpaceID: spaceID, MappedRoleIds: mapped})
		if err != nil {
			return err
		}
	}
	// Acquire role locks before member and node locks, but disclose no role
	// information until the caller's current management authority is proven.
	decision, err := s.CheckMutationTx(ctx, q, CheckRequest{MemberID: actorID, Permission: "auth.connections:manage", ResourceSpace: spaceID})
	if err != nil {
		return err
	}
	if decision.Effect != engine.Allow {
		return &apierr.Error{Code: decision.Code, Message: "The authorization engine denied this operation."}
	}
	if err := checkSSOConfiguratorTx(ctx, q, actorID, HumanActorUserID(ctx, actorID)); err != nil {
		return err
	}
	return s.checkSSOMappedDeltaTx(ctx, q, actorID, spaceID, connectionID, mapped, roles, false)
}

// CheckSSOLoginGrantsTx runs only for a newly bound human, with the same roles,
// identity chain and Space held until commit. The interactive approval authorizes
// connection configuration. Automated grants use current assignment authority.
func (s *Service) CheckSSOLoginGrantsTx(ctx context.Context, q *db.Queries, actorID, userID, spaceID, connectionID string, mapped []string, roles []db.LockSSOMappingRolesRow) error {
	ctx = WithHumanActor(ctx, actorID, userID)
	return s.checkSSOMappedDeltaTx(ctx, q, actorID, spaceID, connectionID, mapped, roles, true)
}

// LockSSOLoginGrantsTx interleaves the mapped/default role locks between
// the participating accounts and member chains, as in interactive role edits.
func LockSSOLoginGrantsTx(ctx context.Context, q *db.Queries, spaceID string, users, members, mapped []string) ([]db.LockSSOMappingRolesRow, error) {
	if err := lockProvisioningUsersTx(ctx, q, users); err != nil {
		return nil, err
	}
	roles, err := q.LockSSOMappingRoles(ctx, db.LockSSOMappingRolesParams{SpaceID: spaceID, MappedRoleIds: mapped})
	if err != nil {
		return nil, err
	}
	if err := lockAuthorizationMembersTx(ctx, q, members...); err != nil {
		return nil, err
	}
	if err := lockAuthorizationNodesTx(ctx, q, spaceID, ""); err != nil {
		return nil, err
	}
	return roles, nil
}

func (s *Service) checkSSOMappedDeltaTx(ctx context.Context, q *db.Queries, actorID, spaceID, connectionID string, mapped []string, roles []db.LockSSOMappingRolesRow, automated bool) error {
	var before, after delta.Snapshot
	found := 0
	for _, role := range roles {
		isMapped := slices.Contains(mapped, role.ID)
		if isMapped {
			if err := validateOrdinaryGrantRoleTx(ctx, q, role.ID); err != nil {
				return err
			}
			found++
		}
		permissions, err := ssoHumanRolePermissionsTx(ctx, q, role.ID, spaceID, connectionID, isMapped)
		if err != nil {
			return err
		}
		if role.Name == "member" {
			// JIT grants this role to every new human whether or not any claim matches.
			before.Permissions = permissions
		}
		if isMapped {
			after.Permissions = append(after.Permissions, permissions...)
		}
	}
	if found != len(mapped) {
		return apierr.New("validation_failed", "role mapping references a role outside this Space")
	}
	after.Permissions = append(after.Permissions, before.Permissions...)
	change, err := delta.Evaluate(before, after, delta.Graph{})
	if err != nil || len(change.Permissions) == 0 {
		return err
	}
	if automated {
		if err := checkSSOConfiguratorTx(ctx, q, actorID, HumanActorUserID(ctx, actorID)); err != nil {
			return err
		}
	}
	if err := s.authorizeGroupTx(ctx, q, actorID, "auth.grants:assign", spaceID, ""); err != nil {
		return err
	}
	// The future human has no member ID yet. The receiving Space and grant
	// anchor are already known and remain the same for every mapped role.
	return s.coverPositiveGrantDeltaTx(ctx, q, change, actorID, "", "human", spaceID)
}

func checkSSOConfiguratorTx(ctx context.Context, q *db.Queries, memberID, userID string) error {
	if memberID == "" {
		return apierr.New("AUTHORITY_DELTA_NOT_COVERED", "the SSO mapping has no verified configuring identity")
	}
	member, err := q.GetMemberForAuthorization(ctx, db.GetMemberForAuthorizationParams{ID: memberID})
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return err
	}
	validIdentity := member.Type == "human" && userID != "" || member.Type == "agent" && userID == ""
	if member.Status != "active" || !validIdentity {
		return apierr.New("AUTHORITY_DELTA_NOT_COVERED", "the SSO mapping configuring identity is unavailable")
	}
	return validateHumanActorTx(ctx, q, memberID)
}

func ssoHumanRolePermissionsTx(ctx context.Context, q *db.Queries, roleID, spaceID, connectionID string, isMapped bool) ([]delta.Permission, error) {
	rows, err := q.ListRolePermissions(ctx, db.ListRolePermissionsParams{RoleID: roleID})
	if err != nil {
		return nil, err
	}
	var projected []delta.Permission
	for _, row := range rows {
		if isMapped && row.Status != "active" {
			return nil, &apierr.Error{Code: "AUTHORITY_DELTA_NOT_COVERED", Message: "The role contains a permission that cannot be newly granted.", Details: map[string]string{"permission": row.Key}}
		}
		var kinds []string
		if err := json.Unmarshal(row.PrincipalKinds, &kinds); err != nil {
			return nil, err
		}
		if row.Status != "disabled" && slices.Contains(kinds, "human") {
			projected = append(projected, delta.Permission{
				Subject: connectionID, Position: delta.Node{Kind: delta.Space, ID: spaceID},
				Scope: delta.Scope{Kind: delta.SpaceOnly, Anchor: spaceID}, Key: row.Key,
			})
		}
	}
	return projected, nil
}
