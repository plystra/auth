package authorization

import (
	"context"
	"encoding/json"
	"maps"
	"slices"

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
	mapped := make(map[string]bool, len(mappings))
	for _, id := range mappings {
		mapped[id] = true
	}
	var roles []db.LockSSOMappingRolesRow
	if len(mapped) > 0 {
		var err error
		roles, err = q.LockSSOMappingRoles(ctx, db.LockSSOMappingRolesParams{SpaceID: spaceID, MappedRoleIds: slices.Collect(maps.Keys(mapped))})
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
	var before, after delta.Snapshot
	for _, role := range roles {
		isMapped := mapped[role.ID]
		if isMapped {
			if err := validateOrdinaryGrantRoleTx(ctx, q, role.ID); err != nil {
				return err
			}
			delete(mapped, role.ID)
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
	if len(mapped) != 0 {
		return apierr.New("validation_failed", "role mapping references a role outside this Space")
	}
	after.Permissions = append(after.Permissions, before.Permissions...)
	change, err := delta.Evaluate(before, after, delta.Graph{})
	if err != nil || len(change.Permissions) == 0 {
		return err
	}
	if err := s.authorizeGroupTx(ctx, q, actorID, "auth.grants:assign", spaceID, ""); err != nil {
		return err
	}
	// The future human has no member ID yet. The receiving Space and grant
	// anchor are already known and remain the same for every mapped role.
	return s.coverPositiveGrantDeltaTx(ctx, q, change, actorID, "", "human", spaceID)
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
