package enterprise

import (
	"context"
	"encoding/json"
	"strconv"
	"strings"

	"github.com/plystra/auth/internal/apierr"
	"github.com/plystra/auth/internal/audit"
	"github.com/plystra/auth/internal/authorization"
	"github.com/plystra/auth/internal/db"
)

type ssoMappingAuthority struct {
	MemberID string `json:"member_id"`
	UserID   string `json:"user_id,omitempty"`
}

func validateSSORoleMappings(mappings map[string]string) error {
	if len(mappings) > maxRoleMappings {
		return apierr.New("validation_failed", "too many SSO role mappings")
	}
	for group, roleID := range mappings {
		if strings.TrimSpace(group) == "" || len(group) > 256 || strings.TrimSpace(roleID) == "" || len(roleID) > 128 {
			return apierr.New("validation_failed", "SSO role mappings are invalid")
		}
	}
	return nil
}

func SSORoleMappingUpdateRequest(spaceID, connectionID, ifMatch string, mappings map[string]string) map[string]string {
	// Maps of strings are encoded in the same canonical form as step-up.
	encoded, _ := json.Marshal(mappings)
	return map[string]string{
		"operation": SSOConnectionUpdateOperation, "space_id": spaceID, "connection_id": connectionID,
		"if_match": ifMatch, "role_mappings_digest": sha256Hex(string(encoded)),
	}
}

func (s *Service) ReplaceSSORoleMappings(ctx context.Context, actorMemberID, spaceID, connectionID, ifMatch string, mappings map[string]string) (Connection, error) {
	if err := validateSSORoleMappings(mappings); err != nil {
		return Connection{}, err
	}
	if mappings == nil {
		return Connection{}, apierr.New("validation_failed", "role_mappings must be an object")
	}
	encoded, err := json.Marshal(mappings)
	if err != nil {
		return Connection{}, err
	}
	request := SSORoleMappingUpdateRequest(spaceID, connectionID, ifMatch, mappings)
	var out Connection
	err = s.Store.InTx(ctx, func(q *db.Queries) error {
		roles, err := authorization.LockSSOMappingUpdateRolesTx(ctx, q, actorMemberID, spaceID, mappings)
		if err != nil {
			return err
		}
		if _, err := s.lockConnectionUpdateTx(ctx, q, actorMemberID, request); err != nil {
			return err
		}
		current, err := q.GetSSOConnection(ctx, db.GetSSOConnectionParams{ID: connectionID})
		if err != nil {
			return err
		}
		var previous map[string]string
		if err := json.Unmarshal(current.RoleMappings, &previous); err != nil {
			return err
		}
		var sources map[string]ssoMappingAuthority
		if err := json.Unmarshal(current.RoleMappingAuthority, &sources); err != nil {
			return err
		}
		changed := make(map[string]string)
		updated := make(map[string]ssoMappingAuthority)
		actor := ssoMappingAuthority{MemberID: actorMemberID, UserID: authorization.HumanActorUserID(ctx, actorMemberID)}
		for group, role := range mappings {
			if role != previous[group] {
				changed[group], updated[group] = role, actor
			} else if source, ok := sources[group]; ok {
				updated[group] = source
			}
		}
		if err := s.Authorization.CheckSSOMappingUpdateDeltaTx(ctx, q, actorMemberID, spaceID, connectionID, changed, roles); err != nil {
			return err
		}
		encodedSources, err := json.Marshal(updated)
		if err != nil {
			return err
		}
		row, err := q.ReplaceSSORoleMappings(ctx, db.ReplaceSSORoleMappingsParams{
			ID: connectionID, SpaceID: spaceID, RoleMappings: encoded, RoleMappingAuthority: encodedSources,
		})
		if err != nil {
			return err
		}
		out, err = connectionFromPublicRow(db.ListSSOConnectionsRow(row))
		if err != nil {
			return err
		}
		removed := 0
		for group := range previous {
			if _, retained := mappings[group]; !retained {
				removed++
			}
		}
		return audit.WriteSecurityEvent(ctx, q, audit.SecurityEvent{
			ActorType: "member", ActorID: actorMemberID, MemberID: actorMemberID,
			Action: "sso.connection.role_mappings.update", Outcome: "success", Permission: "auth.connections:manage",
			Resource: audit.Resource{Type: "sso_connection", ID: connectionID, SpaceID: spaceID},
			Metadata: map[string]string{"changed": strconv.Itoa(len(changed)), "removed": strconv.Itoa(removed)},
		})
	})
	if err != nil {
		return Connection{}, normalizeConnectionError(err)
	}
	return out, nil
}
