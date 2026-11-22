package enterprise

import (
	"context"
	"encoding/json"
	"errors"
	"maps"
	"slices"

	"github.com/jackc/pgx/v5"
	"github.com/plystra/auth/internal/authorization"
	"github.com/plystra/auth/internal/db"
)

type ssoLoginGrants struct {
	userID   string
	memberID string
	mapped   []string
	roles    []db.LockSSOMappingRolesRow
}

// Existing and SCIM-provisioned memberships authenticate without replaying a
// mapping. Inspect the identity before choosing the lock set and re-read it
// under the node/connection locks before any writes.
func lockSSOLoginTx(ctx context.Context, q *db.Queries, c db.SsoConnection, claims idTokenClaims, directory *directorySSOHint) (*ssoLoginGrants, error) {
	if directory != nil {
		if err := authorization.LockProvisioningTx(ctx, q, c.SpaceID, []string{directory.user.UserID}, []string{directory.user.MemberID}); err != nil {
			return nil, err
		}
		return nil, lockDirectorySSOTx(ctx, q, c, directory)
	}
	external, err := q.GetExternalIdentity(ctx, db.GetExternalIdentityParams{Issuer: c.Issuer, Subject: claims.Subject})
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return nil, err
	}
	if err == nil {
		member, err := q.GetSSOMembershipForUser(ctx, db.GetSSOMembershipForUserParams{UserID: external.UserID, SpaceID: c.SpaceID})
		if err == nil {
			if err := authorization.LockProvisioningTx(ctx, q, c.SpaceID, []string{external.UserID}, []string{member.ID}); err != nil {
				return nil, err
			}
			return &ssoLoginGrants{userID: external.UserID, memberID: member.ID}, lockDirectorySSOTx(ctx, q, c, nil)
		}
		if !errors.Is(err, pgx.ErrNoRows) {
			return nil, err
		}
	}
	var mappings map[string]string
	if err := json.Unmarshal(c.RoleMappings, &mappings); err != nil {
		return nil, err
	}
	matched := make(map[string]bool)
	for _, group := range claims.Groups {
		if role, ok := mappings[group]; ok {
			matched[role] = true
		}
	}
	plan := &ssoLoginGrants{userID: external.UserID, mapped: slices.Sorted(maps.Keys(matched))}
	users := []string{external.UserID}
	var members []string
	if len(plan.mapped) > 0 {
		users = append(users, c.ConfiguredByUserID.String)
		members = append(members, c.ConfiguredByMemberID.String)
	}
	plan.roles, err = authorization.LockSSOLoginGrantsTx(ctx, q, c.SpaceID, users, members, plan.mapped)
	if err != nil {
		return nil, err
	}
	return plan, lockDirectorySSOTx(ctx, q, c, nil)
}
