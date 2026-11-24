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
	grants   []ssoMappingGrant
	roles    []db.LockSSOMappingRolesRow
}

type ssoMappingGrant struct {
	authority ssoMappingAuthority
	roles     []string
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
	var sources map[string]ssoMappingAuthority
	if err := json.Unmarshal(c.RoleMappingAuthority, &sources); err != nil {
		return nil, err
	}
	defaultSource := ssoMappingAuthority{MemberID: c.ConfiguredByMemberID.String, UserID: c.ConfiguredByUserID.String}
	matched := make(map[string]struct{})
	byAuthority := make(map[ssoMappingAuthority]map[string]struct{})
	var authorityOrder []ssoMappingAuthority
	for _, group := range claims.Groups {
		if role, ok := mappings[group]; ok {
			source, overridden := sources[group]
			if !overridden {
				source = defaultSource
			}
			if byAuthority[source] == nil {
				byAuthority[source] = make(map[string]struct{})
				authorityOrder = append(authorityOrder, source)
			}
			byAuthority[source][role], matched[role] = struct{}{}, struct{}{}
		}
	}
	plan := &ssoLoginGrants{userID: external.UserID}
	users := []string{external.UserID}
	var members []string
	for _, source := range authorityOrder {
		plan.grants = append(plan.grants, ssoMappingGrant{source, slices.Sorted(maps.Keys(byAuthority[source]))})
		users = append(users, source.UserID)
		members = append(members, source.MemberID)
	}
	plan.roles, err = authorization.LockSSOLoginGrantsTx(ctx, q, c.SpaceID, users, members, slices.Sorted(maps.Keys(matched)))
	if err != nil {
		return nil, err
	}
	return plan, lockDirectorySSOTx(ctx, q, c, nil)
}
