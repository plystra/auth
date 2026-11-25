package enterprise

import (
	"context"
	"errors"
	"strconv"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/plystra/auth/internal/apierr"
	"github.com/plystra/auth/internal/audit"
	"github.com/plystra/auth/internal/db"
)

const DomainUpdateOperation = "domains.update"

func DomainUpdateRequest(spaceID, domainID, ifMatch string, forceSSO bool) map[string]string {
	return map[string]string{
		"operation": DomainUpdateOperation, "space_id": spaceID, "domain_id": domainID,
		"if_match": strings.TrimSpace(ifMatch), "force_sso": strconv.FormatBool(forceSSO),
	}
}

func (s *Service) UpdateDomainEnforcement(ctx context.Context, actorMemberID, spaceID, domainID, ifMatch string, forceSSO bool) (Domain, error) {
	request := DomainUpdateRequest(spaceID, domainID, ifMatch, forceSSO)
	var out Domain
	err := s.Store.InTx(ctx, func(q *db.Queries) error {
		if err := s.authorizeSettingsTx(ctx, q, actorMemberID, request); err != nil {
			return err
		}
		current, err := q.LockSSODomain(ctx, db.LockSSODomainParams{ID: domainID, SpaceID: spaceID})
		if errors.Is(err, pgx.ErrNoRows) {
			return apierr.New("not_found", "domain was not found")
		}
		if err != nil {
			return err
		}
		if request["if_match"] != resourceETag(current.ID, current.UpdatedAt.Time) {
			return apierr.New("precondition_failed", "If-Match must contain the current domain ETag")
		}
		if current.Status != "verified" {
			return apierr.New("conflict", "only verified domains can change SSO enforcement")
		}
		if forceSSO {
			connection, err := q.LockSSOConnectionInSpace(ctx, db.LockSSOConnectionInSpaceParams{ID: current.ConnectionID.String, SpaceID: spaceID})
			if errors.Is(err, pgx.ErrNoRows) || err == nil && connection.Status != "active" {
				return apierr.New("conflict", "force_sso requires an active SSO connection in this Space")
			}
			if err != nil {
				return err
			}
		}
		if err := q.LockForcedSSODomainForChange(ctx, db.LockForcedSSODomainForChangeParams{Domain: current.Domain}); err != nil {
			return err
		}
		row, err := q.UpdateSSODomainEnforcement(ctx, db.UpdateSSODomainEnforcementParams{ID: domainID, SpaceID: spaceID, ForceSso: forceSSO})
		if err != nil {
			return err
		}
		out = domainFromListRow(db.ListSSODomainsRow(row))
		return audit.WriteSecurityEvent(ctx, q, audit.SecurityEvent{
			ActorType: "member", ActorID: actorMemberID, MemberID: actorMemberID,
			Action: "sso.domain.policy.update", Outcome: "success", Permission: "auth.connections:manage",
			Resource: audit.Resource{Type: "sso_domain", ID: domainID, SpaceID: spaceID},
			Metadata: map[string]string{
				"domain": current.Domain, "previous_force_sso": strconv.FormatBool(current.ForceSso), "force_sso": request["force_sso"],
			},
		})
	})
	if err != nil {
		return Domain{}, normalizeConnectionError(err)
	}
	return out, nil
}
