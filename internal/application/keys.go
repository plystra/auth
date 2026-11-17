package application

import (
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/plystra/auth/internal/apierr"
	"github.com/plystra/auth/internal/audit"
	"github.com/plystra/auth/internal/authorization"
	"github.com/plystra/auth/internal/authz/engine"
	"github.com/plystra/auth/internal/db"
	"github.com/plystra/auth/internal/ids"
	"github.com/plystra/auth/internal/secret"
	"github.com/plystra/auth/internal/stepup"
)

type ManagedKey struct {
	ID                    string           `json:"id"`
	ApplicationID         string           `json:"application_id"`
	Name                  string           `json:"name"`
	Prefix                string           `json:"prefix"`
	Grants                []string         `json:"grants"`
	RestrictTo            []KeyRestriction `json:"restrict_to"`
	AllowedIPCIDRs        []string         `json:"allowed_ip_cidrs"`
	ExpiresAt             time.Time        `json:"expires_at"`
	LastUsedAt            *time.Time       `json:"last_used_at,omitempty"`
	RevokedAt             *time.Time       `json:"revoked_at,omitempty"`
	CreatedAt             time.Time        `json:"created_at"`
	AllowSubjectAssertion bool             `json:"allow_subject_assertion"`
}

type CreateManagedKeyInput struct {
	Name                  string
	Grants                []string
	RestrictTo            []KeyRestriction
	AllowedIPCIDRs        []string
	ExpiresAt             time.Time
	AllowSubjectAssertion bool
}

func (s *Service) ApplicationSpace(ctx context.Context, applicationID string) (string, error) {
	if s == nil || s.Store == nil {
		return "", apierr.New("UNAVAILABLE", "application key management is unavailable")
	}
	row, err := s.Store.Queries().GetApplicationForKeyManagement(ctx, db.GetApplicationForKeyManagementParams{ApplicationID: applicationID})
	if errors.Is(err, pgx.ErrNoRows) {
		return "", apierr.New("NOT_FOUND", "application was not found")
	}
	if err != nil {
		return "", err
	}
	return row.SpaceID, nil
}

func (s *Service) CreateManagedKey(ctx context.Context, actorMemberID, applicationID string, in CreateManagedKeyInput) (ManagedKey, secret.String, error) {
	if s == nil || s.Store == nil || s.Authorization == nil || len(s.HMACKeys) == 0 {
		return ManagedKey{}, "", apierr.New("UNAVAILABLE", "application key management is unavailable")
	}
	in.Name = strings.TrimSpace(in.Name)
	if in.Name == "" || utf8.RuneCountInString(in.Name) > 120 {
		return ManagedKey{}, "", apierr.New("VALIDATION_FAILED", "key name must contain 1 to 120 characters")
	}
	now := time.Now()
	if !in.ExpiresAt.After(now) || in.ExpiresAt.After(now.Add(365*24*time.Hour)) {
		return ManagedKey{}, "", apierr.New("VALIDATION_FAILED", "API key expiry must be in the future and within one year")
	}
	if len(in.Grants) == 0 || len(in.Grants) > 100 || len(in.RestrictTo) > 50 {
		return ManagedKey{}, "", apierr.New("VALIDATION_FAILED", "API key grants or installation limits are invalid")
	}
	if len(in.AllowedIPCIDRs) > 50 {
		return ManagedKey{}, "", apierr.New("VALIDATION_FAILED", "API key has too many source IP ranges")
	}
	allowedIPCIDRs := make([]string, 0, len(in.AllowedIPCIDRs))
	seenIPCIDRs := map[string]bool{}
	for _, value := range in.AllowedIPCIDRs {
		network, err := netip.ParsePrefix(value)
		if err != nil || !network.IsValid() {
			return ManagedKey{}, "", apierr.New("VALIDATION_FAILED", "API key source IP range must be a CIDR prefix")
		}
		canonical := network.Masked().String()
		if seenIPCIDRs[canonical] {
			return ManagedKey{}, "", apierr.New("VALIDATION_FAILED", "API key source IP ranges contain a duplicate")
		}
		seenIPCIDRs[canonical] = true
		allowedIPCIDRs = append(allowedIPCIDRs, canonical)
	}
	slices.Sort(allowedIPCIDRs)
	grants := slices.Clone(in.Grants)
	if in.RestrictTo == nil {
		in.RestrictTo = []KeyRestriction{}
	}
	slices.Sort(grants)
	for i, grant := range grants {
		if grant == "" || strings.TrimSpace(grant) != grant || (i > 0 && grant == grants[i-1]) {
			return ManagedKey{}, "", apierr.New("VALIDATION_FAILED", "API key grants contain an invalid or duplicate permission")
		}
	}
	keyID := string(ids.New[ids.APIKeyID]("key"))
	raw, prefix, hash, err := GenerateSecret(keyID, s.HMACKeys[0])
	if err != nil {
		return ManagedKey{}, "", err
	}
	var out ManagedKey
	err = s.Store.InTx(ctx, func(q *db.Queries) error {
		application, err := s.managedApplicationTx(ctx, q, actorMemberID, applicationID)
		if err != nil {
			return err
		}
		if application.Status != "active" {
			return apierr.New("CONFLICT", "application is not active")
		}
		var manifest []string
		if err := json.Unmarshal(application.ManifestPermissions, &manifest); err != nil {
			return err
		}
		for _, grant := range grants {
			if !slices.Contains(manifest, grant) {
				return apierr.New("GRANT_EXCEEDS_OWNER", "API key grant is outside the application manifest")
			}
			permission, err := q.GetPermissionByKey(ctx, db.GetPermissionByKeyParams{Key: grant})
			if errors.Is(err, pgx.ErrNoRows) || (err == nil && permission.Status == "disabled") {
				return apierr.New("PERMISSION_DISABLED", "API key grant is disabled")
			}
			if err != nil {
				return err
			}
		}
		seen := map[string]bool{}
		for _, restriction := range in.RestrictTo {
			if restriction.SpaceID == "" || seen[restriction.SpaceID] {
				return apierr.New("VALIDATION_FAILED", "API key installation limits contain an invalid or duplicate Space")
			}
			seen[restriction.SpaceID] = true
			installationScope, err := q.GetActiveInstallationForKeyRestriction(ctx, db.GetActiveInstallationForKeyRestrictionParams{
				ApplicationID: applicationID, SpaceID: restriction.SpaceID,
			})
			if errors.Is(err, pgx.ErrNoRows) {
				return apierr.New("VALIDATION_FAILED", "API key limit must name an active installation")
			}
			if err != nil {
				return err
			}
			if restriction.IncludeDescendants && installationScope != "space_tree" {
				return apierr.New("VALIDATION_FAILED", "descendant limit requires a space_tree installation")
			}
		}
		if _, required := stepup.RequirementFromContext(ctx); required {
			if s.StepUp == nil {
				return apierr.New("UNAVAILABLE", "step-up authentication is unavailable")
			}
			if err := s.StepUp.ConsumeStepUpTx(ctx, q); err != nil {
				return err
			}
		}
		grantsJSON, err := json.Marshal(grants)
		if err != nil {
			return err
		}
		restrictJSON, err := json.Marshal(in.RestrictTo)
		if err != nil {
			return err
		}
		allowedIPCIDRsJSON, err := json.Marshal(allowedIPCIDRs)
		if err != nil {
			return err
		}
		row, err := q.CreateAPIKey(ctx, db.CreateAPIKeyParams{
			ID: keyID, ApplicationID: applicationID, Name: in.Name, Prefix: prefix,
			SecretHash: hash, Scopes: grantsJSON, RestrictTo: restrictJSON, AllowedIpCidrs: allowedIPCIDRsJSON,
			ExpiresAt: pgtype.Timestamptz{Time: in.ExpiresAt, Valid: true}, AllowSubjectAssertion: in.AllowSubjectAssertion,
		})
		if err != nil {
			return err
		}
		if err := audit.Write(ctx, q, "member", actorMemberID, "application.key.create", keyID, "success"); err != nil {
			return err
		}
		out = managedKey(row.ID, row.ApplicationID, row.Name, row.Prefix, row.ExpiresAt,
			row.LastUsedAt, row.RevokedAt, row.CreatedAt, row.AllowSubjectAssertion, grants, in.RestrictTo, allowedIPCIDRs)
		return nil
	})
	if err != nil {
		return ManagedKey{}, "", err
	}
	return out, secret.New(raw), nil
}

func (s *Service) ListManagedKeys(ctx context.Context, actorMemberID, applicationID string) ([]ManagedKey, error) {
	if s == nil || s.Store == nil || s.Authorization == nil {
		return nil, apierr.New("UNAVAILABLE", "application key management is unavailable")
	}
	var out []ManagedKey
	err := s.Store.InTx(ctx, func(q *db.Queries) error {
		if _, err := s.managedApplicationTx(ctx, q, actorMemberID, applicationID); err != nil {
			return err
		}
		rows, err := q.ListManagedAPIKeys(ctx, db.ListManagedAPIKeysParams{ApplicationID: applicationID})
		if err != nil {
			return err
		}
		out = make([]ManagedKey, 0, len(rows))
		for _, row := range rows {
			var grants []string
			var restrictions []KeyRestriction
			var allowedIPCIDRs []string
			if err := json.Unmarshal(row.Scopes, &grants); err != nil {
				return err
			}
			if err := json.Unmarshal(row.RestrictTo, &restrictions); err != nil {
				return err
			}
			if err := json.Unmarshal(row.AllowedIpCidrs, &allowedIPCIDRs); err != nil {
				return err
			}
			out = append(out, managedKey(row.ID, row.ApplicationID, row.Name, row.Prefix, row.ExpiresAt,
				row.LastUsedAt, row.RevokedAt, row.CreatedAt, row.AllowSubjectAssertion, grants, restrictions, allowedIPCIDRs))
		}
		return nil
	})
	return out, err
}

func (s *Service) RevokeManagedKey(ctx context.Context, actorMemberID, applicationID, keyID string) (ManagedKey, error) {
	if s == nil || s.Store == nil || s.Authorization == nil {
		return ManagedKey{}, apierr.New("UNAVAILABLE", "application key management is unavailable")
	}
	var out ManagedKey
	err := s.Store.InTx(ctx, func(q *db.Queries) error {
		if _, err := s.managedApplicationTx(ctx, q, actorMemberID, applicationID); err != nil {
			return err
		}
		row, err := q.RevokeManagedAPIKey(ctx, db.RevokeManagedAPIKeyParams{ApplicationID: applicationID, KeyID: keyID})
		if errors.Is(err, pgx.ErrNoRows) {
			return apierr.New("NOT_FOUND", "API key was not found")
		}
		if err != nil {
			return err
		}
		if err := audit.Write(ctx, q, "member", actorMemberID, "application.key.revoke", keyID, "success"); err != nil {
			return err
		}
		var grants []string
		var restrictions []KeyRestriction
		var allowedIPCIDRs []string
		if err := json.Unmarshal(row.Scopes, &grants); err != nil {
			return err
		}
		if err := json.Unmarshal(row.RestrictTo, &restrictions); err != nil {
			return err
		}
		if err := json.Unmarshal(row.AllowedIpCidrs, &allowedIPCIDRs); err != nil {
			return err
		}
		out = managedKey(row.ID, row.ApplicationID, row.Name, row.Prefix, row.ExpiresAt,
			row.LastUsedAt, row.RevokedAt, row.CreatedAt, row.AllowSubjectAssertion, grants, restrictions, allowedIPCIDRs)
		return nil
	})
	return out, err
}

func (s *Service) UpdateManagedKeyGrants(ctx context.Context, actorMemberID, applicationID, keyID string, grants []string) (ManagedKey, error) {
	if s == nil || s.Store == nil || s.Authorization == nil {
		return ManagedKey{}, apierr.New("UNAVAILABLE", "application key management is unavailable")
	}
	if grants == nil || len(grants) > 100 {
		return ManagedKey{}, apierr.New("VALIDATION_FAILED", "API key grants must be an array of up to 100 permissions")
	}
	grants = slices.Clone(grants)
	slices.Sort(grants)
	for i, grant := range grants {
		if grant == "" || strings.TrimSpace(grant) != grant || (i > 0 && grant == grants[i-1]) {
			return ManagedKey{}, apierr.New("VALIDATION_FAILED", "API key grants contain an invalid or duplicate permission")
		}
	}
	var out ManagedKey
	err := s.Store.InTx(ctx, func(q *db.Queries) error {
		// Manifest reviews, key rotation and revocation use this same lock order.
		app, err := s.managedApplicationTx(ctx, q, actorMemberID, applicationID)
		if err != nil {
			return err
		}
		if app.Status != "active" {
			return apierr.New("CONFLICT", "application is not active")
		}
		previous, err := q.LockManagedAPIKey(ctx, db.LockManagedAPIKeyParams{ApplicationID: applicationID, KeyID: keyID})
		if errors.Is(err, pgx.ErrNoRows) {
			return apierr.New("NOT_FOUND", "API key was not found")
		}
		if err != nil {
			return err
		}
		if previous.RevokedAt.Valid || !previous.ExpiresAt.Valid || !previous.ExpiresAt.Time.After(time.Now()) {
			return apierr.New("CONFLICT", "API key is revoked or expired")
		}
		var manifest []string
		if err := json.Unmarshal(app.ManifestPermissions, &manifest); err != nil {
			return err
		}
		for _, grant := range grants {
			if !slices.Contains(manifest, grant) {
				return apierr.New("GRANT_EXCEEDS_OWNER", "API key grant is outside the application manifest")
			}
			permission, err := q.GetPermissionByKey(ctx, db.GetPermissionByKeyParams{Key: grant})
			if errors.Is(err, pgx.ErrNoRows) || (err == nil && permission.Status == "disabled") {
				return apierr.New("PERMISSION_DISABLED", "API key grant is disabled")
			}
			if err != nil {
				return err
			}
		}
		scopes, err := json.Marshal(grants)
		if err != nil {
			return err
		}
		changed, err := q.UpdateManagedAPIKeyGrants(ctx, db.UpdateManagedAPIKeyGrantsParams{
			ApplicationID: applicationID, KeyID: keyID, Scopes: scopes,
		})
		if err != nil {
			return err
		}
		if changed != 1 {
			return apierr.New("CONFLICT", "API key is revoked or expired")
		}
		if err := audit.WriteSecurityEvent(ctx, q, audit.SecurityEvent{
			ActorType: "member", ActorID: actorMemberID, MemberID: actorMemberID,
			ApplicationID: applicationID, Action: "application.key.grants.replace", Outcome: "success",
			Permission: "auth.applications:manage", Resource: audit.Resource{Type: "api_key", ID: keyID, SpaceID: app.SpaceID},
			Metadata: map[string]string{"previous_grants": string(previous.Scopes), "grants": string(scopes)},
		}); err != nil {
			return err
		}
		var restrictions []KeyRestriction
		var allowedIPCIDRs []string
		if err := json.Unmarshal(previous.RestrictTo, &restrictions); err != nil {
			return err
		}
		if err := json.Unmarshal(previous.AllowedIpCidrs, &allowedIPCIDRs); err != nil {
			return err
		}
		out = managedKey(previous.ID, previous.ApplicationID, previous.Name, previous.Prefix, previous.ExpiresAt,
			previous.LastUsedAt, previous.RevokedAt, previous.CreatedAt, previous.AllowSubjectAssertion, grants, restrictions, allowedIPCIDRs)
		return nil
	})
	return out, err
}

func (s *Service) RotateManagedKey(ctx context.Context, actorMemberID, applicationID, keyID string) (ManagedKey, secret.String, error) {
	if s == nil || s.Store == nil || s.Authorization == nil || len(s.HMACKeys) == 0 {
		return ManagedKey{}, "", apierr.New("UNAVAILABLE", "application key management is unavailable")
	}
	raw, _, hash, err := GenerateSecret(keyID, s.HMACKeys[0])
	if err != nil {
		return ManagedKey{}, "", err
	}
	var out ManagedKey
	err = s.Store.InTx(ctx, func(q *db.Queries) error {
		application, err := s.managedApplicationTx(ctx, q, actorMemberID, applicationID)
		if err != nil {
			return err
		}
		if application.Status != "active" {
			return apierr.New("CONFLICT", "application is not active")
		}
		previous, err := q.LockManagedAPIKey(ctx, db.LockManagedAPIKeyParams{
			ApplicationID: applicationID, KeyID: keyID,
		})
		if errors.Is(err, pgx.ErrNoRows) {
			return apierr.New("NOT_FOUND", "API key was not found")
		}
		if err != nil {
			return err
		}
		if previous.RevokedAt.Valid || !previous.ExpiresAt.Valid || !previous.ExpiresAt.Time.After(time.Now()) {
			return apierr.New("CONFLICT", "API key is revoked or expired")
		}
		if previous.HashScheme != "hmac_sha256" {
			return apierr.New("UNAVAILABLE", "API key hash upgrade is required before rotation")
		}
		if _, required := stepup.RequirementFromContext(ctx); required {
			if s.StepUp == nil {
				return apierr.New("UNAVAILABLE", "step-up authentication is unavailable")
			}
			if err := s.StepUp.ConsumeStepUpTx(ctx, q); err != nil {
				return err
			}
		}
		if err := q.PreserveAPIKeySecretForGrace(ctx, db.PreserveAPIKeySecretForGraceParams{
			KeyID: keyID, SecretHash: previous.SecretHash,
		}); err != nil {
			return err
		}
		row, err := q.ReplaceManagedAPIKeySecret(ctx, db.ReplaceManagedAPIKeySecretParams{
			ApplicationID: applicationID, KeyID: keyID, SecretHash: hash,
		})
		if err != nil {
			return err
		}
		if err := audit.Write(ctx, q, "member", actorMemberID, "application.key.rotate", keyID, "success"); err != nil {
			return err
		}
		var grants []string
		var restrictions []KeyRestriction
		var allowedIPCIDRs []string
		if err := json.Unmarshal(row.Scopes, &grants); err != nil {
			return err
		}
		if err := json.Unmarshal(row.RestrictTo, &restrictions); err != nil {
			return err
		}
		if err := json.Unmarshal(row.AllowedIpCidrs, &allowedIPCIDRs); err != nil {
			return err
		}
		out = managedKey(row.ID, row.ApplicationID, row.Name, row.Prefix, row.ExpiresAt,
			row.LastUsedAt, row.RevokedAt, row.CreatedAt, row.AllowSubjectAssertion, grants, restrictions, allowedIPCIDRs)
		return nil
	})
	if err != nil {
		return ManagedKey{}, "", err
	}
	return out, secret.New(raw), nil
}

func (s *Service) managedApplicationTx(ctx context.Context, q *db.Queries, actorMemberID, applicationID string) (db.LockApplicationForUpdateRow, error) {
	row, err := q.LockApplicationForUpdate(ctx, db.LockApplicationForUpdateParams{ApplicationID: applicationID})
	if errors.Is(err, pgx.ErrNoRows) {
		return db.LockApplicationForUpdateRow{}, apierr.New("NOT_FOUND", "application was not found")
	}
	if err != nil {
		return db.LockApplicationForUpdateRow{}, err
	}
	decision, err := s.Authorization.CheckTx(ctx, q, authorization.CheckRequest{
		MemberID: actorMemberID, Permission: "auth.applications:manage", ResourceSpace: row.SpaceID,
	})
	if err != nil {
		return db.LockApplicationForUpdateRow{}, err
	}
	if decision.Effect != engine.Allow {
		return db.LockApplicationForUpdateRow{}, &apierr.Error{Code: decision.Code, Message: "The authorization engine denied this operation."}
	}
	return row, nil
}

func managedKey(id, applicationID, name, prefix string, expiresAt, lastUsedAt, revokedAt, createdAt pgtype.Timestamptz,
	allowSubjectAssertion bool, grants []string, restrictions []KeyRestriction, allowedIPCIDRs []string) ManagedKey {
	out := ManagedKey{ID: id, ApplicationID: applicationID, Name: name, Prefix: prefix, Grants: grants,
		RestrictTo: restrictions, AllowedIPCIDRs: allowedIPCIDRs, ExpiresAt: expiresAt.Time, CreatedAt: createdAt.Time,
		AllowSubjectAssertion: allowSubjectAssertion}
	if lastUsedAt.Valid {
		out.LastUsedAt = &lastUsedAt.Time
	}
	if revokedAt.Valid {
		out.RevokedAt = &revokedAt.Time
	}
	return out
}
