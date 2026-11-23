package application

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/plystra/auth/internal/apierr"
	"github.com/plystra/auth/internal/audit"
	"github.com/plystra/auth/internal/authorization"
	"github.com/plystra/auth/internal/authz/engine"
	"github.com/plystra/auth/internal/db"
	"github.com/plystra/auth/internal/secret"
	"github.com/plystra/auth/internal/stepup"
)

const RotateOAuthSecretOperation = "applications.oauth_client_secret.rotate"

func validOAuthHMACKeys(keys [][]byte) bool {
	if len(keys) == 0 {
		return false
	}
	for _, key := range keys {
		if len(key) < 32 {
			return false
		}
	}
	return true
}

func (s *Service) newPublisherOAuthSecret() (secret.String, []byte, error) {
	if !validOAuthHMACKeys(s.HMACKeys) {
		return "", nil, apierr.New("UNAVAILABLE", "OAuth credential issuance is unavailable")
	}
	var entropy [32]byte
	if _, err := rand.Read(entropy[:]); err != nil {
		return "", nil, err
	}
	raw := "ply_ocs_" + base64.RawURLEncoding.EncodeToString(entropy[:])
	return secret.New(raw), HMACClientSecretHash(s.HMACKeys[0], raw), nil
}

func (in RegisterInput) GovernanceRequest() map[string]any {
	return map[string]any{"operation": "applications.register", "space_id": in.SpaceID, "name": in.Name, "redirect_uris": in.RedirectURIs,
		"manifest_permissions": in.ManifestPermissions, "visibility": in.Visibility, "human_oidc_enabled": in.HumanOIDCEnabled, "token_endpoint_auth_method": in.TokenEndpointAuthMethod}
}

func OAuthRotationGovernanceRequest(space, app string, grace int32) map[string]any {
	return map[string]any{"operation": RotateOAuthSecretOperation, "space_id": space, "application_id": app, "grace_period_seconds": grace}
}

type OAuthSecretRotation struct {
	ApplicationID           string        `json:"application_id"`
	ClientID                string        `json:"client_id"`
	ClientSecret            secret.String `json:"client_secret"`
	PreviousSecretExpiresAt *time.Time    `json:"previous_secret_expires_at"`
}

func (s *Service) RotateOAuthSecret(ctx context.Context, memberID, appID string, grace int32) (OAuthSecretRotation, error) {
	if s == nil || s.Store == nil || s.Authorization == nil {
		return OAuthSecretRotation{}, apierr.New("UNAVAILABLE", "application management is unavailable")
	}
	if grace < 0 || grace > 86400 {
		return OAuthSecretRotation{}, apierr.New("VALIDATION_FAILED", "grace period must be between 0 and 86400 seconds")
	}
	var result OAuthSecretRotation
	err := s.Store.InTx(ctx, func(q *db.Queries) error {
		app, err := q.LockApplicationForUpdate(ctx, db.LockApplicationForUpdateParams{ApplicationID: appID})
		if errors.Is(err, pgx.ErrNoRows) {
			return apierr.New("NOT_FOUND", "application was not found")
		}
		if err != nil {
			return err
		}
		digest, err := stepup.DigestValue(OAuthRotationGovernanceRequest(app.SpaceID, appID, grace))
		if err != nil {
			return err
		}
		bound := authorization.BindGovernanceApproval(ctx, RotateOAuthSecretOperation, app.SpaceID, digest)
		decision, err := s.Authorization.CheckMutationTx(bound, q, authorization.CheckRequest{MemberID: memberID, Permission: "auth.applications:manage", ResourceSpace: app.SpaceID})
		if err != nil {
			return err
		}
		if decision.Effect != engine.Allow {
			return apierr.New(decision.Code, "The authorization engine denied this operation.")
		}
		if app.TokenEndpointAuthMethod != "client_secret_basic" || app.Status != "active" {
			return apierr.New("CONFLICT", "application does not have a rotatable OAuth credential")
		}
		if _, required := stepup.RequirementFromContext(ctx); required {
			if s.StepUp == nil {
				return apierr.New("UNAVAILABLE", "step-up authentication is unavailable")
			}
			if err := s.StepUp.ConsumeStepUpTx(ctx, q); err != nil {
				return err
			}
		}
		raw, hash, err := s.newPublisherOAuthSecret()
		if err != nil {
			return err
		}
		deadline, err := q.RotatePublisherOAuthSecret(ctx, db.RotatePublisherOAuthSecretParams{ApplicationID: appID, GraceSeconds: grace, NewHash: hash})
		if errors.Is(err, pgx.ErrNoRows) {
			return apierr.New("CONFLICT", "application does not have a rotatable OAuth credential")
		}
		if err != nil {
			return err
		}
		metadata := map[string]string{}
		if deadline.Valid {
			metadata["previous_secret_expires_at"] = deadline.Time.UTC().Format(time.RFC3339Nano)
			result.PreviousSecretExpiresAt = &deadline.Time
		}
		if err := audit.WriteSecurityEvent(ctx, q, audit.SecurityEvent{ActorType: "member", ActorID: memberID, MemberID: memberID, ApplicationID: appID,
			Action: "application.oauth_client_secret.rotate", Outcome: "success", Permission: "auth.applications:manage", Metadata: metadata,
			Resource: audit.Resource{Type: "application", ID: appID, SpaceID: app.SpaceID}}); err != nil {
			return err
		}
		result.ApplicationID, result.ClientID, result.ClientSecret = appID, app.ClientID, raw
		return nil
	})
	if err != nil {
		return OAuthSecretRotation{}, err
	}
	return result, nil
}
