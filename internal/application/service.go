package application

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net"
	"net/netip"
	"net/url"
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
	"github.com/plystra/auth/internal/requestinfo"
	"github.com/plystra/auth/internal/stepup"
	"github.com/plystra/auth/internal/store"
)

type Service struct {
	Store         *store.Store
	Authorization *authorization.Service
	StepUp        stepup.Consumer
	HMACKeys      [][]byte
}

type PublishedApplication struct {
	ID                         string    `json:"id"`
	SpaceID                    string    `json:"space_id"`
	Name                       string    `json:"name"`
	ClientID                   string    `json:"client_id"`
	RedirectURIs               []string  `json:"redirect_uris"`
	ManifestPermissions        []string  `json:"manifest_permissions"`
	PendingManifestPermissions []string  `json:"pending_manifest_permissions,omitempty"`
	Visibility                 string    `json:"visibility"`
	ReviewStatus               string    `json:"review_status"`
	Status                     string    `json:"status"`
	CreatedAt                  time.Time `json:"created_at"`
}

type RegisterInput struct {
	SpaceID             string
	Name                string
	RedirectURIs        []string
	ManifestPermissions []string
	Visibility          string
}

// Register records a publisher-owned application. Registration does not
// grant the application authority; installations and their positive delta are
// evaluated separately.
func (s *Service) Register(ctx context.Context, actorMemberID string, in RegisterInput) (PublishedApplication, error) {
	if s == nil || s.Store == nil || s.Authorization == nil {
		return PublishedApplication{}, apierr.New("UNAVAILABLE", "application registration is unavailable")
	}
	in.Name = strings.TrimSpace(in.Name)
	if in.Visibility == "" {
		in.Visibility = "private"
	}
	if in.Visibility != "private" && in.Visibility != "public" {
		return PublishedApplication{}, apierr.New("VALIDATION_FAILED", "application visibility is invalid")
	}
	if in.Name == "" || utf8.RuneCountInString(in.Name) > 120 {
		return PublishedApplication{}, apierr.New("VALIDATION_FAILED", "application name must contain 1 to 120 characters")
	}
	if len(in.ManifestPermissions) == 0 || len(in.ManifestPermissions) > 100 {
		return PublishedApplication{}, apierr.New("VALIDATION_FAILED", "application manifest must contain 1 to 100 permissions")
	}
	if len(in.RedirectURIs) > 20 {
		return PublishedApplication{}, apierr.New("VALIDATION_FAILED", "application has too many redirect URIs")
	}
	permissions := append([]string(nil), in.ManifestPermissions...)
	slices.Sort(permissions)
	for index, key := range permissions {
		if strings.TrimSpace(key) != key || key == "" || (index > 0 && key == permissions[index-1]) {
			return PublishedApplication{}, apierr.New("VALIDATION_FAILED", "application manifest contains an invalid or duplicate permission")
		}
	}
	redirects := append([]string(nil), in.RedirectURIs...)
	for _, raw := range redirects {
		parsed, err := url.Parse(raw)
		if err != nil || parsed.Host == "" || parsed.Fragment != "" || parsed.User != nil ||
			(parsed.Scheme != "https" && (parsed.Scheme != "http" || !isLoopbackHost(parsed.Hostname()))) {
			return PublishedApplication{}, apierr.New("VALIDATION_FAILED", "redirect URI must use HTTPS or HTTP on a loopback host")
		}
	}
	manifest, err := json.Marshal(permissions)
	if err != nil {
		return PublishedApplication{}, err
	}
	redirectJSON, err := json.Marshal(redirects)
	if err != nil {
		return PublishedApplication{}, err
	}
	id := string(ids.New[ids.ApplicationID]("app"))
	effectiveManifest := manifest
	var pendingManifest []byte
	reviewStatus := "not_required"
	if in.Visibility == "public" {
		effectiveManifest = []byte("[]")
		pendingManifest = manifest
		reviewStatus = "pending"
	}
	var out PublishedApplication
	err = s.Store.InTx(ctx, func(q *db.Queries) error {
		decision, err := s.Authorization.CheckTx(ctx, q, authorization.CheckRequest{
			MemberID: actorMemberID, Permission: "auth.applications:manage", ResourceSpace: in.SpaceID,
		})
		if err != nil {
			return err
		}
		if decision.Effect != engine.Allow {
			return &apierr.Error{Code: decision.Code, Message: "The authorization engine denied this operation."}
		}
		for _, key := range permissions {
			permission, err := q.GetPermissionByKey(ctx, db.GetPermissionByKeyParams{Key: key})
			if errors.Is(err, pgx.ErrNoRows) {
				return apierr.New("VALIDATION_FAILED", "application manifest contains an unknown permission")
			}
			if err != nil {
				return err
			}
			if permission.Status == "disabled" {
				return apierr.New("PERMISSION_DISABLED", "application manifest contains a disabled permission")
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
		row, err := q.CreateApplication(ctx, db.CreateApplicationParams{
			ID: id, SpaceID: in.SpaceID, Name: in.Name, ClientID: id,
			RedirectUris: redirectJSON, AllowedScopes: effectiveManifest,
			ManifestPermissions: effectiveManifest, PendingManifestPermissions: pendingManifest,
			Visibility: in.Visibility, ReviewStatus: reviewStatus,
		})
		if err != nil {
			return err
		}
		if err := audit.Write(ctx, q, "member", actorMemberID, "application.register", row.ID, "success"); err != nil {
			return err
		}
		out = PublishedApplication{ID: row.ID, SpaceID: row.SpaceID, Name: row.Name, ClientID: row.ClientID,
			RedirectURIs: redirects, Visibility: row.Visibility, ReviewStatus: row.ReviewStatus,
			Status: row.Status, CreatedAt: row.CreatedAt.Time}
		if in.Visibility == "public" {
			out.ManifestPermissions = []string{}
			out.PendingManifestPermissions = permissions
		} else {
			out.ManifestPermissions = permissions
		}
		return nil
	})
	return out, err
}

func (s *Service) ListPublished(ctx context.Context, spaceID string) ([]PublishedApplication, error) {
	if s == nil || s.Store == nil {
		return nil, apierr.New("UNAVAILABLE", "application listing is unavailable")
	}
	rows, err := s.Store.Queries().ListPublishedApplications(ctx, db.ListPublishedApplicationsParams{SpaceID: spaceID})
	if err != nil {
		return nil, err
	}
	applications := make([]PublishedApplication, 0, len(rows))
	for _, row := range rows {
		var redirects, permissions []string
		if err := json.Unmarshal(row.RedirectUris, &redirects); err != nil {
			return nil, err
		}
		if err := json.Unmarshal(row.ManifestPermissions, &permissions); err != nil {
			return nil, err
		}
		var pending []string
		if len(row.PendingManifestPermissions) > 0 {
			if err := json.Unmarshal(row.PendingManifestPermissions, &pending); err != nil {
				return nil, err
			}
		}
		applications = append(applications, PublishedApplication{ID: row.ID, SpaceID: row.SpaceID,
			Name: row.Name, ClientID: row.ClientID, RedirectURIs: redirects,
			ManifestPermissions: permissions, PendingManifestPermissions: pending,
			Visibility: row.Visibility, ReviewStatus: row.ReviewStatus, Status: row.Status,
			CreatedAt: row.CreatedAt.Time})
	}
	return applications, nil
}

func isLoopbackHost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

type OAuthClient struct {
	ID               string
	SpaceID          string
	Name             string
	ClientID         string
	RedirectURIs     []string
	AllowedScopes    []string
	ClientSecretHash []byte
}

type AuthorizationCode struct {
	ID                  string
	ApplicationID       string
	UserID              string
	MemberID            string
	RedirectURI         string
	CodeChallenge       string
	CodeChallengeMethod string
	Scope               string
	Nonce               string
	Resource            string
	ExpiresAt           time.Time
}

type CreateAuthorizationCodeInput struct {
	ID                  string
	ApplicationID       string
	UserID              string
	MemberID            string
	RedirectURI         string
	CodeHash            []byte
	CodeChallenge       string
	CodeChallengeMethod string
	Scope               string
	Nonce               string
	Resource            string
	ExpiresAt           time.Time
}
type Key struct {
	ID                    string
	ApplicationID         string
	ClientID              string
	SpaceID               string
	Name                  string
	Prefix                string
	ExpiresAt             time.Time
	CreatedAt             time.Time
	Scopes                []string
	RestrictTo            []KeyRestriction
	AllowedIPCIDRs        []string
	AllowSubjectAssertion bool
}

type KeyRestriction struct {
	SpaceID            string `json:"space_id"`
	IncludeDescendants bool   `json:"include_descendants"`
}

func (s *Service) AuthenticateKey(ctx context.Context, raw string) (Key, error) {
	if s == nil || s.Store == nil || len(s.HMACKeys) == 0 {
		return Key{}, apierr.New("UNAVAILABLE", "application API key authentication is unavailable")
	}
	var key Key
	err := s.Store.InTx(ctx, func(q *db.Queries) error {
		var err error
		key, err = s.AuthenticateKeyTx(ctx, q, raw)
		return err
	})
	return key, err
}

// AuthenticateKeyTx lets a credential check participate in the caller's write transaction.
func (s *Service) AuthenticateKeyTx(ctx context.Context, q *db.Queries, raw string) (Key, error) {
	if s == nil || len(s.HMACKeys) == 0 {
		return Key{}, apierr.New("UNAVAILABLE", "application API key authentication is unavailable")
	}
	parts := strings.SplitN(raw, ".", 2)
	if len(parts) != 2 || !strings.HasPrefix(parts[0], "ply_sk_") {
		return Key{}, apierr.New("unauthorized", "application API key is required")
	}
	row, e := q.GetAPIKeyByPrefix(ctx, db.GetAPIKeyByPrefixParams{Prefix: parts[0]})
	if e != nil {
		if errors.Is(e, pgx.ErrNoRows) {
			return Key{}, apierr.New("unauthorized", "application API key is invalid")
		}
		return Key{}, e
	}
	valid := false
	if row.HashScheme == "hmac_sha256" {
		for _, key := range s.HMACKeys {
			if hmac.Equal(apiKeyHash(key, parts[1]), row.SecretHash) {
				valid = true
			}
		}
	}
	if !valid && row.HashScheme == "hmac_sha256" {
		for _, key := range s.HMACKeys {
			valid, e = q.ValidGraceAPIKeySecret(ctx, db.ValidGraceAPIKeySecretParams{
				KeyID: row.ID, SecretHash: apiKeyHash(key, parts[1]),
			})
			if e != nil {
				return Key{}, e
			}
			if valid {
				break
			}
		}
	}
	if !valid {
		return Key{}, apierr.New("unauthorized", "application API key is invalid")
	}
	if row.RevokedAt.Valid || !row.ExpiresAt.Valid || !row.ExpiresAt.Time.After(time.Now()) || row.ApplicationStatus != "active" ||
		(row.ApplicationVisibility == "public" && row.ApplicationReviewStatus != "approved") {
		return Key{}, apierr.New("unauthorized", "application API key is revoked or expired")
	}
	var allowedIPCIDRs []string
	if err := json.Unmarshal(row.AllowedIpCidrs, &allowedIPCIDRs); err != nil {
		return Key{}, apierr.New("UNAVAILABLE", "API key source IP policy is invalid")
	}
	if len(allowedIPCIDRs) > 0 {
		client, ok := netip.AddrFromSlice(requestinfo.Get(ctx).IP)
		if !ok {
			return Key{}, apierr.New("unauthorized", "application API key is invalid")
		}
		allowed := false
		for _, value := range allowedIPCIDRs {
			network, err := netip.ParsePrefix(value)
			if err != nil {
				return Key{}, apierr.New("UNAVAILABLE", "API key source IP policy is invalid")
			}
			if network.Contains(client) || network.Contains(client.Unmap()) {
				allowed = true
			}
		}
		if !allowed {
			return Key{}, apierr.New("unauthorized", "application API key is invalid")
		}
	}
	if e = q.TouchAPIKey(ctx, db.TouchAPIKeyParams{ID: row.ID}); e != nil {
		return Key{}, e
	}
	var scopes []string
	if err := json.Unmarshal(row.Scopes, &scopes); err != nil {
		return Key{}, apierr.New("UNAVAILABLE", "API key permissions are invalid")
	}
	var restrictions []KeyRestriction
	if err := json.Unmarshal(row.RestrictTo, &restrictions); err != nil {
		return Key{}, apierr.New("UNAVAILABLE", "API key installation scope is invalid")
	}
	for _, restriction := range restrictions {
		if restriction.SpaceID == "" {
			return Key{}, apierr.New("UNAVAILABLE", "API key installation scope is invalid")
		}
	}
	return Key{ID: row.ID, ApplicationID: row.ApplicationID, ClientID: row.ClientID, SpaceID: row.SpaceID,
		Name: row.Name, Prefix: row.Prefix, ExpiresAt: row.ExpiresAt.Time, CreatedAt: row.CreatedAt.Time,
		Scopes: scopes, RestrictTo: restrictions, AllowedIPCIDRs: allowedIPCIDRs, AllowSubjectAssertion: row.AllowSubjectAssertion}, nil
}

// ResolveKeyInstallation finds the application member whose current authority
// covers the requested Space. A key restriction is checked before the
// installation so a restricted key cannot reveal another installation.
func (s *Service) ResolveKeyInstallation(ctx context.Context, key Key, targetSpaceID string) (string, string, error) {
	if s == nil || s.Store == nil {
		return "", "", apierr.New("UNAVAILABLE", "application installations are unavailable")
	}
	return s.ResolveKeyInstallationTx(ctx, s.Store.Queries(), key, targetSpaceID)
}

// ResolveKeyInstallationTx applies the same installation boundary using the
// transaction supplied by a state-changing operation.
func (s *Service) ResolveKeyInstallationTx(ctx context.Context, q *db.Queries, key Key, targetSpaceID string) (string, string, error) {
	ancestors, err := q.ListActiveSpaceAncestorsForKey(ctx, db.ListActiveSpaceAncestorsForKeyParams{TargetSpaceID: targetSpaceID})
	if err != nil {
		return "", "", err
	}
	if len(ancestors) == 0 {
		return "", "APPLICATION_NOT_INSTALLED", nil
	}
	if len(key.RestrictTo) > 0 {
		allowed := false
		for _, restriction := range key.RestrictTo {
			if restriction.SpaceID == targetSpaceID || (restriction.IncludeDescendants && slices.Contains(ancestors, restriction.SpaceID)) {
				allowed = true
				break
			}
		}
		if !allowed {
			return "", "KEY_SCOPE_EXCLUDED", nil
		}
	}
	installation, err := q.GetActiveApplicationInstallationForSpace(ctx, db.GetActiveApplicationInstallationForSpaceParams{
		ApplicationID: key.ApplicationID, TargetSpaceID: targetSpaceID,
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return "", "APPLICATION_NOT_INSTALLED", nil
	}
	if err != nil {
		return "", "", err
	}
	return installation.MemberID, "", nil
}

func (s *Service) OAuthClient(ctx context.Context, clientID string) (OAuthClient, error) {
	row, err := s.Store.Queries().GetApplicationByClientID(ctx, db.GetApplicationByClientIDParams{ClientID: clientID})
	if errors.Is(err, pgx.ErrNoRows) {
		return OAuthClient{}, apierr.New("invalid_request", "client_id is not registered")
	}
	if err != nil {
		return OAuthClient{}, err
	}
	if row.Status != "active" || (row.Visibility == "public" && row.ReviewStatus != "approved") {
		return OAuthClient{}, apierr.New("invalid_request", "client_id is not registered")
	}
	var redirectURIs, allowedScopes []string
	if err := json.Unmarshal(row.RedirectUris, &redirectURIs); err != nil {
		return OAuthClient{}, apierr.New("temporarily_unavailable", "client metadata is invalid")
	}
	if err := json.Unmarshal(row.AllowedScopes, &allowedScopes); err != nil {
		return OAuthClient{}, apierr.New("temporarily_unavailable", "client metadata is invalid")
	}
	return OAuthClient{ID: row.ID, SpaceID: row.SpaceID, Name: row.Name, ClientID: row.ClientID, RedirectURIs: redirectURIs, AllowedScopes: allowedScopes, ClientSecretHash: row.ClientSecretHash}, nil
}

func (s *Service) OAuthClientInstalled(ctx context.Context, applicationID, spaceID string) (bool, error) {
	_, err := s.Store.Queries().GetActiveApplicationInstallationForSpace(ctx, db.GetActiveApplicationInstallationForSpaceParams{
		ApplicationID: applicationID, TargetSpaceID: spaceID,
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	return err == nil, err
}

func (s *Service) OAuthClientByIDTx(ctx context.Context, q *db.Queries, id string) (OAuthClient, error) {
	row, err := q.GetOAuthClientByID(ctx, db.GetOAuthClientByIDParams{ID: id})
	if errors.Is(err, pgx.ErrNoRows) {
		return OAuthClient{}, apierr.New("invalid_request", "client_id is not registered")
	}
	if err != nil {
		return OAuthClient{}, err
	}
	if row.Status != "active" || (row.Visibility == "public" && row.ReviewStatus != "approved") {
		return OAuthClient{}, apierr.New("invalid_request", "client_id is not registered")
	}
	var redirects, scopes []string
	if json.Unmarshal(row.RedirectUris, &redirects) != nil || json.Unmarshal(row.AllowedScopes, &scopes) != nil {
		return OAuthClient{}, apierr.New("temporarily_unavailable", "client metadata is invalid")
	}
	return OAuthClient{ID: row.ID, SpaceID: row.SpaceID, Name: row.Name, ClientID: row.ClientID, RedirectURIs: redirects, AllowedScopes: scopes, ClientSecretHash: row.ClientSecretHash}, nil
}

// AuthenticateOAuthClient resolves a registered OAuth client and verifies its
// secret when the client is confidential. Public PKCE clients have no stored
// secret and are intentionally accepted without one.
func (s *Service) AuthenticateOAuthClient(ctx context.Context, clientID, rawSecret string) (OAuthClient, error) {
	client, err := s.OAuthClient(ctx, clientID)
	if err != nil {
		var publicErr *apierr.Error
		if errors.As(err, &publicErr) && publicErr.Code != "invalid_request" {
			return OAuthClient{}, err
		}
		return OAuthClient{}, apierr.New("invalid_client", "OAuth client authentication failed")
	}
	if len(client.ClientSecretHash) == 0 {
		return client, nil
	}
	if strings.TrimSpace(rawSecret) == "" {
		return OAuthClient{}, apierr.New("invalid_client", "OAuth client authentication failed")
	}
	for _, key := range s.HMACKeys {
		mac := hmac.New(sha256.New, key)
		_, _ = mac.Write([]byte(rawSecret))
		if hmac.Equal(mac.Sum(nil), client.ClientSecretHash) {
			return client, nil
		}
	}
	return OAuthClient{}, apierr.New("invalid_client", "OAuth client authentication failed")
}

// HMACClientSecretHash returns the storage digest for an OAuth client secret.
// Deployments should use the current configured HMAC key and retain previous
// keys during rotation.
func HMACClientSecretHash(key []byte, rawSecret string) []byte {
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write([]byte(rawSecret))
	return mac.Sum(nil)
}

func (s *Service) CreateAuthorizationCode(ctx context.Context, in CreateAuthorizationCodeInput) error {
	return s.Store.InTx(ctx, func(q *db.Queries) error {
		return s.CreateAuthorizationCodeTx(ctx, q, in)
	})
}

func (s *Service) CreateAuthorizationCodeTx(ctx context.Context, q *db.Queries, in CreateAuthorizationCodeInput) error {
	return q.CreateAuthorizationCode(ctx, db.CreateAuthorizationCodeParams{
		ID: in.ID, ApplicationID: in.ApplicationID, UserID: in.UserID,
		MemberID: nullableText(in.MemberID), RedirectUri: in.RedirectURI,
		CodeHash: in.CodeHash, CodeChallenge: pgtype.Text{String: in.CodeChallenge, Valid: true},
		CodeChallengeMethod: pgtype.Text{String: in.CodeChallengeMethod, Valid: true}, Scope: in.Scope,
		Nonce: nullableText(in.Nonce), Resource: nullableText(in.Resource), ExpiresAt: pgtype.Timestamptz{Time: in.ExpiresAt, Valid: true},
	})
}

func (s *Service) ConsumeAuthorizationCode(ctx context.Context, codeHash []byte, applicationID, redirectURI string) (AuthorizationCode, error) {
	var out AuthorizationCode
	err := s.Store.InTx(ctx, func(q *db.Queries) error {
		row, err := q.ConsumeAuthorizationCode(ctx, db.ConsumeAuthorizationCodeParams{CodeHash: codeHash, ApplicationID: applicationID, RedirectUri: redirectURI})
		if err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return apierr.New("invalid_grant", "authorization code is invalid or expired")
			}
			return err
		}
		out = AuthorizationCode{ID: row.ID, ApplicationID: row.ApplicationID, UserID: row.UserID, RedirectURI: row.RedirectUri, Scope: row.Scope, ExpiresAt: row.ExpiresAt.Time}
		if row.MemberID.Valid {
			out.MemberID = row.MemberID.String
		}
		if row.CodeChallenge.Valid {
			out.CodeChallenge = row.CodeChallenge.String
		}
		if row.CodeChallengeMethod.Valid {
			out.CodeChallengeMethod = row.CodeChallengeMethod.String
		}
		if row.Nonce.Valid {
			out.Nonce = row.Nonce.String
		}
		if row.Resource.Valid {
			out.Resource = row.Resource.String
		}
		return nil
	})
	return out, err
}

func nullableText(value string) pgtype.Text {
	return pgtype.Text{String: value, Valid: value != ""}
}

// UpgradeLegacyKeyHashes wraps existing SHA-256 digests before serving traffic.
// The old digest is sufficient to perform this one-way migration without
// recovering or reissuing the secret. Historical keys without expiry are
// revoked during conversion because they cannot be valid credentials.
func (s *Service) UpgradeLegacyKeyHashes(ctx context.Context) error {
	if s == nil || s.Store == nil || len(s.HMACKeys) == 0 || len(s.HMACKeys[0]) < 32 {
		return errors.New("application API key HMAC key of at least 32 bytes is required")
	}
	for {
		processed := 0
		err := s.Store.InTx(ctx, func(q *db.Queries) error {
			rows, err := q.LockLegacyAPIKeyHashes(ctx)
			if err != nil {
				return err
			}
			for _, row := range rows {
				if len(row.SecretHash) != sha256.Size {
					return errors.New("legacy application API key has an invalid digest")
				}
				mac := hmac.New(sha256.New, s.HMACKeys[0])
				_, _ = mac.Write(row.SecretHash)
				updated, err := q.UpdateAPIKeyHash(ctx, db.UpdateAPIKeyHashParams{
					ID: row.ID, SecretHash: mac.Sum(nil), PreviousHash: row.SecretHash, PreviousScheme: "sha256_legacy",
				})
				if err != nil {
					return err
				}
				processed += int(updated)
			}
			return nil
		})
		if err != nil {
			return err
		}
		if processed == 0 {
			return nil
		}
	}
}

func apiKeyHash(key []byte, raw string) []byte {
	sum := sha256.Sum256([]byte(raw))
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write(sum[:])
	return mac.Sum(nil)
}

func GenerateSecret(keyID string, key []byte) (string, string, []byte, error) {
	if len(key) < 32 {
		return "", "", nil, errors.New("application API key HMAC key must be at least 32 bytes")
	}
	if !strings.HasPrefix(keyID, "key_") || len(keyID) <= len("key_") {
		return "", "", nil, errors.New("application API key ID is invalid")
	}
	b := make([]byte, 32)
	if _, e := rand.Read(b); e != nil {
		return "", "", nil, e
	}
	raw := base64.RawURLEncoding.EncodeToString(b)
	prefix := "ply_sk_" + strings.TrimPrefix(keyID, "key_")
	return prefix + "." + raw, prefix, apiKeyHash(key, raw), nil
}
func (s *Service) CreateKey(ctx context.Context, applicationID, name string, scopes []string, expires *time.Time) (string, error) {
	if s == nil || s.Store == nil || len(s.HMACKeys) == 0 {
		return "", apierr.New("UNAVAILABLE", "application API key creation is unavailable")
	}
	now := time.Now()
	if expires == nil || !expires.After(now) || expires.After(now.Add(365*24*time.Hour)) {
		return "", apierr.New("VALIDATION_FAILED", "API key expiry must be in the future and within one year")
	}
	keyID := string(ids.New[ids.APIKeyID]("key"))
	raw, prefix, hash, e := GenerateSecret(keyID, s.HMACKeys[0])
	if e != nil {
		return "", e
	}
	_, e = s.Store.Queries().CreateAPIKey(ctx, db.CreateAPIKeyParams{ID: keyID, ApplicationID: applicationID, Name: name, Prefix: prefix, SecretHash: hash, Scopes: mustJSON(scopes), ExpiresAt: nullableTime(expires)})
	return raw, e
}
func mustJSON(v any) []byte { b, _ := json.Marshal(v); return b }
func nullableTime(t *time.Time) pgtype.Timestamptz {
	if t == nil {
		return pgtype.Timestamptz{}
	}
	return pgtype.Timestamptz{Time: *t, Valid: true}
}
