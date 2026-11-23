package enterprise

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	saml2 "github.com/russellhaering/gosaml2"
	"github.com/russellhaering/gosaml2/types"
	"golang.org/x/oauth2"

	"github.com/plystra/auth/internal/account"
	"github.com/plystra/auth/internal/apierr"
	"github.com/plystra/auth/internal/audit"
	"github.com/plystra/auth/internal/authorization"
	"github.com/plystra/auth/internal/authz/engine"
	"github.com/plystra/auth/internal/db"
	"github.com/plystra/auth/internal/ids"
	"github.com/plystra/auth/internal/secret"
	"github.com/plystra/auth/internal/security"
	"github.com/plystra/auth/internal/session"
	"github.com/plystra/auth/internal/stepup"
	"github.com/plystra/auth/internal/store"
)

const (
	stateLifetime         = 5 * time.Minute
	clientSecretAAD       = "plystra-auth-sso-client-secret-v1"
	pkceVerifierAAD       = "plystra-auth-sso-pkce-verifier-v1"
	defaultGroupsClaim    = "groups"
	maxRoleMappings       = 100
	maxIdentityGroups     = 200
	maxExternalSubjectLen = 512
	maxDiscoveryBytes     = 256 << 10
	domainTXTLabel        = "_plystra-auth"
)

type Service struct {
	Store         *store.Store
	Authorization *authorization.Service
	Sessions      *session.Service
	StepUp        stepup.Consumer
	DataKey       secret.String
	Passwords     security.PasswordHasher
	HTTPClient    *http.Client
	DNSResolver   TXTResolver
	Issuer        string
}

type TXTResolver interface {
	LookupTXT(context.Context, string) ([]string, error)
}

type DomainInput struct {
	Domain        string
	ConnectionID  string
	ForceSSO      bool
	CoversSubtree bool
}

type Domain struct {
	ID                string    `json:"id"`
	SpaceID           string    `json:"space_id"`
	Domain            string    `json:"domain"`
	ConnectionID      string    `json:"connection_id,omitempty"`
	ForceSSO          bool      `json:"force_sso"`
	CoversSubtree     bool      `json:"covers_subtree"`
	Status            string    `json:"status"`
	VerificationToken string    `json:"verification_token,omitempty"`
	VerifiedAt        time.Time `json:"verified_at,omitempty"`
	CreatedAt         time.Time `json:"created_at"`
	UpdatedAt         time.Time `json:"updated_at"`
}

type ConnectionInput struct {
	Name          string
	Provider      string
	Issuer        string
	ClientID      string
	ClientSecret  string
	RedirectURI   string
	GroupsClaim   string
	RoleMappings  map[string]string
	SAMLMetadata  string
	CoversSubtree bool
}

type Connection struct {
	ID            string            `json:"id"`
	SpaceID       string            `json:"space_id"`
	Name          string            `json:"name"`
	Provider      string            `json:"provider"`
	Issuer        string            `json:"issuer"`
	ClientID      string            `json:"client_id"`
	RedirectURI   string            `json:"redirect_uri"`
	GroupsClaim   string            `json:"groups_claim"`
	RoleMappings  map[string]string `json:"role_mappings"`
	Status        string            `json:"status"`
	CoversSubtree bool              `json:"covers_subtree"`
	CreatedAt     time.Time         `json:"created_at"`
	UpdatedAt     time.Time         `json:"updated_at"`
}

type StartResult struct {
	AuthorizationURL    string    `json:"authorization_url"`
	AuthorizationMethod string    `json:"authorization_method,omitempty"`
	SAMLRequest         string    `json:"saml_request,omitempty"`
	RelayState          string    `json:"relay_state,omitempty"`
	State               string    `json:"state"`
	ExpiresAt           time.Time `json:"expires_at"`
}

type CallbackInput struct {
	ConnectionID string
	State        string
	Code         string
	RedirectURI  string
	SAMLResponse string
}

type samlConnectionDetails struct {
	EntityID    string
	SSOURL      string
	Binding     string
	Certificate string
}

type idTokenClaims struct {
	samlProof      *samlLoginProof
	Subject        string                     `json:"sub"`
	Email          string                     `json:"email"`
	EmailVerified  bool                       `json:"email_verified"`
	Name           string                     `json:"name"`
	Nonce          string                     `json:"nonce"`
	Groups         []string                   `json:"-"`
	VerifiedClaims map[string]json.RawMessage `json:"-"`
	SAMLAttributes map[string][]string        `json:"-"`
}

func (s *Service) CreateConnection(ctx context.Context, actorMemberID, spaceID string, in ConnectionInput) (Connection, error) {
	in.Name = strings.TrimSpace(in.Name)
	in.Provider = strings.TrimSpace(strings.ToLower(in.Provider))
	in.Issuer = strings.TrimSpace(in.Issuer)
	in.ClientID = strings.TrimSpace(in.ClientID)
	in.RedirectURI = strings.TrimSpace(in.RedirectURI)
	in.GroupsClaim = strings.TrimSpace(in.GroupsClaim)
	in.SAMLMetadata = strings.TrimSpace(in.SAMLMetadata)
	if in.GroupsClaim == "" {
		in.GroupsClaim = defaultGroupsClaim
	}
	if in.Name == "" || len(in.Name) > 128 || len(in.GroupsClaim) > 128 {
		return Connection{}, apierr.New("validation_failed", "SSO connection fields are invalid")
	}
	var samlDetails *samlConnectionDetails
	switch in.Provider {
	case "oidc":
		if in.ClientID == "" || len(in.ClientID) > 512 || in.ClientSecret == "" || len(in.ClientSecret) > 4096 {
			return Connection{}, apierr.New("validation_failed", "OIDC connection fields are invalid")
		}
		if err := validateIssuer(in.Issuer); err != nil {
			return Connection{}, err
		}
	case "saml":
		if in.ClientSecret != "" || in.SAMLMetadata == "" || len(in.SAMLMetadata) > 1024*1024 {
			return Connection{}, apierr.New("validation_failed", "SAML connection metadata is required")
		}
		parsed, err := parseSAMLMetadata(in.SAMLMetadata)
		if err != nil {
			return Connection{}, err
		}
		if in.Issuer != "" && in.Issuer != parsed.EntityID {
			return Connection{}, apierr.New("validation_failed", "SAML issuer does not match metadata")
		}
		in.Issuer = parsed.EntityID
		in.ClientID = parsed.EntityID
		samlDetails = &parsed
	default:
		return Connection{}, apierr.New("validation_failed", "provider must be oidc or saml")
	}
	connectionID := string(ids.New[ids.ID]("con"))
	if strings.Count(in.RedirectURI, "{connection_id}") > 1 || (strings.Contains(in.RedirectURI, "{") && !strings.Contains(in.RedirectURI, "{connection_id}")) || strings.Contains(in.RedirectURI, "}") && !strings.Contains(in.RedirectURI, "{connection_id}") {
		return Connection{}, apierr.New("validation_failed", "redirect_uri contains an unsupported placeholder")
	}
	redirectURI := strings.ReplaceAll(in.RedirectURI, "{connection_id}", connectionID)
	if err := validateRedirectURI(redirectURI); err != nil {
		return Connection{}, err
	}
	if len(in.RoleMappings) > maxRoleMappings {
		return Connection{}, apierr.New("validation_failed", "too many SSO role mappings")
	}
	for group, roleID := range in.RoleMappings {
		if strings.TrimSpace(group) == "" || len(group) > 256 || strings.TrimSpace(roleID) == "" {
			return Connection{}, apierr.New("validation_failed", "SSO role mappings are invalid")
		}
	}
	var ciphertext []byte
	var err error
	if in.Provider == "oidc" {
		ciphertext, err = s.seal([]byte(in.ClientSecret), clientSecretAAD)
		if err != nil {
			return Connection{}, err
		}
	}
	roleMappings := in.RoleMappings
	if roleMappings == nil {
		roleMappings = map[string]string{}
	}
	mappings, err := json.Marshal(roleMappings)
	if err != nil {
		return Connection{}, err
	}
	var out Connection
	err = s.Store.InTx(ctx, func(q *db.Queries) error {
		if s.Authorization == nil {
			return apierr.New("unavailable", "authorization is unavailable")
		}
		if err := s.Authorization.CheckSSOConnectionCreateTx(ctx, q, actorMemberID, spaceID, connectionID, in.RoleMappings); err != nil {
			return err
		}
		if _, err := q.GetSpace(ctx, db.GetSpaceParams{ID: spaceID}); err != nil {
			return err
		}
		if _, required := stepup.RequirementFromContext(ctx); required {
			if s.StepUp == nil {
				return apierr.New("unavailable", "step-up authentication is unavailable")
			}
			if err := s.StepUp.ConsumeStepUpTx(ctx, q); err != nil {
				return err
			}
		}
		params := db.CreateSSOConnectionParams{
			ID: connectionID, SpaceID: spaceID, Name: in.Name, Provider: in.Provider,
			Issuer: in.Issuer, ClientID: in.ClientID, ClientSecretCiphertext: ciphertext,
			RedirectUri: redirectURI, GroupsClaim: in.GroupsClaim, RoleMappings: mappings,
			CoversSubtree: in.CoversSubtree, ConfiguredByMemberID: optionalDirectoryText(actorMemberID), ConfiguredByUserID: actorUserID(ctx, actorMemberID),
		}
		if samlDetails != nil {
			params.SamlEntityID = pgtype.Text{String: samlDetails.EntityID, Valid: true}
			params.SamlSsoUrl = pgtype.Text{String: samlDetails.SSOURL, Valid: true}
			params.SamlSsoBinding = pgtype.Text{String: samlDetails.Binding, Valid: true}
			params.SamlIdpCertificate = pgtype.Text{String: samlDetails.Certificate, Valid: true}
		}
		row, err := q.CreateSSOConnection(ctx, params)
		if err != nil {
			return err
		}
		out, err = connectionFromPublicRow(db.ListSSOConnectionsRow(row))
		if err != nil {
			return err
		}
		return audit.WriteSecurityEvent(ctx, q, audit.SecurityEvent{
			ActorType: "member", ActorID: actorMemberID, MemberID: actorMemberID,
			Action: "sso.connection.create", Outcome: "success", Permission: "auth.connections:manage",
			Resource: audit.Resource{Type: "sso_connection", ID: out.ID, SpaceID: spaceID},
			Metadata: map[string]string{"provider": out.Provider, "issuer": out.Issuer, "covers_subtree": fmt.Sprintf("%t", out.CoversSubtree)},
		})
	})
	if err != nil {
		return Connection{}, normalizeConnectionError(err)
	}
	return out, nil
}

func (s *Service) ListConnections(ctx context.Context, actorMemberID, spaceID string) ([]Connection, error) {
	var out []Connection
	err := s.Store.InTx(ctx, func(q *db.Queries) error {
		if err := s.authorizeSettingsReadTx(ctx, q, actorMemberID, SettingsListRequest("sso_connections.list", spaceID)); err != nil {
			return err
		}
		rows, err := q.ListSSOConnections(ctx, db.ListSSOConnectionsParams{SpaceID: spaceID})
		if err != nil {
			return err
		}
		out = make([]Connection, 0, len(rows))
		for _, row := range rows {
			connection, err := connectionFromPublicRow(row)
			if err != nil {
				return err
			}
			out = append(out, connection)
		}
		return nil
	})
	if err != nil {
		return nil, normalizeConnectionError(err)
	}
	return out, nil
}

func SettingsListRequest(operation, spaceID string) map[string]string {
	return map[string]string{"operation": operation, "space_id": spaceID}
}

func ConnectionDetailRequest(spaceID, connectionID string) map[string]string {
	return map[string]string{"operation": "sso_connections.get", "space_id": spaceID, "connection_id": connectionID}
}

func (s *Service) authorizeSettingsReadTx(ctx context.Context, q *db.Queries, actorMemberID string, request map[string]string) error {
	digest, err := stepup.DigestValue(request)
	if err != nil {
		return err
	}
	operation, spaceID := request["operation"], request["space_id"]
	ctx = authorization.BindGovernanceApproval(ctx, operation, spaceID, digest)
	if err := s.checkConnectionManagement(ctx, q, actorMemberID, spaceID); err != nil {
		return err
	}
	actor, err := q.GetMemberForAuthorization(ctx, db.GetMemberForAuthorizationParams{ID: actorMemberID})
	if err != nil {
		return err
	}
	if actor.Type == "agent" {
		return nil
	}
	if actor.Type != "human" {
		return apierr.New("PRINCIPAL_KIND_NOT_ALLOWED", "reading enterprise connection settings requires a human or Agent member")
	}
	proof, ok := stepup.RequirementFromContext(ctx)
	if !ok || proof.Operation != operation || !bytes.Equal(proof.Digest, digest) {
		return apierr.New("STEP_UP_REQUIRED", "complete step-up for this operation and request")
	}
	issued, err := q.GetSession(ctx, db.GetSessionParams{ID: proof.SessionID})
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return err
	}
	validUser := issued.UserID != "" && issued.UserID == authorization.HumanActorUserID(ctx, actorMemberID)
	if !validUser || issued.MemberID.Valid && issued.MemberID.String != actorMemberID {
		return apierr.New("STEP_UP_REQUIRED", "complete step-up for this operation and request")
	}
	return s.consumeStepUp(ctx, q)
}

func (s *Service) GetConnection(ctx context.Context, actorMemberID, spaceID, connectionID string) (Connection, error) {
	var out Connection
	err := s.Store.InTx(ctx, func(q *db.Queries) error {
		if err := s.authorizeSettingsReadTx(ctx, q, actorMemberID, ConnectionDetailRequest(spaceID, connectionID)); err != nil {
			return err
		}
		row, err := q.GetSSOConnectionInSpace(ctx, db.GetSSOConnectionInSpaceParams{SpaceID: spaceID, ID: connectionID})
		if errors.Is(err, pgx.ErrNoRows) {
			return apierr.New("not_found", "SSO connection was not found")
		}
		if err != nil {
			return err
		}
		out, err = connectionFromPublicRow(db.ListSSOConnectionsRow(row))
		return err
	})
	if err != nil {
		return Connection{}, normalizeConnectionError(err)
	}
	return out, nil
}

func (s *Service) DisableConnection(ctx context.Context, actorMemberID, spaceID, connectionID string) error {
	return normalizeConnectionError(s.Store.InTx(ctx, func(q *db.Queries) error {
		if s.Authorization == nil {
			return apierr.New("unavailable", "authorization is unavailable")
		}
		decision, err := s.Authorization.CheckMutationTx(ctx, q, authorization.CheckRequest{
			MemberID: actorMemberID, Permission: "auth.connections:manage", ResourceSpace: spaceID,
		})
		if err != nil {
			return err
		}
		if decision.Effect != engine.Allow {
			return &apierr.Error{Code: decision.Code, Message: "The authorization engine denied this operation."}
		}
		connection, err := q.LockSSOConnection(ctx, db.LockSSOConnectionParams{ID: connectionID})
		if errors.Is(err, pgx.ErrNoRows) {
			return apierr.New("not_found", "SSO connection was not found")
		}
		if err != nil {
			return err
		}
		if connection.SpaceID != spaceID {
			return apierr.New("not_found", "SSO connection was not found")
		}
		if _, required := stepup.RequirementFromContext(ctx); required {
			if s.StepUp == nil {
				return apierr.New("unavailable", "step-up authentication is unavailable")
			}
			if err := s.StepUp.ConsumeStepUpTx(ctx, q); err != nil {
				return err
			}
		}
		if err := q.DisableSSOConnection(ctx, db.DisableSSOConnectionParams{ID: connection.ID}); err != nil {
			return err
		}
		return audit.WriteSecurityEvent(ctx, q, audit.SecurityEvent{
			ActorType: "member", ActorID: actorMemberID, MemberID: actorMemberID,
			Action: "sso.connection.disable", Outcome: "success", Permission: "auth.connections:manage",
			Resource: audit.Resource{Type: "sso_connection", ID: connection.ID, SpaceID: spaceID},
		})
	}))
}

func (s *Service) CreateDomain(ctx context.Context, actorMemberID, spaceID string, in DomainInput) (Domain, error) {
	domain, err := normalizeDomain(in.Domain)
	if err != nil {
		return Domain{}, err
	}
	if in.ForceSSO && strings.TrimSpace(in.ConnectionID) == "" {
		return Domain{}, apierr.New("validation_failed", "force_sso requires an OIDC connection")
	}
	if in.CoversSubtree && strings.TrimSpace(in.ConnectionID) == "" {
		return Domain{}, apierr.New("validation_failed", "covers_subtree requires an SSO connection")
	}
	token, err := randomOpaque("domv_")
	if err != nil {
		return Domain{}, err
	}
	var out Domain
	err = s.Store.InTx(ctx, func(q *db.Queries) error {
		if err := s.checkConnectionManagement(ctx, q, actorMemberID, spaceID); err != nil {
			return err
		}
		if _, err := q.GetSpace(ctx, db.GetSpaceParams{ID: spaceID}); err != nil {
			return err
		}
		var connectionID pgtype.Text
		if strings.TrimSpace(in.ConnectionID) != "" {
			connection, err := q.LockSSOConnection(ctx, db.LockSSOConnectionParams{ID: strings.TrimSpace(in.ConnectionID)})
			if errors.Is(err, pgx.ErrNoRows) {
				return apierr.New("not_found", "SSO connection was not found")
			}
			if err != nil {
				return err
			}
			if connection.SpaceID != spaceID {
				return apierr.New("not_found", "SSO connection was not found")
			}
			if in.ForceSSO && connection.Status != "active" {
				return apierr.New("validation_failed", "force_sso requires an active OIDC connection")
			}
			if in.CoversSubtree && !connection.CoversSubtree {
				return apierr.New("validation_failed", "covers_subtree requires a connection that covers the subtree")
			}
			connectionID = pgtype.Text{String: connection.ID, Valid: true}
		}
		if err := s.consumeStepUp(ctx, q); err != nil {
			return err
		}
		row, err := q.CreateSSODomain(ctx, db.CreateSSODomainParams{
			ID: string(ids.New[ids.DomainID]("dom")), SpaceID: spaceID, Domain: domain,
			VerificationTokenHash: digest(token), ConnectionID: connectionID, ForceSso: in.ForceSSO,
			CoversSubtree: in.CoversSubtree,
		})
		if err != nil {
			return err
		}
		out = domainFromRow(row)
		out.VerificationToken = token
		return audit.WriteSecurityEvent(ctx, q, audit.SecurityEvent{
			ActorType: "member", ActorID: actorMemberID, MemberID: actorMemberID,
			Action: "sso.domain.create", Outcome: "success", Permission: "auth.connections:manage",
			Resource: audit.Resource{Type: "sso_domain", ID: out.ID, SpaceID: spaceID},
			Metadata: map[string]string{"domain": domain, "force_sso": fmt.Sprintf("%t", in.ForceSSO), "covers_subtree": fmt.Sprintf("%t", in.CoversSubtree)},
		})
	})
	if err != nil {
		return Domain{}, normalizeConnectionError(err)
	}
	return out, nil
}

func (s *Service) ListDomains(ctx context.Context, actorMemberID, spaceID string) ([]Domain, error) {
	var rows []db.ListSSODomainsRow
	err := s.Store.InTx(ctx, func(q *db.Queries) error {
		if err := s.authorizeSettingsReadTx(ctx, q, actorMemberID, SettingsListRequest("domains.list", spaceID)); err != nil {
			return err
		}
		var err error
		rows, err = q.ListSSODomains(ctx, db.ListSSODomainsParams{SpaceID: spaceID})
		return err
	})
	if err != nil {
		return nil, normalizeConnectionError(err)
	}
	out := make([]Domain, 0, len(rows))
	for _, row := range rows {
		out = append(out, domainFromListRow(row))
	}
	return out, nil
}

func (s *Service) VerifyDomain(ctx context.Context, actorMemberID, spaceID, domainID string) error {
	if err := s.Store.InTx(ctx, func(q *db.Queries) error {
		return s.checkConnectionManagement(ctx, q, actorMemberID, spaceID)
	}); err != nil {
		return normalizeConnectionError(err)
	}
	row, err := s.Store.Queries().GetSSODomain(ctx, db.GetSSODomainParams{ID: strings.TrimSpace(domainID)})
	if errors.Is(err, pgx.ErrNoRows) {
		return apierr.New("not_found", "domain was not found")
	}
	if err != nil {
		return err
	}
	if row.SpaceID != spaceID {
		return apierr.New("not_found", "domain was not found")
	}
	if row.Status == "verified" {
		return nil
	}
	if row.Status != "pending" {
		return apierr.New("forbidden", "domain verification is disabled")
	}
	resolver := s.DNSResolver
	if resolver == nil {
		resolver = net.DefaultResolver
	}
	txt, err := resolver.LookupTXT(ctx, domainTXTLabel+"."+row.Domain)
	if err != nil {
		return apierr.New("verification_failed", "the DNS TXT record could not be resolved")
	}
	matched := false
	for _, value := range txt {
		if subtle.ConstantTimeCompare(digest(strings.TrimSpace(value)), row.VerificationTokenHash) == 1 {
			matched = true
			break
		}
	}
	if !matched {
		return apierr.New("verification_failed", "the DNS TXT record does not match")
	}
	return normalizeConnectionError(s.Store.InTx(ctx, func(q *db.Queries) error {
		if err := s.checkConnectionManagement(ctx, q, actorMemberID, spaceID); err != nil {
			return err
		}
		locked, err := q.LockSSODomain(ctx, db.LockSSODomainParams{ID: row.ID})
		if errors.Is(err, pgx.ErrNoRows) || locked.SpaceID != spaceID {
			return apierr.New("not_found", "domain was not found")
		}
		if err != nil {
			return err
		}
		if locked.Status == "verified" {
			return nil
		}
		if locked.Status != "pending" || subtle.ConstantTimeCompare(locked.VerificationTokenHash, row.VerificationTokenHash) != 1 {
			return apierr.New("verification_failed", "domain verification changed while it was being checked")
		}
		if err := s.consumeStepUp(ctx, q); err != nil {
			return err
		}
		if err := q.LockForcedSSODomainForChange(ctx, db.LockForcedSSODomainForChangeParams{Domain: locked.Domain}); err != nil {
			return err
		}
		if err := q.VerifySSODomain(ctx, db.VerifySSODomainParams{ID: row.ID}); err != nil {
			return err
		}
		return audit.WriteSecurityEvent(ctx, q, audit.SecurityEvent{
			ActorType: "member", ActorID: actorMemberID, MemberID: actorMemberID,
			Action: "sso.domain.verify", Outcome: "success", Permission: "auth.connections:manage",
			Resource: audit.Resource{Type: "sso_domain", ID: row.ID, SpaceID: spaceID},
			Metadata: map[string]string{"domain": row.Domain},
		})
	}))
}

func (s *Service) DisableDomain(ctx context.Context, actorMemberID, spaceID, domainID string) error {
	return normalizeConnectionError(s.Store.InTx(ctx, func(q *db.Queries) error {
		if err := s.checkConnectionManagement(ctx, q, actorMemberID, spaceID); err != nil {
			return err
		}
		row, err := q.LockSSODomain(ctx, db.LockSSODomainParams{ID: strings.TrimSpace(domainID)})
		if errors.Is(err, pgx.ErrNoRows) {
			return apierr.New("not_found", "domain was not found")
		}
		if err != nil {
			return err
		}
		if row.SpaceID != spaceID {
			return apierr.New("not_found", "domain was not found")
		}
		if err := s.consumeStepUp(ctx, q); err != nil {
			return err
		}
		if err := q.LockForcedSSODomainForChange(ctx, db.LockForcedSSODomainForChangeParams{Domain: row.Domain}); err != nil {
			return err
		}
		if err := q.DisableSSODomain(ctx, db.DisableSSODomainParams{ID: row.ID}); err != nil {
			return err
		}
		return audit.WriteSecurityEvent(ctx, q, audit.SecurityEvent{
			ActorType: "member", ActorID: actorMemberID, MemberID: actorMemberID,
			Action: "sso.domain.disable", Outcome: "success", Permission: "auth.connections:manage",
			Resource: audit.Resource{Type: "sso_domain", ID: row.ID, SpaceID: spaceID},
			Metadata: map[string]string{"domain": row.Domain},
		})
	}))
}

func (s *Service) ForcedConnectionForEmail(ctx context.Context, email string, targetSpaceID ...string) (string, error) {
	_, domain, err := splitEmailDomain(email)
	if err != nil {
		return "", nil
	}
	spaceID := ""
	if len(targetSpaceID) > 0 {
		spaceID = strings.TrimSpace(targetSpaceID[0])
	}
	return forcedConnectionForDomain(ctx, s.Store.Queries(), domain, spaceID)
}

func (s *Service) CheckLocalSignInTx(ctx context.Context, q *db.Queries, email, spaceID string) error {
	_, domain, err := splitEmailDomain(email)
	if err != nil {
		return nil
	}
	// Shared locks let logins proceed concurrently. A verification or disable
	// serializes with the entire authentication and issuance transaction.
	if err := q.LockForcedSSODomainForLogin(ctx, db.LockForcedSSODomainForLoginParams{Domain: domain}); err != nil {
		return err
	}
	connection, err := forcedConnectionForDomain(ctx, q, domain, spaceID)
	if err != nil {
		return err
	}
	if connection != "" {
		return apierr.New("invalid_grant", "single sign-on is required; restart sign-in")
	}
	return nil
}

func (s *Service) AllowsSpaceSession(ctx context.Context, q *db.Queries, email, spaceID, signedInConnectionID string) (bool, error) {
	return allowsSpaceSession(ctx, q, email, spaceID, signedInConnectionID, false)
}

func (s *Service) AllowsSpaceSessionTx(ctx context.Context, q *db.Queries, email, spaceID, signedInConnectionID string) (bool, error) {
	return allowsSpaceSession(ctx, q, email, spaceID, signedInConnectionID, true)
}

func allowsSpaceSession(ctx context.Context, q *db.Queries, email, spaceID, signedInConnectionID string, lock bool) (bool, error) {
	if spaceID == "" {
		return true, nil
	}
	_, domain, err := splitEmailDomain(email)
	if err != nil {
		return true, nil
	}
	if lock {
		if err := q.LockForcedSSODomainForLogin(ctx, db.LockForcedSSODomainForLoginParams{Domain: domain}); err != nil {
			return false, err
		}
	}
	required, err := forcedConnectionForDomain(ctx, q, domain, spaceID)
	if err != nil {
		var unavailable *apierr.Error
		if errors.As(err, &unavailable) && unavailable.Code == "temporarily_unavailable" {
			return false, nil
		}
		return false, err
	}
	return required == "" || required == signedInConnectionID, nil
}

func forcedConnectionForDomain(ctx context.Context, q *db.Queries, domain, spaceID string) (string, error) {
	if spaceID != "" {
		active, err := q.AreSpaceAncestorsActive(ctx, db.AreSpaceAncestorsActiveParams{SpaceID: spaceID})
		if err != nil {
			return "", err
		}
		if !active {
			return "", apierr.New("temporarily_unavailable", "the target Space or one of its ancestors is unavailable")
		}
		row, err := q.GetForcedSSOForEmailDomainInSpace(ctx, db.GetForcedSSOForEmailDomainInSpaceParams{
			Domain: domain, SpaceID: spaceID,
		})
		if errors.Is(err, pgx.ErrNoRows) {
			return "", nil
		}
		if err != nil {
			return "", err
		}
		if row.SsoConnectionStatus.String != "active" || !row.SsoConnectionID.Valid {
			return "", apierr.New("temporarily_unavailable", "the configured SSO connection is unavailable")
		}
		return row.SsoConnectionID.String, nil
	}
	row, err := q.GetForcedSSOForEmailDomain(ctx, db.GetForcedSSOForEmailDomainParams{Domain: domain})
	if errors.Is(err, pgx.ErrNoRows) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	active, err := q.AreSpaceAncestorsActive(ctx, db.AreSpaceAncestorsActiveParams{SpaceID: row.SpaceID})
	if err != nil {
		return "", err
	}
	if !active {
		return "", apierr.New("temporarily_unavailable", "the configured Space is unavailable")
	}
	if !row.SsoConnectionID.Valid || !row.SsoConnectionStatus.Valid || row.SsoConnectionStatus.String != "active" {
		return "", apierr.New("temporarily_unavailable", "the configured SSO connection is unavailable")
	}
	return row.SsoConnectionID.String, nil
}

func (s *Service) checkConnectionManagement(ctx context.Context, q *db.Queries, actorMemberID, spaceID string) error {
	if s.Authorization == nil {
		return apierr.New("unavailable", "authorization is unavailable")
	}
	decision, err := s.Authorization.CheckMutationTx(ctx, q, authorization.CheckRequest{
		MemberID: actorMemberID, Permission: "auth.connections:manage", ResourceSpace: spaceID,
	})
	if err != nil {
		return err
	}
	if decision.Effect != engine.Allow {
		return &apierr.Error{Code: decision.Code, Message: "The authorization engine denied this operation."}
	}
	return nil
}

func (s *Service) consumeStepUp(ctx context.Context, q *db.Queries) error {
	if _, required := stepup.RequirementFromContext(ctx); !required {
		return nil
	}
	if s.StepUp == nil {
		return apierr.New("unavailable", "step-up authentication is unavailable")
	}
	return s.StepUp.ConsumeStepUpTx(ctx, q)
}

func (s *Service) Start(ctx context.Context, connectionID, requestedRedirectURI string) (StartResult, error) {
	connectionID = strings.TrimSpace(connectionID)
	row, err := s.Store.Queries().GetSSOConnection(ctx, db.GetSSOConnectionParams{ID: connectionID})
	if errors.Is(err, pgx.ErrNoRows) {
		return StartResult{}, apierr.New("not_found", "SSO connection was not found")
	}
	if err != nil {
		return StartResult{}, err
	}
	if row.Status != "active" {
		return StartResult{}, apierr.New("forbidden", "SSO connection is disabled")
	}
	redirectURI := strings.TrimSpace(requestedRedirectURI)
	if redirectURI == "" {
		redirectURI = row.RedirectUri
	}
	if redirectURI != row.RedirectUri {
		return StartResult{}, apierr.New("invalid_request", "redirect_uri does not match the configured connection")
	}
	if row.Provider == "saml" {
		return s.startSAML(ctx, row, redirectURI)
	}
	provider, err := s.discovery(ctx, row.Issuer)
	if err != nil {
		return StartResult{}, err
	}
	state, err := randomOpaque("sso_state_")
	if err != nil {
		return StartResult{}, err
	}
	nonce, err := randomOpaque("sso_nonce_")
	if err != nil {
		return StartResult{}, err
	}
	verifier, err := randomOpaque("")
	if err != nil {
		return StartResult{}, err
	}
	challenge := sha256.Sum256([]byte(verifier))
	expiresAt := time.Now().UTC().Add(stateLifetime)
	verifierCiphertext, err := s.seal([]byte(verifier), pkceVerifierAAD)
	if err != nil {
		return StartResult{}, err
	}
	if err := s.Store.InTx(ctx, func(q *db.Queries) error {
		_, err := q.CreateSSOState(ctx, db.CreateSSOStateParams{
			ID: string(ids.New[ids.ID]("sos")), ConnectionID: row.ID,
			StateHash: digest(state), NonceHash: digest(nonce),
			PkceVerifierCiphertext: verifierCiphertext, RedirectUri: redirectURI,
			ExpiresAt: pgtype.Timestamptz{Time: expiresAt, Valid: true},
			RequestID: pgtype.Text{},
		})
		return err
	}); err != nil {
		return StartResult{}, err
	}
	query := url.Values{}
	query.Set("response_type", "code")
	query.Set("client_id", row.ClientID)
	query.Set("redirect_uri", redirectURI)
	query.Set("scope", "openid email profile")
	query.Set("state", state)
	query.Set("nonce", nonce)
	query.Set("code_challenge", base64.RawURLEncoding.EncodeToString(challenge[:]))
	query.Set("code_challenge_method", "S256")
	return StartResult{AuthorizationURL: provider.Endpoint().AuthURL + "?" + query.Encode(), State: state, ExpiresAt: expiresAt}, nil
}

func (s *Service) startSAML(ctx context.Context, row db.SsoConnection, redirectURI string) (StartResult, error) {
	provider, err := s.samlProvider(row)
	if err != nil {
		return StartResult{}, err
	}
	relayState, err := randomOpaque("saml_state_")
	if err != nil {
		return StartResult{}, err
	}
	nonce, err := randomOpaque("saml_nonce_")
	if err != nil {
		return StartResult{}, err
	}
	document, err := provider.BuildAuthRequestDocumentNoSig()
	if err != nil {
		return StartResult{}, apierr.New("temporarily_unavailable", "SAML authorization request could not be built")
	}
	requestBytes, err := document.WriteToBytes()
	if err != nil {
		return StartResult{}, apierr.New("temporarily_unavailable", "SAML authorization request could not be built")
	}
	var request struct {
		ID string `xml:"ID,attr"`
	}
	if err := xml.Unmarshal(requestBytes, &request); err != nil || request.ID == "" {
		return StartResult{}, apierr.New("temporarily_unavailable", "SAML authorization request could not be built")
	}
	expiresAt := time.Now().UTC().Add(stateLifetime)
	verifierCiphertext, err := s.seal([]byte("saml"), pkceVerifierAAD)
	if err != nil {
		return StartResult{}, err
	}
	if err := s.Store.InTx(ctx, func(q *db.Queries) error {
		_, err := q.CreateSSOState(ctx, db.CreateSSOStateParams{
			ID: string(ids.New[ids.ID]("sos")), ConnectionID: row.ID,
			StateHash: digest(relayState), NonceHash: digest(nonce),
			PkceVerifierCiphertext: verifierCiphertext, RedirectUri: redirectURI,
			ExpiresAt: pgtype.Timestamptz{Time: expiresAt, Valid: true},
			RequestID: pgtype.Text{String: request.ID, Valid: true},
		})
		return err
	}); err != nil {
		return StartResult{}, err
	}
	result := StartResult{State: relayState, ExpiresAt: expiresAt, AuthorizationMethod: "GET"}
	if row.SamlSsoBinding.String == saml2.BindingHttpPost {
		result.AuthorizationMethod = "POST"
		result.AuthorizationURL = row.SamlSsoUrl.String
		result.SAMLRequest = base64.StdEncoding.EncodeToString(requestBytes)
		result.RelayState = relayState
		return result, nil
	}
	result.AuthorizationURL, err = provider.BuildAuthURLRedirect(relayState, document)
	if err != nil {
		return StartResult{}, apierr.New("temporarily_unavailable", "SAML authorization request could not be built")
	}
	return result, nil
}

func (s *Service) Callback(ctx context.Context, in CallbackInput) (account.AuthResult, error) {
	in.ConnectionID = strings.TrimSpace(in.ConnectionID)
	in.State = strings.TrimSpace(in.State)
	if in.ConnectionID == "" {
		return account.AuthResult{}, apierr.New("invalid_request", "connection_id is required")
	}
	row, err := s.Store.Queries().GetSSOConnection(ctx, db.GetSSOConnectionParams{ID: in.ConnectionID})
	if errors.Is(err, pgx.ErrNoRows) {
		return account.AuthResult{}, apierr.New("invalid_grant", "SSO state is invalid or expired")
	}
	if err != nil {
		return account.AuthResult{}, err
	}
	if row.Status != "active" {
		return account.AuthResult{}, apierr.New("forbidden", "SSO connection is disabled")
	}
	if row.Provider == "saml" {
		if in.RedirectURI != "" && in.RedirectURI != row.RedirectUri {
			return account.AuthResult{}, apierr.New("invalid_grant", "redirect_uri does not match the SSO connection")
		}
		if in.SAMLResponse == "" {
			// The shared JSON callback carries the encoded SAML response in code.
			in.SAMLResponse = in.Code
		}
		return s.callbackSAML(ctx, row, in)
	}
	in.Code = strings.TrimSpace(in.Code)
	in.RedirectURI = strings.TrimSpace(in.RedirectURI)
	if in.State == "" || in.Code == "" {
		return account.AuthResult{}, apierr.New("invalid_request", "state and code are required")
	}
	var state db.SsoState
	err = s.Store.InTx(ctx, func(q *db.Queries) error {
		state, err = q.LockSSOStateByHash(ctx, db.LockSSOStateByHashParams{StateHash: digest(in.State)})
		if errors.Is(err, pgx.ErrNoRows) {
			return apierr.New("invalid_grant", "SSO state is invalid or expired")
		}
		if err != nil {
			return err
		}
		if state.ConnectionID != row.ID || state.ConsumedAt.Valid || !state.ExpiresAt.Time.After(time.Now().UTC()) {
			return apierr.New("invalid_grant", "SSO state is invalid or expired")
		}
		if in.RedirectURI != "" && in.RedirectURI != state.RedirectUri {
			return apierr.New("invalid_grant", "redirect_uri does not match the SSO request")
		}
		return nil
	})
	if err != nil {
		return account.AuthResult{}, err
	}
	verifier, err := s.open(state.PkceVerifierCiphertext, pkceVerifierAAD)
	if err != nil {
		return account.AuthResult{}, apierr.New("temporarily_unavailable", "SSO state is unavailable")
	}
	provider, err := s.discovery(ctx, row.Issuer)
	if err != nil {
		return account.AuthResult{}, err
	}
	clientSecret, err := s.open(row.ClientSecretCiphertext, clientSecretAAD)
	if err != nil {
		return account.AuthResult{}, apierr.New("temporarily_unavailable", "SSO connection is unavailable")
	}
	config := oauth2.Config{ClientID: row.ClientID, ClientSecret: string(clientSecret), Endpoint: provider.Endpoint(), RedirectURL: state.RedirectUri, Scopes: []string{"openid", "email", "profile"}}
	exchangeCtx := context.WithValue(ctx, oauth2.HTTPClient, s.httpClient())
	token, err := config.Exchange(exchangeCtx, in.Code, oauth2.SetAuthURLParam("code_verifier", string(verifier)))
	if err != nil {
		return account.AuthResult{}, apierr.New("invalid_grant", "the OIDC authorization code is invalid")
	}
	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok || strings.TrimSpace(rawIDToken) == "" {
		return account.AuthResult{}, apierr.New("invalid_grant", "the OIDC provider did not return an ID token")
	}
	claims, err := parseIDToken(exchangeCtx, provider, rawIDToken, row.ClientID, row.GroupsClaim)
	if err != nil {
		return account.AuthResult{}, apierr.New("invalid_grant", "the OIDC ID token is invalid")
	}
	if claims.Nonce == "" || !equalDigest(state.NonceHash, claims.Nonce) || claims.Subject == "" || len(claims.Subject) > maxExternalSubjectLen || claims.Email == "" || !claims.EmailVerified {
		return account.AuthResult{}, apierr.New("invalid_grant", "the OIDC identity is not valid for this connection")
	}
	result, err := s.finishCallback(ctx, row, state, claims)
	if err != nil {
		return account.AuthResult{}, err
	}
	return result, nil
}

func (s *Service) callbackSAML(ctx context.Context, row db.SsoConnection, in CallbackInput) (account.AuthResult, error) {
	inResponseTo, keyHintMissing, err := parseSAMLResponseHints(in.SAMLResponse)
	if err != nil {
		return account.AuthResult{}, err
	}
	provider, err := s.samlProvider(row)
	if err != nil {
		return account.AuthResult{}, err
	}
	var state db.SsoState
	if strings.TrimSpace(in.State) != "" {
		err = s.Store.InTx(ctx, func(q *db.Queries) error {
			state, err = q.LockSSOStateByHash(ctx, db.LockSSOStateByHashParams{StateHash: digest(strings.TrimSpace(in.State))})
			if errors.Is(err, pgx.ErrNoRows) {
				return apierr.New("invalid_grant", "SAML state is invalid or expired")
			}
			if err != nil {
				return err
			}
			if state.ConnectionID != row.ID || state.ConsumedAt.Valid || !state.ExpiresAt.Time.After(time.Now().UTC()) {
				return apierr.New("invalid_grant", "SAML state is invalid or expired")
			}
			if state.RequestID.Valid && inResponseTo != state.RequestID.String {
				return apierr.New("invalid_grant", "the SAML response does not match the authorization request")
			}
			return nil
		})
		if err != nil {
			return account.AuthResult{}, err
		}
	} else if inResponseTo != "" {
		return account.AuthResult{}, apierr.New("invalid_grant", "an unsolicited SAML response cannot contain InResponseTo")
	}
	info, err := provider.verify(ctx, in.SAMLResponse, keyHintMissing)
	if err != nil {
		return account.AuthResult{}, err
	}
	email := firstSAMLValue(info.Values, "email", "Email", "mail", "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress")
	if email == "" && strings.Contains(info.NameID, "@") {
		email = info.NameID
	}
	if !validSAMLIdentity(email) || info.NameID == "" || len(info.NameID) > maxExternalSubjectLen {
		return account.AuthResult{}, apierr.New("invalid_grant", "the SAML identity is not valid for this connection")
	}
	claims := idTokenClaims{
		samlProof: &samlLoginProof{provider: provider, response: in.SAMLResponse, keyHintMissing: keyHintMissing},
		Subject:   info.NameID, Email: email, EmailVerified: true,
		Name: firstSAMLValue(info.Values, "displayName", "DisplayName", "name", "Name"),
	}
	claims.SAMLAttributes = make(map[string][]string, len(info.Values))
	if len(info.Assertions) != 1 {
		return account.AuthResult{}, directoryIdentityUnavailable()
	}
	if statement := info.Assertions[0].AttributeStatement; statement != nil {
		for _, attribute := range statement.Attributes {
			for _, value := range attribute.Values {
				claims.SAMLAttributes[attribute.Name] = append(claims.SAMLAttributes[attribute.Name], value.Value)
			}
		}
	}
	claims.Groups = claims.SAMLAttributes[row.GroupsClaim]
	return s.finishCallback(ctx, row, state, claims)
}

func (s *Service) samlProvider(row db.SsoConnection) (*samlLoginProvider, error) {
	if !row.SamlEntityID.Valid || !row.SamlSsoUrl.Valid || !row.SamlSsoBinding.Valid || !row.SamlIdpCertificate.Valid {
		return nil, apierr.New("temporarily_unavailable", "SAML connection metadata is unavailable")
	}
	certificates, err := currentSAMLSigningCertificates(row.SamlIdpCertificate.String, time.Now())
	if err != nil {
		return nil, err
	}
	entityID := s.samlEntityID(row.ID)
	provider := &samlLoginProvider{SAMLServiceProvider: &saml2.SAMLServiceProvider{
		IdentityProviderSSOURL: row.SamlSsoUrl.String, IdentityProviderSSOBinding: row.SamlSsoBinding.String,
		IdentityProviderIssuer: row.SamlEntityID.String, AssertionConsumerServiceURL: row.RedirectUri,
		ServiceProviderIssuer: entityID, AudienceURI: entityID,
		AllowMissingAttributes: false, MaximumDecompressedBodySize: 5 * 1024 * 1024, MaximumXMLTokens: 50000,
	}}
	provider.setTrust(certificates)
	return provider, nil
}

func (s *Service) samlEntityID(connectionID string) string {
	base := strings.TrimRight(strings.TrimSpace(s.Issuer), "/")
	if base == "" {
		base = "https://auth.example.com"
	}
	return base + "/saml/" + connectionID
}

func firstSAMLValue(values saml2.Values, names ...string) string {
	for _, name := range names {
		if value := strings.TrimSpace(values.Get(name)); value != "" {
			return value
		}
	}
	return ""
}

func validSAMLIdentity(email string) bool {
	email = strings.TrimSpace(strings.ToLower(email))
	if email == "" || len(email) > 320 || strings.ContainsAny(email, "\r\n") {
		return false
	}
	at := strings.LastIndexByte(email, '@')
	return at > 0 && at < len(email)-1 && !strings.Contains(email[at+1:], " ")
}

func (s *Service) finishCallback(ctx context.Context, connection db.SsoConnection, state db.SsoState, claims idTokenClaims) (account.AuthResult, error) {
	email := strings.TrimSpace(strings.ToLower(claims.Email))
	if email == "" || len(email) > 320 || strings.ContainsAny(email, "\r\n") {
		return account.AuthResult{}, apierr.New("invalid_grant", "the OIDC email claim is invalid")
	}
	if len(claims.Groups) > maxIdentityGroups {
		return account.AuthResult{}, apierr.New("invalid_grant", "the OIDC groups claim is too large")
	}
	hint, err := s.directorySSOHint(ctx, connection, claims)
	if err != nil {
		return account.AuthResult{}, err
	}
	var userID, memberID string
	var userEmail, userStatus string
	userName := displayName(claims, email)
	var userCreated time.Time
	if s.Sessions == nil || s.Sessions.Settings == nil {
		return account.AuthResult{}, apierr.New("temporarily_unavailable", "session service is unavailable")
	}
	sessionSettings, err := s.Sessions.Settings(ctx)
	if err != nil {
		return account.AuthResult{}, err
	}
	var tokens session.Tokens
	err = s.Store.InTx(ctx, func(q *db.Queries) error {
		plan, err := lockSSOLoginTx(ctx, q, connection, claims, hint)
		if err != nil {
			return err
		}
		lockedConnection, err := q.LockSSOConnection(ctx, db.LockSSOConnectionParams{ID: connection.ID})
		if err != nil {
			return err
		}
		if lockedConnection.Status != "active" {
			return apierr.New("forbidden", "SSO connection is disabled")
		}
		if lockedConnection.ConfiguredByMemberID != connection.ConfiguredByMemberID || lockedConnection.ConfiguredByUserID != connection.ConfiguredByUserID ||
			lockedConnection.GroupsClaim != connection.GroupsClaim || !bytes.Equal(lockedConnection.RoleMappings, connection.RoleMappings) {
			return apierr.New("conflict", "SSO mapping changed; restart sign-in")
		}
		active, err := q.AreSpaceAncestorsActive(ctx, db.AreSpaceAncestorsActiveParams{SpaceID: connection.SpaceID})
		if err != nil {
			return err
		}
		if !active {
			return directoryIdentityUnavailable()
		}
		if state.ID != "" {
			lockedState, err := q.LockSSOStateByHash(ctx, db.LockSSOStateByHashParams{StateHash: state.StateHash})
			if err != nil {
				return err
			}
			if lockedState.ConsumedAt.Valid || !lockedState.ExpiresAt.Time.After(time.Now().UTC()) || lockedState.ConnectionID != connection.ID {
				return apierr.New("invalid_grant", "SSO state is invalid or expired")
			}
			if err := q.ConsumeSSOState(ctx, db.ConsumeSSOStateParams{ID: lockedState.ID}); err != nil {
				return err
			}
		}
		newMembership := false
		if hint != nil {
			identity, err := linkDirectoryIdentityTx(ctx, q, connection, hint, claims)
			if err != nil {
				return err
			}
			userID, memberID = identity.UserID, identity.MemberID
			userEmail, userStatus, userCreated, userName = identity.Email, identity.Status, identity.CreatedAt.Time, identity.DisplayName
		} else {
			external, err := q.GetExternalIdentity(ctx, db.GetExternalIdentityParams{Issuer: connection.Issuer, Subject: claims.Subject})
			if (err == nil || errors.Is(err, pgx.ErrNoRows)) && external.UserID != plan.userID {
				return apierr.New("conflict", "SSO identity changed; restart sign-in")
			}
			if errors.Is(err, pgx.ErrNoRows) {
				if existing, emailErr := q.GetUserByEmail(ctx, db.GetUserByEmailParams{EmailNormalized: email}); emailErr == nil {
					_ = existing
					return apierr.New("conflict", "an account with this email requires explicit SSO identity linking")
				} else if !errors.Is(emailErr, pgx.ErrNoRows) {
					return emailErr
				}
				passwordHash, hashErr := s.passwordHash()
				if hashErr != nil {
					return hashErr
				}
				created, createErr := q.CreateUser(ctx, db.CreateUserParams{ID: string(ids.New[ids.UserID]("usr")), Email: email, EmailNormalized: email, PasswordHash: passwordHash, Status: "active"})
				if createErr != nil {
					return createErr
				}
				userID, userEmail, userStatus, userCreated = created.ID, created.Email, created.Status, created.CreatedAt.Time
				if err := q.MarkExternalUserVerified(ctx, db.MarkExternalUserVerifiedParams{ID: userID}); err != nil {
					return err
				}
				if _, err := q.CreateExternalIdentity(ctx, db.CreateExternalIdentityParams{ID: string(ids.New[ids.ID]("ext")), UserID: userID, Issuer: connection.Issuer, Subject: claims.Subject}); err != nil {
					return err
				}
			} else if err != nil {
				return err
			} else {
				if external.DirectoryUserID.Valid {
					return directoryIdentityUnavailable()
				}
				userID = external.UserID
				user, userErr := q.GetUserByID(ctx, db.GetUserByIDParams{ID: userID})
				if userErr != nil {
					return userErr
				}
				if user.Status != "active" {
					return apierr.New("forbidden", "the linked account is not active")
				}
				userEmail, userStatus, userCreated = user.Email, user.Status, user.CreatedAt.Time
			}
			member, memberErr := q.GetSSOMembershipForUser(ctx, db.GetSSOMembershipForUserParams{UserID: userID, SpaceID: connection.SpaceID})
			newMembership = errors.Is(memberErr, pgx.ErrNoRows)
			if memberErr != nil && !newMembership {
				return memberErr
			}
			if member.ID != plan.memberID || !newMembership && !member.Active {
				return apierr.New("invalid_grant", "the SSO identity is not valid for this connection")
			}
			if newMembership {
				if !slices.ContainsFunc(plan.roles, func(role db.LockSSOMappingRolesRow) bool { return role.Name == "member" }) {
					return apierr.New("temporarily_unavailable", "the Space has no default member role")
				}
				if s.Authorization == nil {
					return apierr.New("unavailable", "authorization is unavailable")
				}
				if err := s.Authorization.CheckSSOLoginGrantsTx(ctx, q, connection.ConfiguredByMemberID.String, connection.ConfiguredByUserID.String,
					connection.SpaceID, connection.ID, plan.mapped, plan.roles); err != nil {
					return err
				}
				createdMember, createErr := q.CreateMemberWithPolicy(ctx, db.CreateMemberWithPolicyParams{ID: string(ids.New[ids.MemberID]("mem")), SpaceID: connection.SpaceID, Name: displayName(claims, email), Type: "human", BindingPolicy: "single"})
				if createErr != nil {
					return createErr
				}
				memberID = createdMember.ID
				if err := q.LinkUserMember(ctx, db.LinkUserMemberParams{UserID: userID, MemberID: memberID}); err != nil {
					return err
				}
			} else {
				memberID = member.ID
			}
		}
		if newMembership {
			for _, role := range plan.roles {
				if _, err := q.CreateGrant(ctx, db.CreateGrantParams{
					ID: string(ids.New[ids.GrantID]("grt")), SpaceID: connection.SpaceID,
					RoleID: pgtype.Text{String: role.ID, Valid: true}, GranteeMemberID: pgtype.Text{String: memberID, Valid: true},
					Scope: "space", AnchorSpaceID: pgtype.Text{String: connection.SpaceID, Valid: true}, GrantedBy: connection.ID,
				}); err != nil {
					return err
				}
			}
		}
		space, err := q.GetSpace(ctx, db.GetSpaceParams{ID: connection.SpaceID})
		if err != nil {
			return err
		}
		tokens, err = s.Sessions.CreateForSSOTx(ctx, q, sessionSettings, userID, memberID, connection.ID, connection.Provider)
		if err != nil {
			return err
		}
		metadata := map[string]string{"provider": connection.Provider, "subject_hash": hexDigest(claims.Subject), "new_membership": fmt.Sprintf("%t", newMembership)}
		if hint != nil {
			metadata["directory_id"], metadata["directory_user_id"] = hint.directory.ID, hint.user.ID
		}
		if err := audit.WriteSecurityEvent(ctx, q, audit.SecurityEvent{
			ActorType: "sso", ActorID: connection.ID, MemberID: memberID, UserID: userID,
			Action: "auth.sso.login", Outcome: "success", CredentialType: connection.Provider,
			Resource:      audit.Resource{Type: "sso_connection", ID: connection.ID, SpaceID: connection.SpaceID},
			PolicyVersion: space.PolicyVersion,
			Metadata:      metadata,
		}); err != nil {
			return err
		}
		if connection.Provider == "saml" {
			// Identity and audit writes may wait on locks after signature verification.
			if lockedConnection.SamlIdpCertificate != connection.SamlIdpCertificate {
				return apierr.New("conflict", "SSO signing certificate changed; restart sign-in")
			}
			return claims.samlProof.recheck(ctx)
		}
		return nil
	})
	if err != nil {
		return account.AuthResult{}, normalizeConnectionError(err)
	}
	return account.AuthResult{User: account.User{ID: userID, Email: userEmail, EmailVerified: true, Status: userStatus, DisplayName: userName, CreatedAt: userCreated}, Tokens: &tokens}, nil
}

func (s *Service) discovery(ctx context.Context, issuer string) (*oidc.Provider, error) {
	if err := validateIssuer(issuer); err != nil {
		return nil, err
	}
	client := s.httpClient()
	requestCtx := context.WithValue(ctx, oauth2.HTTPClient, client)
	discoveryURL := strings.TrimRight(issuer, "/") + "/.well-known/openid-configuration"
	req, err := http.NewRequestWithContext(requestCtx, http.MethodGet, discoveryURL, nil)
	if err != nil {
		return nil, apierr.New("temporarily_unavailable", "OIDC discovery is unavailable")
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, apierr.New("temporarily_unavailable", "OIDC discovery is unavailable")
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, apierr.New("temporarily_unavailable", "OIDC discovery is unavailable")
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxDiscoveryBytes+1))
	if err != nil || len(body) > maxDiscoveryBytes {
		return nil, apierr.New("temporarily_unavailable", "OIDC discovery is invalid")
	}
	var doc oidc.ProviderConfig
	if err := json.Unmarshal(body, &doc); err != nil || doc.IssuerURL != issuer {
		return nil, apierr.New("temporarily_unavailable", "OIDC discovery is invalid")
	}
	for _, endpoint := range []string{doc.AuthURL, doc.TokenURL, doc.JWKSURL} {
		if err := validateEndpoint(endpoint, issuer); err != nil {
			return nil, apierr.New("temporarily_unavailable", "OIDC discovery contains an unsafe endpoint")
		}
	}
	if doc.Algorithms != nil {
		doc.Algorithms = slices.DeleteFunc(doc.Algorithms, func(alg string) bool {
			switch alg {
			case oidc.RS256, oidc.RS384, oidc.RS512, oidc.ES256, oidc.ES384, oidc.ES512,
				oidc.PS256, oidc.PS384, oidc.PS512, oidc.EdDSA:
				return false
			default:
				return true
			}
		})
		if len(doc.Algorithms) == 0 {
			return nil, apierr.New("temporarily_unavailable", "OIDC discovery contains no supported signing algorithm")
		}
	}
	// The code exchange and signature verifier must use the metadata checked above.
	return doc.NewProvider(requestCtx), nil
}

func parseIDToken(ctx context.Context, provider *oidc.Provider, raw, clientID, groupsClaim string) (idTokenClaims, error) {
	verifier := provider.Verifier(&oidc.Config{ClientID: clientID})
	token, err := verifier.Verify(ctx, raw)
	if err != nil {
		return idTokenClaims{}, err
	}
	var claims idTokenClaims
	if err := token.Claims(&claims); err != nil {
		return idTokenClaims{}, err
	}
	if err := token.Claims(&claims.VerifiedClaims); err != nil {
		return idTokenClaims{}, err
	}
	if value, ok := claims.VerifiedClaims[groupsClaim]; ok {
		if err := json.Unmarshal(value, &claims.Groups); err != nil {
			return idTokenClaims{}, err
		}
	}
	return claims, nil
}

func (s *Service) passwordHash() (string, error) {
	password := make([]byte, 32)
	if _, err := rand.Read(password); err != nil {
		return "", err
	}
	hasher := s.Passwords
	if hasher.Time == 0 {
		hasher = security.DefaultPasswordHasher()
	}
	return hasher.Hash(base64.RawURLEncoding.EncodeToString(password))
}

func (s *Service) httpClient() *http.Client {
	if s.HTTPClient != nil {
		return s.HTTPClient
	}
	return &http.Client{Timeout: 10 * time.Second, CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }}
}

func (s *Service) seal(plain []byte, aad string) ([]byte, error) {
	aead, err := s.aead()
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return aead.Seal(nonce, nonce, plain, []byte(aad)), nil
}

func (s *Service) open(ciphertext []byte, aad string) ([]byte, error) {
	aead, err := s.aead()
	if err != nil || len(ciphertext) < aead.NonceSize() {
		if err == nil {
			err = errors.New("ciphertext is too short")
		}
		return nil, err
	}
	return aead.Open(nil, ciphertext[:aead.NonceSize()], ciphertext[aead.NonceSize():], []byte(aad))
}

func (s *Service) aead() (cipher.AEAD, error) {
	key := []byte(s.DataKey.Value())
	if len(key) != 32 {
		return nil, errors.New("enterprise data key must be 32 bytes")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

func randomOpaque(prefix string) (string, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return prefix + base64.RawURLEncoding.EncodeToString(raw), nil
}

func digest(value string) []byte {
	sum := sha256.Sum256([]byte(value))
	return sum[:]
}

func equalDigest(expected []byte, value string) bool {
	actual := digest(value)
	return len(expected) == len(actual) && subtleCompare(expected, actual)
}

func subtleCompare(a, b []byte) bool {
	return subtle.ConstantTimeCompare(a, b) == 1
}

func hexDigest(value string) string {
	sum := digest(value)
	return fmt.Sprintf("%x", sum)
}

func validateIssuer(raw string) error {
	u, err := url.Parse(raw)
	if err != nil || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || !isSecureOIDCURL(u) {
		return apierr.New("validation_failed", "issuer must be an HTTPS URL without user info, query, or fragment")
	}
	return nil
}

func parseSAMLMetadata(raw string) (samlConnectionDetails, error) {
	var metadata types.EntityDescriptor
	_ = xml.Unmarshal([]byte(raw), &metadata)
	if metadata.IDPSSODescriptor == nil {
		var bundle struct {
			Descriptors []types.EntityDescriptor `xml:"EntityDescriptor"`
		}
		if err := xml.Unmarshal([]byte(raw), &bundle); err != nil || len(bundle.Descriptors) == 0 {
			return samlConnectionDetails{}, apierr.New("validation_failed", "SAML metadata does not contain an IdP descriptor")
		}
		var found *types.EntityDescriptor
		for i := range bundle.Descriptors {
			if bundle.Descriptors[i].IDPSSODescriptor == nil {
				continue
			}
			if found != nil {
				return samlConnectionDetails{}, apierr.New("validation_failed", "SAML metadata contains multiple IdP descriptors")
			}
			found = &bundle.Descriptors[i]
		}
		if found == nil {
			return samlConnectionDetails{}, apierr.New("validation_failed", "SAML metadata does not contain an IdP descriptor")
		}
		metadata = *found
	}
	if metadata.EntityID == "" || metadata.IDPSSODescriptor == nil {
		return samlConnectionDetails{}, apierr.New("validation_failed", "SAML metadata does not contain an IdP descriptor")
	}
	if !metadata.ValidUntil.IsZero() && !metadata.ValidUntil.After(time.Now().UTC()) {
		return samlConnectionDetails{}, apierr.New("validation_failed", "SAML metadata has expired")
	}
	var endpoint types.SingleSignOnService
	for _, candidate := range metadata.IDPSSODescriptor.SingleSignOnServices {
		if candidate.Binding == saml2.BindingHttpRedirect {
			endpoint = candidate
			break
		}
		if endpoint.Location == "" && candidate.Binding == saml2.BindingHttpPost {
			endpoint = candidate
		}
	}
	if endpoint.Location == "" || (endpoint.Binding != saml2.BindingHttpRedirect && endpoint.Binding != saml2.BindingHttpPost) {
		return samlConnectionDetails{}, apierr.New("validation_failed", "SAML metadata has no supported SSO endpoint")
	}
	if err := validateSAMLURL(endpoint.Location); err != nil {
		return samlConnectionDetails{}, err
	}
	var certificates strings.Builder
	seen := make(map[string]bool)
	base64Whitespace := strings.NewReplacer(" ", "", "\t", "")
	now := time.Now()
	active := false
	for _, descriptor := range metadata.IDPSSODescriptor.KeyDescriptors {
		if descriptor.Use != "" && descriptor.Use != "signing" {
			continue
		}
		for _, encoded := range descriptor.KeyInfo.X509Data.X509Certificates {
			if strings.TrimSpace(encoded.Data) == "" {
				continue
			}
			decoded, err := base64.StdEncoding.DecodeString(base64Whitespace.Replace(encoded.Data))
			if err != nil {
				return samlConnectionDetails{}, apierr.New("validation_failed", "SAML metadata certificate is invalid")
			}
			cert, err := x509.ParseCertificate(decoded)
			if err != nil {
				return samlConnectionDetails{}, apierr.New("validation_failed", "SAML metadata certificate is invalid or expired")
			}
			active = active || certificateValidAt(cert, now)
			if !seen[string(decoded)] {
				seen[string(decoded)] = true
				certificates.Write(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: decoded}))
			}
			// Additional X509Certificate elements can describe the signing key's chain.
			// Only a separate signing KeyDescriptor introduces another signing key.
			break
		}
	}
	if certificates.Len() == 0 {
		return samlConnectionDetails{}, apierr.New("validation_failed", "SAML metadata has no signing certificate")
	}
	if !active {
		return samlConnectionDetails{}, apierr.New("validation_failed", "SAML metadata certificate is invalid or expired")
	}
	return samlConnectionDetails{
		EntityID: metadata.EntityID, SSOURL: endpoint.Location, Binding: endpoint.Binding,
		Certificate: certificates.String(),
	}, nil
}

func validateSAMLURL(raw string) error {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return apierr.New("validation_failed", "SAML endpoint must be an HTTPS URL without user info, query, or fragment")
	}
	return nil
}

func validateEndpoint(raw, issuer string) error {
	u, err := url.Parse(raw)
	if err != nil || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || !isSecureOIDCURL(u) {
		return errors.New("unsafe OIDC endpoint")
	}
	base, err := url.Parse(issuer)
	if err != nil || u.Scheme != base.Scheme || !strings.EqualFold(u.Hostname(), base.Hostname()) || u.Port() != base.Port() {
		return errors.New("OIDC endpoint origin differs from issuer")
	}
	return nil
}

func validateRedirectURI(raw string) error {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme == "" || u.Hostname() == "" || u.User != nil || u.Fragment != "" || strings.ContainsAny(raw, "*\r\n\t ") {
		return apierr.New("validation_failed", "redirect_uri must be an exact URL without wildcards")
	}
	if !isSecureOIDCURL(u) {
		return apierr.New("validation_failed", "redirect_uri must use HTTPS")
	}
	return nil
}

func isSecureOIDCURL(u *url.URL) bool {
	return u.Scheme == "https" || u.Scheme == "http" && u.Hostname() == "localhost"
}

func displayName(claims idTokenClaims, email string) string {
	name := strings.TrimSpace(claims.Name)
	if name == "" {
		name = strings.TrimSpace(strings.SplitN(email, "@", 2)[0])
	}
	if len(name) > 128 {
		name = name[:128]
	}
	return name
}

func connectionFromPublicRow(row db.ListSSOConnectionsRow) (Connection, error) {
	mappings := map[string]string{}
	if err := json.Unmarshal(row.RoleMappings, &mappings); err != nil || mappings == nil {
		return Connection{}, apierr.New("UNAVAILABLE", "SSO connection configuration is unavailable")
	}
	return Connection{
		ID: row.ID, SpaceID: row.SpaceID, Name: row.Name, Provider: row.Provider,
		Issuer: row.Issuer, ClientID: row.ClientID, RedirectURI: row.RedirectUri,
		GroupsClaim: row.GroupsClaim, RoleMappings: mappings, Status: row.Status,
		CoversSubtree: row.CoversSubtree, CreatedAt: row.CreatedAt.Time, UpdatedAt: row.UpdatedAt.Time,
	}, nil
}

func normalizeConnectionError(err error) error {
	if err == nil {
		return nil
	}
	var public *apierr.Error
	if errors.As(err, &public) {
		return public
	}
	if strings.Contains(strings.ToLower(err.Error()), "duplicate") || strings.Contains(strings.ToLower(err.Error()), "unique") {
		return apierr.New("conflict", "an SSO connection or identity already exists")
	}
	return err
}

func domainFromRow(row db.CreateSSODomainRow) Domain {
	out := Domain{ID: row.ID, SpaceID: row.SpaceID, Domain: row.Domain, ForceSSO: row.ForceSso, CoversSubtree: row.CoversSubtree, Status: row.Status, CreatedAt: row.CreatedAt.Time, UpdatedAt: row.UpdatedAt.Time}
	if row.ConnectionID.Valid {
		out.ConnectionID = row.ConnectionID.String
	}
	if row.VerifiedAt.Valid {
		out.VerifiedAt = row.VerifiedAt.Time
	}
	return out
}

func domainFromListRow(row db.ListSSODomainsRow) Domain {
	out := Domain{ID: row.ID, SpaceID: row.SpaceID, Domain: row.Domain, ForceSSO: row.ForceSso, CoversSubtree: row.CoversSubtree, Status: row.Status, CreatedAt: row.CreatedAt.Time, UpdatedAt: row.UpdatedAt.Time}
	if row.ConnectionID.Valid {
		out.ConnectionID = row.ConnectionID.String
	}
	if row.VerifiedAt.Valid {
		out.VerifiedAt = row.VerifiedAt.Time
	}
	return out
}

func normalizeDomain(raw string) (string, error) {
	domain := strings.TrimSpace(strings.ToLower(strings.TrimSuffix(raw, ".")))
	if domain == "" || len(domain) > 253 || strings.ContainsAny(domain, "@/\\\r\n\t ") {
		return "", apierr.New("validation_failed", "domain is invalid")
	}
	labels := strings.Split(domain, ".")
	if len(labels) < 2 {
		return "", apierr.New("validation_failed", "domain must contain a public suffix")
	}
	for _, label := range labels {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return "", apierr.New("validation_failed", "domain is invalid")
		}
		for _, r := range label {
			if (r < 'a' || r > 'z') && (r < '0' || r > '9') && r != '-' {
				return "", apierr.New("validation_failed", "domain must use ASCII DNS labels")
			}
		}
	}
	return domain, nil
}

func splitEmailDomain(raw string) (string, string, error) {
	email := strings.TrimSpace(strings.ToLower(raw))
	at := strings.LastIndexByte(email, '@')
	if at <= 0 || at == len(email)-1 {
		return "", "", apierr.New("invalid_request", "a valid email is required")
	}
	domain, err := normalizeDomain(email[at+1:])
	if err != nil {
		return "", "", err
	}
	return email[:at], domain, nil
}
