package operator

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"sort"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/plystra/auth/internal/account"
	"github.com/plystra/auth/internal/apierr"
	"github.com/plystra/auth/internal/application"
	"github.com/plystra/auth/internal/audit"
	"github.com/plystra/auth/internal/db"
	"github.com/plystra/auth/internal/factor"
	"github.com/plystra/auth/internal/ids"
	"github.com/plystra/auth/internal/secret"
	"github.com/plystra/auth/internal/security"
	"github.com/plystra/auth/internal/store"
)

const accessTTL = 10 * time.Minute

type Service struct {
	Store     *store.Store
	Passwords security.PasswordHasher
	Factors   *factor.Service
	HMACKeys  [][]byte
	dummyHash string
}

type Session struct {
	Token        secret.String
	ID           string
	UserID       string
	Capabilities []string
	ExpiresAt    time.Time
}

// Capability names are intentionally explicit. Unknown names are rejected so a
// typo cannot silently create an operator permission that no route enforces.
var knownCapabilities = map[string]struct{}{
	"ops:session":          {},
	"ops:settings:read":    {},
	"ops:settings:write":   {},
	"ops:operators:read":   {},
	"ops:operators:manage": {},
	"ops:users:manage":     {},
}

type Operator struct {
	UserID       string     `json:"user_id"`
	Email        string     `json:"email"`
	Capabilities []string   `json:"capabilities"`
	Active       bool       `json:"active"`
	Disabled     bool       `json:"disabled"`
	CreatedAt    time.Time  `json:"created_at"`
	LastStepUpAt *time.Time `json:"last_step_up_at,omitempty"`
}

type OperatorCreate struct {
	Operator   Operator           `json:"operator"`
	Enrollment *factor.Enrollment `json:"mfa_enrollment,omitempty"`
}

type BootstrapResult struct {
	UserID     string
	TOTPSecret string
	APIKey     string
}

func New(st *store.Store, factors *factor.Service, keys [][]byte) (*Service, error) {
	if st == nil {
		return nil, errors.New("operator store is required")
	}
	if factors == nil {
		return nil, errors.New("operator MFA service is required")
	}
	if len(keys) == 0 {
		return nil, errors.New("operator HMAC key is required")
	}
	for _, key := range keys {
		if len(key) < 32 {
			return nil, errors.New("operator HMAC key must be at least 32 bytes")
		}
	}
	s := &Service{Store: st, Factors: factors, HMACKeys: keys, Passwords: security.DefaultPasswordHasher()}
	dummy, err := newToken()
	if err != nil {
		return nil, err
	}
	s.dummyHash, err = s.Passwords.Hash(dummy.Value())
	return s, err
}

// Bootstrap creates the first full-capability operator while holding the
// database bootstrap lock. It is intentionally usable only before any
// operator exists; subsequent operator changes go through the operations
// session and capability checks.
func (s *Service) Bootstrap(ctx context.Context, userID string) (BootstrapResult, error) {
	userID = strings.TrimSpace(userID)
	if userID == "" {
		return BootstrapResult{}, apierr.New("VALIDATION_FAILED", "user_id is required")
	}
	var result BootstrapResult
	err := s.Store.InTx(ctx, func(q *db.Queries) error {
		if err := q.LockOperatorBootstrap(ctx); err != nil {
			return err
		}
		count, err := q.CountOperators(ctx)
		if err != nil {
			return err
		}
		if count != 0 {
			return apierr.New("CONFLICT", "an operator already exists; use the operations plane")
		}
		user, err := q.GetUserByID(ctx, db.GetUserByIDParams{ID: userID})
		if errors.Is(err, pgx.ErrNoRows) {
			return apierr.New("NOT_FOUND", "bootstrap user was not found")
		}
		if err != nil {
			return err
		}
		if user.DisabledAt.Valid || user.Status != "active" {
			return apierr.New("CONFLICT", "bootstrap user is not active")
		}
		caps, err := json.Marshal([]string{"*"})
		if err != nil {
			return err
		}
		rawKey, prefix, keyHash, err := application.GenerateSecret()
		if err != nil {
			return err
		}
		if _, err := q.CreateAPIKey(ctx, db.CreateAPIKeyParams{
			ID: string(ids.New[ids.APIKeyID]("key")), ApplicationID: "app_01h00000000000000000000000", Name: "bootstrap", Prefix: prefix, SecretHash: keyHash,
			Scopes: []byte(`["auth.authz:check","auth.tokens:introspect"]`), ExpiresAt: pgtype.Timestamptz{Time: time.Now().UTC().Add(365 * 24 * time.Hour), Valid: true},
		}); err != nil {
			return err
		}
		if err := q.CreateOperator(ctx, db.CreateOperatorParams{UserID: user.ID, Capabilities: caps}); err != nil {
			return err
		}
		enrollment, err := s.Factors.BeginTOTPTx(ctx, q, user.ID, user.Email)
		if err != nil {
			return err
		}
		result = BootstrapResult{UserID: user.ID, TOTPSecret: enrollment.Secret.Value(), APIKey: rawKey}
		return audit.Write(ctx, q, "operator", user.ID, "ops.operator.bootstrap", user.ID, "success")
	})
	return result, err
}

func (s *Service) limit(ctx context.Context, kind, value string, count int) error {
	// Account and IP identifiers are not retained in rate-limit bucket keys.
	digest := hashWithKey(kind+":"+value, s.HMACKeys[0])
	ok, err := (store.RateLimiter{Store: s.Store}).Allow(ctx, "ops:"+kind+":"+base64.RawURLEncoding.EncodeToString(digest), count, time.Minute)
	if err != nil {
		return err
	}
	if !ok {
		return apierr.New("RATE_LIMITED", "Too many authentication attempts. Try again later.")
	}
	return nil
}

func (s *Service) SignIn(ctx context.Context, email, password, code string, ip net.IP, userAgent string) (Session, error) {
	email = strings.ToLower(strings.TrimSpace(email))
	for _, bucket := range []struct {
		kind, value string
		count       int
	}{
		{"ip", ip.String(), 30}, {"account", email, 10}, {"pair", ip.String() + ":" + email, 5},
	} {
		if err := s.limit(ctx, bucket.kind, bucket.value, bucket.count); err != nil {
			return Session{}, s.failure(ctx, "", "ops.auth.sign_in", err)
		}
	}
	user, err := s.Store.Queries().GetUserByEmail(ctx, db.GetUserByEmailParams{EmailNormalized: email})
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return Session{}, err
	}
	hash := s.dummyHash
	if err == nil {
		hash = user.PasswordHash
	}
	valid := s.Passwords.Verify(password, hash)
	if !valid || err != nil || user.DisabledAt.Valid {
		return Session{}, s.failure(ctx, "", "ops.auth.sign_in", invalidCredentials())
	}
	raw, err := newToken()
	if err != nil {
		return Session{}, err
	}
	var result Session
	err = s.Store.InTx(ctx, func(q *db.Queries) error {
		op, err := q.LockOperatorIdentity(ctx, db.LockOperatorIdentityParams{UserID: user.ID})
		if errors.Is(err, pgx.ErrNoRows) {
			return invalidCredentials()
		}
		if err != nil {
			return err
		}
		if !op.Active || op.DisabledAt.Valid || op.PasswordHash != user.PasswordHash {
			return invalidCredentials()
		}
		if err := s.Factors.VerifyTOTPTx(ctx, q, user.ID, "", code, time.Now().UTC()); err != nil {
			if errors.Is(err, factor.ErrInvalidCode) {
				return invalidCredentials()
			}
			return err
		}
		now := time.Now().UTC()
		row, err := q.CreateOperatorSession(ctx, db.CreateOperatorSessionParams{
			ID: string(ids.New[ids.OperatorSessionID]("ops")), UserID: user.ID,
			TokenHash: hashWithKey(raw.Value(), s.HMACKeys[0]),
			ExpiresAt: pgTime(now.Add(8 * time.Hour)), IdleExpiresAt: pgTime(now.Add(30 * time.Minute)), AccessExpiresAt: pgTime(now.Add(accessTTL)),
			Ip: nullable(ip.String()), UserAgent: nullable(userAgent),
		})
		if err != nil {
			return err
		}
		result = Session{Token: raw, ID: row.ID, UserID: user.ID, ExpiresAt: row.AccessExpiresAt.Time}
		return audit.Write(ctx, q, "operator_session", user.ID, "ops.auth.sign_in", row.ID, "success")
	})
	if err != nil {
		return Session{}, s.failure(ctx, user.ID, "ops.auth.sign_in", err)
	}
	return result, nil
}

// Run rechecks operator and user state under locks and executes a request in the
// same transaction as its audit record and any single-use step-up consumption.
func (s *Service) Run(ctx context.Context, raw, operation, capability string, digest []byte, fn func(*db.Queries, Session) error) error {
	var actor string
	err := s.Store.InTx(ctx, func(q *db.Queries) error {
		if !strings.HasPrefix(raw, "ply_ops_") {
			return apierr.New("CREDENTIAL_PLANE_MISMATCH", "An operations session is required.")
		}
		b, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(raw, "ply_ops_"))
		if err != nil || len(b) != 32 {
			return invalidCredentials()
		}
		var row db.OperatorSession
		found := false
		for _, key := range s.HMACKeys {
			row, err = q.LockOperatorSession(ctx, db.LockOperatorSessionParams{TokenHash: hashWithKey(raw, key)})
			if err == nil {
				found = true
				break
			}
			if !errors.Is(err, pgx.ErrNoRows) {
				return err
			}
		}
		if !found {
			return invalidCredentials()
		}
		op, err := q.LockOperatorIdentity(ctx, db.LockOperatorIdentityParams{UserID: row.UserID})
		if errors.Is(err, pgx.ErrNoRows) {
			return invalidCredentials()
		}
		if err != nil {
			return err
		}
		if !op.Active || op.DisabledAt.Valid || row.AssuranceLevel < 2 {
			return invalidCredentials()
		}
		actor = row.UserID
		current := Session{ID: row.ID, UserID: row.UserID, ExpiresAt: row.AccessExpiresAt.Time}
		if err := json.Unmarshal(op.Capabilities, &current.Capabilities); err != nil {
			return err
		}
		if capability != "" && !allows(current, capability) {
			return &apierr.Error{Code: "PERMISSION_DENIED", Message: "Operator capability is required.", Details: map[string]string{"permission": capability}}
		}
		if digest != nil {
			_, err := q.ConsumeOperatorStepUp(ctx, db.ConsumeOperatorStepUpParams{ID: row.ID, Operation: nullable(operation), Digest: digest})
			if errors.Is(err, pgx.ErrNoRows) {
				return apierr.New("STEP_UP_REQUIRED", "Verify MFA for this operation and request content.")
			}
			if err != nil {
				return err
			}
		}
		if err := q.TouchOperatorSession(ctx, db.TouchOperatorSessionParams{ID: row.ID}); err != nil {
			return err
		}
		if err := fn(q, current); err != nil {
			return err
		}
		return audit.Write(ctx, q, "operator_session", row.UserID, operation, row.ID, "success")
	})
	if err != nil {
		return s.failure(ctx, actor, operation, err)
	}
	return nil
}

func (s *Service) StepUp(ctx context.Context, raw, code, operation string, digest []byte) error {
	switch operation {
	case "ops.settings.update", "ops.operators.create", "ops.operators.update", "ops.operators.disable", "ops.users.suspend", "ops.users.sign_out_all", "ops.users.require_password_reset":
	default:
		return s.failure(ctx, "", "ops.auth.step_up", apierr.New("VALIDATION_FAILED", "An implemented operation and its request digest are required."))
	}
	if len(digest) != sha256.Size {
		return s.failure(ctx, "", "ops.auth.step_up", apierr.New("VALIDATION_FAILED", "An implemented operation and its request digest are required."))
	}
	return s.Run(ctx, raw, "ops.auth.step_up", "ops:session", nil, func(q *db.Queries, current Session) error {
		if err := s.limit(ctx, "mfa", current.UserID, 5); err != nil {
			return err
		}
		if err := s.Factors.VerifyTOTPTx(ctx, q, current.UserID, "", code, time.Now().UTC()); err != nil {
			if errors.Is(err, factor.ErrInvalidCode) {
				return invalidCredentials()
			}
			return err
		}
		_, err := q.StepUpOperatorSession(ctx, db.StepUpOperatorSessionParams{ID: current.ID, Operation: nullable(operation), Digest: digest})
		return err
	})
}

func (s *Service) SuspendUser(ctx context.Context, raw, userID string, digest []byte) error {
	return s.Run(ctx, raw, "ops.users.suspend", "ops:users:manage", digest, func(q *db.Queries, current Session) error {
		return account.SetUserStatusTx(ctx, q, "operator", current.UserID, userID, "suspended")
	})
}

func (s *Service) SignOutAllUserSessions(ctx context.Context, raw, userID string, digest []byte) error {
	return s.Run(ctx, raw, "ops.users.sign_out_all", "ops:users:manage", digest, func(q *db.Queries, current Session) error {
		if _, err := q.LockUserForStatus(ctx, db.LockUserForStatusParams{ID: userID}); errors.Is(err, pgx.ErrNoRows) {
			return apierr.New("NOT_FOUND", "user was not found")
		} else if err != nil {
			return err
		}
		if err := q.RevokeUserSessions(ctx, db.RevokeUserSessionsParams{UserID: userID}); err != nil {
			return err
		}
		if err := q.RevokeUserRefreshTokens(ctx, db.RevokeUserRefreshTokensParams{UserID: userID}); err != nil {
			return err
		}
		return audit.Write(ctx, q, "operator", current.UserID, "user.sessions.revoke", userID, "success")
	})
}

func (s *Service) RequirePasswordReset(ctx context.Context, raw, userID string, digest []byte) error {
	return s.Run(ctx, raw, "ops.users.require_password_reset", "ops:users:manage", digest, func(q *db.Queries, current Session) error {
		return account.RequirePasswordResetTx(ctx, q, "operator", current.UserID, userID)
	})
}

func (s *Service) SignOut(ctx context.Context, raw string) error {
	return s.Run(ctx, raw, "ops.auth.sign_out", "", nil, func(q *db.Queries, current Session) error {
		return q.RevokeOperatorSession(ctx, db.RevokeOperatorSessionParams{ID: current.ID})
	})
}

func (s *Service) List(ctx context.Context, raw string) ([]Operator, error) {
	var out []Operator
	err := s.Run(ctx, raw, "ops.operators.list", "ops:operators:read", nil, func(q *db.Queries, _ Session) error {
		rows, err := q.ListOperators(ctx)
		if err != nil {
			return err
		}
		out = make([]Operator, 0, len(rows))
		for _, row := range rows {
			caps, err := decodeCapabilities(row.Capabilities)
			if err != nil {
				return err
			}
			view := Operator{UserID: row.UserID, Email: row.Email, Capabilities: caps, Active: row.Active, Disabled: row.DisabledAt.Valid, CreatedAt: row.CreatedAt.Time}
			if row.LastStepUpAt.Valid {
				v := row.LastStepUpAt.Time
				view.LastStepUpAt = &v
			}
			out = append(out, view)
		}
		return nil
	})
	return out, err
}

func (s *Service) Create(ctx context.Context, raw, userID string, capabilities []string, digest []byte) (OperatorCreate, error) {
	requested, err := normalizeCapabilities(capabilities)
	if err != nil {
		return OperatorCreate{}, s.failure(ctx, "", "ops.operators.create", err)
	}
	var result OperatorCreate
	err = s.Run(ctx, raw, "ops.operators.create", "ops:operators:manage", digest, func(q *db.Queries, current Session) error {
		if err := ensureSubset(requested, current.Capabilities); err != nil {
			return err
		}
		user, err := q.LockUserForOperator(ctx, db.LockUserForOperatorParams{ID: userID})
		if errors.Is(err, pgx.ErrNoRows) {
			return apierr.New("NOT_FOUND", "The requested user was not found.")
		}
		if err != nil {
			return err
		}
		if user.DisabledAt.Valid {
			return apierr.New("CONFLICT", "A disabled user cannot become an operator.")
		}
		if _, err := q.GetOperator(ctx, db.GetOperatorParams{UserID: userID}); err == nil {
			return apierr.New("CONFLICT", "The user is already an operator.")
		} else if !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
		caps, _ := json.Marshal(requested)
		if err := q.CreateOperator(ctx, db.CreateOperatorParams{UserID: userID, Capabilities: caps}); err != nil {
			return err
		}
		factorCount, err := q.CountTOTPFactors(ctx, db.CountTOTPFactorsParams{UserID: userID})
		if err != nil {
			return err
		}
		result = OperatorCreate{Operator: Operator{UserID: user.ID, Email: user.Email, Capabilities: requested, Active: true, CreatedAt: time.Now().UTC()}}
		if factorCount == 0 {
			enrollment, err := s.Factors.BeginTOTPTx(ctx, q, userID, user.Email)
			if err != nil {
				return err
			}
			result.Enrollment = &enrollment
		}
		return nil
	})
	return result, err
}

func (s *Service) UpdateCapabilities(ctx context.Context, raw, userID string, capabilities []string, digest []byte) error {
	requested, err := normalizeCapabilities(capabilities)
	if err != nil {
		return s.failure(ctx, "", "ops.operators.update", err)
	}
	return s.Run(ctx, raw, "ops.operators.update", "ops:operators:manage", digest, func(q *db.Queries, current Session) error {
		if err := ensureSubset(requested, current.Capabilities); err != nil {
			return err
		}
		target, err := q.LockOperator(ctx, db.LockOperatorParams{UserID: userID})
		if errors.Is(err, pgx.ErrNoRows) {
			return apierr.New("NOT_FOUND", "The requested operator was not found.")
		}
		if err != nil {
			return err
		}
		if hasCapability(target.Capabilities, "*") && !containsCapability(requested, "*") {
			count, err := q.CountFullCapabilityOperators(ctx)
			if err != nil {
				return err
			}
			if count <= 1 {
				return apierr.New("CONFLICT", "The last full-capability operator cannot be narrowed.")
			}
		}
		caps, _ := json.Marshal(requested)
		_, err = q.UpdateOperatorCapabilities(ctx, db.UpdateOperatorCapabilitiesParams{UserID: userID, Capabilities: caps})
		return err
	})
}

func (s *Service) Disable(ctx context.Context, raw, userID string, digest []byte) error {
	return s.Run(ctx, raw, "ops.operators.disable", "ops:operators:manage", digest, func(q *db.Queries, _ Session) error {
		target, err := q.LockOperator(ctx, db.LockOperatorParams{UserID: userID})
		if errors.Is(err, pgx.ErrNoRows) {
			return apierr.New("NOT_FOUND", "The requested operator was not found.")
		}
		if err != nil {
			return err
		}
		if hasCapability(target.Capabilities, "*") {
			count, err := q.CountFullCapabilityOperators(ctx)
			if err != nil {
				return err
			}
			if count <= 1 {
				return apierr.New("CONFLICT", "The last full-capability operator cannot be disabled.")
			}
		}
		_, err = q.DisableOperator(ctx, db.DisableOperatorParams{UserID: userID})
		if errors.Is(err, pgx.ErrNoRows) {
			return apierr.New("CONFLICT", "The operator is already disabled.")
		}
		return err
	})
}

func (s *Service) failure(ctx context.Context, actor, operation string, cause error) error {
	if err := s.Store.InTx(ctx, func(q *db.Queries) error {
		return audit.Write(ctx, q, "operator_session", actor, operation, "", "failure")
	}); err != nil {
		return fmt.Errorf("operator audit unavailable: %w", err)
	}
	return cause
}

func allows(current Session, capability string) bool {
	for _, value := range current.Capabilities {
		if value == "*" || value == capability {
			return true
		}
	}
	return false
}

func invalidCredentials() error {
	return apierr.New("UNAUTHENTICATED", "Operator credentials are invalid.")
}

func decodeCapabilities(raw []byte) ([]string, error) {
	var caps []string
	if err := json.Unmarshal(raw, &caps); err != nil {
		return nil, err
	}
	return normalizeCapabilities(caps)
}

func normalizeCapabilities(values []string) ([]string, error) {
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			return nil, apierr.New("VALIDATION_FAILED", "capabilities must not contain empty values.")
		}
		if value != "*" {
			if _, ok := knownCapabilities[value]; !ok {
				return nil, apierr.New("VALIDATION_FAILED", "capabilities contains an unknown value.")
			}
		}
		seen[value] = struct{}{}
	}
	if len(seen) == 0 {
		return nil, apierr.New("VALIDATION_FAILED", "at least one operator capability is required.")
	}
	if _, ok := seen["*"]; ok && len(seen) != 1 {
		return nil, apierr.New("VALIDATION_FAILED", "the wildcard capability cannot be combined with named capabilities.")
	}
	out := make([]string, 0, len(seen))
	for value := range seen {
		out = append(out, value)
	}
	sort.Strings(out)
	return out, nil
}

func ensureSubset(requested, owner []string) error {
	if containsCapability(owner, "*") {
		return nil
	}
	for _, value := range requested {
		if !containsCapability(owner, value) {
			return &apierr.Error{Code: "PERMISSION_DENIED", Message: "An operator cannot grant capabilities it does not hold.", Details: map[string]string{"permission": value}}
		}
	}
	return nil
}

func containsCapability(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func hasCapability(raw []byte, want string) bool {
	caps, err := decodeCapabilities(raw)
	return err == nil && containsCapability(caps, want)
}

func newToken() (secret.String, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return secret.New("ply_ops_" + base64.RawURLEncoding.EncodeToString(b)), nil
}
func hashWithKey(token string, key []byte) []byte {
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write([]byte("operator-session:" + token))
	return mac.Sum(nil)
}
func nullable(v string) pgtype.Text         { return pgtype.Text{String: v, Valid: v != ""} }
func pgTime(t time.Time) pgtype.Timestamptz { return pgtype.Timestamptz{Time: t, Valid: true} }
