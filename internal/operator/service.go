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
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/plystra/auth/internal/apierr"
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
	Token        secret.Secret
	ID           string
	UserID       string
	Capabilities []string
	ExpiresAt    time.Time
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
	if operation != "ops.settings.update" || len(digest) != sha256.Size {
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

func (s *Service) SignOut(ctx context.Context, raw string) error {
	return s.Run(ctx, raw, "ops.auth.sign_out", "", nil, func(q *db.Queries, current Session) error {
		return q.RevokeOperatorSession(ctx, db.RevokeOperatorSessionParams{ID: current.ID})
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

func newToken() (secret.Secret, error) {
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
