package account

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/plystra/auth/internal/apierr"
	"github.com/plystra/auth/internal/audit"
	"github.com/plystra/auth/internal/authorization"
	"github.com/plystra/auth/internal/db"
	"github.com/plystra/auth/internal/ids"
	"github.com/plystra/auth/internal/mail"
	"github.com/plystra/auth/internal/secret"
	"github.com/plystra/auth/internal/security"
	"github.com/plystra/auth/internal/session"
	"github.com/plystra/auth/internal/space"
	"github.com/plystra/auth/internal/store"
)

type User struct {
	ID             string         `json:"id"`
	Email          string         `json:"email"`
	EmailVerified  bool           `json:"email_verified"`
	Status         string         `json:"status"`
	DisplayName    string         `json:"name"`
	AvatarURL      string         `json:"avatar_url"`
	PublicMetadata map[string]any `json:"public_metadata"`
	CreatedAt      time.Time      `json:"created_at"`
}
type Service struct {
	Store         *store.Store
	Passwords     security.PasswordHasher
	Sessions      *session.Service
	Settings      *space.Service
	Limiter       *store.RateLimiter
	Authorization *authorization.Service
	Mailer        *mail.Service
	Invitations   InvitationFinalizer
}

type InvitationFinalizer interface {
	FinalizeVerifiedUserTx(context.Context, *db.Queries, string) error
}
type RegisterInput struct {
	Email    string
	Password string
}

type ProfileUpdate struct {
	DisplayName    *string
	AvatarURL      *string
	PublicMetadata *map[string]any
}
type LoginInput struct {
	Email     string
	Password  string
	IP        net.IP
	UserAgent string
}
type AuthResult struct {
	User      User            `json:"user"`
	Tokens    *session.Tokens `json:"tokens,omitempty"`
	AttemptID string          `json:"attempt_id,omitempty"`
	NextStep  string          `json:"next_step,omitempty"`
	ExpiresAt *time.Time      `json:"expires_at,omitempty"`
}

const DefaultSpaceID = "spc_01h00000000000000000000000"

func (s *Service) Register(ctx context.Context, in RegisterInput, ip net.IP, ua string) (AuthResult, error) {
	email := strings.TrimSpace(strings.ToLower(in.Email))
	if !validEmail(email) {
		return AuthResult{}, apierr.New("invalid_request", "a valid email is required")
	}
	if s.Limiter != nil {
		ok, e := s.Limiter.Allow(ctx, "register:"+email, 10, time.Hour)
		if e != nil {
			return AuthResult{}, e
		}
		if !ok {
			return AuthResult{}, apierr.New("rate_limited", "too many registration attempts")
		}
	}
	settings, e := s.Settings.Get(ctx)
	if e != nil {
		return AuthResult{}, e
	}
	if settings.RegistrationMode != "open" {
		return AuthResult{}, apierr.New("forbidden", "registration is not open")
	}
	if settings.RequireEmailVerification && s.Mailer == nil {
		return AuthResult{}, apierr.New("UNAVAILABLE", "email verification delivery is unavailable")
	}
	if len(in.Password) < settings.PasswordMinLength {
		return AuthResult{}, apierr.New("invalid_request", "password does not meet the configured minimum length")
	}
	if len(in.Password) > security.MaxPasswordBytes {
		return AuthResult{}, apierr.New("invalid_request", "password exceeds the maximum length")
	}
	hash, e := s.Passwords.Hash(in.Password)
	if e != nil {
		return AuthResult{}, e
	}
	var u db.CreateUserRow
	var memberID string
	var requireEmailVerification bool
	e = s.Store.InTx(ctx, func(q *db.Queries) error {
		current, err := s.Settings.GetTx(ctx, q)
		if err != nil {
			return err
		}
		if current.RegistrationMode != "open" {
			return apierr.New("forbidden", "registration is not open")
		}
		if len(in.Password) < current.PasswordMinLength {
			return apierr.New("invalid_request", "password does not meet the configured minimum length")
		}
		requireEmailVerification = current.RequireEmailVerification
		status := "active"
		if requireEmailVerification {
			status = "pending"
		}
		u, err = q.CreateUser(ctx, db.CreateUserParams{ID: string(ids.New[ids.UserID]("usr")), Email: email, EmailNormalized: email, PasswordHash: hash, Status: status})
		if err != nil {
			return err
		}
		if s.Authorization != nil {
			memberID, err = s.Authorization.EnsureDefaultMembershipTx(ctx, q, u.ID, email)
			if err != nil {
				return err
			}
		}
		if requireEmailVerification {
			if s.Mailer == nil {
				return apierr.New("UNAVAILABLE", "email verification delivery is unavailable")
			}
			verification, verificationHash, err := opaqueToken("ev_")
			if err != nil {
				return err
			}
			expiresAt := time.Now().UTC().Add(24 * time.Hour)
			if err := q.CreateEmailVerificationToken(ctx, db.CreateEmailVerificationTokenParams{ID: string(ids.New[ids.ID]("evt")), UserID: u.ID, TokenHash: verificationHash, ExpiresAt: pgTime(expiresAt)}); err != nil {
				return err
			}
			if err := s.Mailer.EnqueueVerificationTx(ctx, q, email, secret.New(verification), expiresAt); err != nil {
				return err
			}
		}
		return audit.Write(ctx, q, "public", u.ID, "auth.register", u.ID, "success")
	})
	if e != nil {
		if strings.Contains(e.Error(), "duplicate") || strings.Contains(e.Error(), "unique") {
			return AuthResult{}, apierr.New("conflict", "an account with this email already exists")
		}
		return AuthResult{}, e
	}
	if requireEmailVerification {
		return AuthResult{User: toPublicUser(u.ID, u.Email, u.EmailVerifiedAt.Valid, u.Status, u.CreatedAt.Time)}, nil
	}
	tokens, e := s.Sessions.CreateForMember(ctx, u.ID, memberID, ip, ua, 1)
	if e != nil {
		return AuthResult{}, e
	}
	return AuthResult{User: toPublicUser(u.ID, u.Email, u.EmailVerifiedAt.Valid, u.Status, u.CreatedAt.Time), Tokens: &tokens}, nil
}
func (s *Service) Login(ctx context.Context, in LoginInput) (AuthResult, error) {
	email := strings.TrimSpace(strings.ToLower(in.Email))
	ip := rateIdentity(in.IP)
	for _, bucket := range []struct {
		kind, value string
		limit       int
		window      time.Duration
	}{
		{"login:ip", ip, 30, time.Minute},
		{"login:account", email, 10, time.Minute},
		{"login:pair", ip + ":" + email, 5, time.Minute},
	} {
		if err := s.allowRateLimit(ctx, bucket.kind, bucket.value, bucket.limit, bucket.window); err != nil {
			return AuthResult{}, err
		}
	}
	settings, e := s.Settings.Get(ctx)
	if e != nil {
		return AuthResult{}, e
	}
	var u db.GetUserByEmailRow
	e = func() error {
		row, e := s.Store.Queries().GetUserByEmail(ctx, db.GetUserByEmailParams{EmailNormalized: email})
		u = row
		return e
	}()
	if e != nil {
		if errors.Is(e, pgx.ErrNoRows) {
			return AuthResult{}, apierr.New("invalid_credentials", "email or password is incorrect")
		}
		return AuthResult{}, e
	}
	if len(in.Password) > security.MaxPasswordBytes || u.DisabledAt.Valid || !s.Passwords.Verify(in.Password, u.PasswordHash) {
		return AuthResult{}, apierr.New("invalid_credentials", "email or password is incorrect")
	}
	if s.Passwords.NeedsRehash(u.PasswordHash) {
		upgraded, hashErr := s.Passwords.Hash(in.Password)
		if hashErr != nil {
			return AuthResult{}, hashErr
		}
		if hashErr = s.Store.InTx(ctx, func(q *db.Queries) error {
			if err := q.UpdatePassword(ctx, db.UpdatePasswordParams{ID: u.ID, PasswordHash: upgraded}); err != nil {
				return err
			}
			return audit.Write(ctx, q, "public", u.ID, "auth.password.rehash", u.ID, "success")
		}); hashErr != nil {
			return AuthResult{}, hashErr
		}
	}
	if u.Status == "pending" && settings.RequireEmailVerification {
		return AuthResult{}, apierr.New("EMAIL_VERIFICATION_REQUIRED", "verify your email before signing in")
	}
	if u.Status != "active" {
		return AuthResult{}, apierr.New("UNAUTHENTICATED", "this account is not active")
	}
	if u.PasswordResetRequiredAt.Valid {
		return AuthResult{}, apierr.New("PASSWORD_RESET_REQUIRED", "reset your password before signing in")
	}
	factorCount, e := s.Store.Queries().CountTOTPFactors(ctx, db.CountTOTPFactorsParams{UserID: u.ID})
	if e != nil {
		return AuthResult{}, e
	}
	if factorCount > 0 {
		return AuthResult{}, apierr.New("MFA_REQUIRED", "complete the multi-step sign-in to verify your authenticator")
	}
	memberID, e := s.defaultMemberID(ctx, u.ID)
	if e != nil {
		return AuthResult{}, e
	}
	tokens, e := s.Sessions.CreateForMember(ctx, u.ID, memberID, in.IP, in.UserAgent, 1)
	if e != nil {
		return AuthResult{}, e
	}
	return AuthResult{User: toPublicUser(u.ID, u.Email, u.EmailVerifiedAt.Valid, u.Status, u.CreatedAt.Time), Tokens: &tokens}, nil
}

func (s *Service) defaultMemberID(ctx context.Context, userID string) (string, error) {
	if s.Authorization == nil {
		return "", nil
	}
	members, err := s.Authorization.ListMembersForUser(ctx, userID, "human")
	if err != nil {
		return "", err
	}
	for _, member := range members {
		if member.SpaceID == DefaultSpaceID {
			return member.ID, nil
		}
	}
	if len(members) > 0 {
		return members[0].ID, nil
	}
	return "", nil
}

func (s *Service) allowRateLimit(ctx context.Context, kind, value string, limit int, window time.Duration) error {
	if s.Limiter == nil {
		return nil
	}
	digest := sha256.Sum256([]byte("plystra-auth-rate:" + kind + ":" + value))
	ok, err := s.Limiter.Allow(ctx, "auth:"+base64.RawURLEncoding.EncodeToString(digest[:]), limit, window)
	if err != nil {
		return err
	}
	if !ok {
		return apierr.New("rate_limited", "too many authentication attempts")
	}
	return nil
}

func rateIdentity(ip net.IP) string {
	if len(ip) == 0 {
		return "unknown"
	}
	return ip.String()
}
func (s *Service) Me(ctx context.Context, claims security.Claims) (User, error) {
	u, e := s.Store.Queries().GetUserProfileByID(ctx, db.GetUserProfileByIDParams{ID: claims.Subject})
	if e != nil {
		if errors.Is(e, pgx.ErrNoRows) {
			return User{}, apierr.New("unauthorized", "user no longer exists")
		}
		return User{}, e
	}
	if u.DisabledAt.Valid || u.Status != "active" {
		return User{}, apierr.New("unauthorized", "account is disabled")
	}
	return userFromProfileRow(u.ID, u.Email, u.EmailVerifiedAt.Valid, u.Status, u.DisplayName, u.AvatarUrl, u.PublicMetadata, u.CreatedAt.Time)
}

// UpdateProfile changes only user-owned public profile fields. Private
// metadata is intentionally absent from this API and is reserved for the
// server-side management plane.
func (s *Service) UpdateProfile(ctx context.Context, userID string, in ProfileUpdate) (User, error) {
	if strings.TrimSpace(userID) == "" {
		return User{}, apierr.New("UNAUTHENTICATED", "a user account is required")
	}
	if in.DisplayName != nil && (len([]rune(*in.DisplayName)) > 128 || strings.ContainsAny(*in.DisplayName, "\r\n")) {
		return User{}, apierr.New("VALIDATION_FAILED", "name is invalid")
	}
	if in.AvatarURL != nil && (len(*in.AvatarURL) > 2048 || strings.ContainsAny(*in.AvatarURL, "\r\n")) {
		return User{}, apierr.New("VALIDATION_FAILED", "avatar_url is invalid")
	}
	var publicMetadata []byte
	if in.PublicMetadata != nil {
		encoded, err := json.Marshal(*in.PublicMetadata)
		if err != nil {
			return User{}, apierr.New("VALIDATION_FAILED", "public_metadata must be valid JSON")
		}
		if len(encoded) > 16*1024 {
			return User{}, apierr.New("VALIDATION_FAILED", "public_metadata exceeds 16 KiB")
		}
		publicMetadata = encoded
	}
	var out User
	err := s.Store.InTx(ctx, func(q *db.Queries) error {
		row, err := q.UpdateUserProfile(ctx, db.UpdateUserProfileParams{
			ID: userID, DisplayName: optionalText(in.DisplayName), AvatarUrl: optionalText(in.AvatarURL), PublicMetadata: publicMetadata,
		})
		if errors.Is(err, pgx.ErrNoRows) {
			return apierr.New("NOT_FOUND", "user was not found")
		}
		if err != nil {
			return err
		}
		if row.Status != "active" {
			return apierr.New("UNAUTHENTICATED", "account is not active")
		}
		out, err = userFromProfileRow(row.ID, row.Email, row.EmailVerifiedAt.Valid, row.Status, row.DisplayName, row.AvatarUrl, row.PublicMetadata, row.CreatedAt.Time)
		if err != nil {
			return err
		}
		return audit.Write(ctx, q, "user", userID, "user.profile.update", userID, "success")
	})
	return out, err
}

// SetUserStatus changes an account state and revokes all online credentials
// whenever the account is suspended or disabled. The user row, credentials,
// and audit record share one transaction so no session survives a committed
// state change.
func (s *Service) SetUserStatus(ctx context.Context, actorType, actorID, userID, status string) error {
	return s.Store.InTx(ctx, func(q *db.Queries) error {
		return SetUserStatusTx(ctx, q, actorType, actorID, userID, status)
	})
}

// SetUserStatusTx is the transaction-aware form used by the operations plane.
// The caller owns the surrounding transaction and its operator-session audit.
func SetUserStatusTx(ctx context.Context, q *db.Queries, actorType, actorID, userID, status string) error {
	if status != "pending" && status != "active" && status != "suspended" && status != "disabled" {
		return apierr.New("VALIDATION_FAILED", "user status is invalid")
	}
	user, err := q.LockUserForStatus(ctx, db.LockUserForStatusParams{ID: userID})
	if errors.Is(err, pgx.ErrNoRows) {
		return apierr.New("NOT_FOUND", "user was not found")
	}
	if err != nil {
		return err
	}
	if err := q.SetUserStatus(ctx, db.SetUserStatusParams{ID: user.ID, Status: status}); err != nil {
		return err
	}
	if status == "suspended" || status == "disabled" {
		if err := q.RevokeUserSessions(ctx, db.RevokeUserSessionsParams{UserID: user.ID}); err != nil {
			return err
		}
		if err := q.RevokeUserRefreshTokens(ctx, db.RevokeUserRefreshTokensParams{UserID: user.ID}); err != nil {
			return err
		}
	}
	return audit.Write(ctx, q, actorType, actorID, "user.status.update", user.ID, "success")
}

func (s *Service) RequirePasswordReset(ctx context.Context, actorType, actorID, userID string) error {
	return s.Store.InTx(ctx, func(q *db.Queries) error {
		return RequirePasswordResetTx(ctx, q, actorType, actorID, userID)
	})
}

func RequirePasswordResetTx(ctx context.Context, q *db.Queries, actorType, actorID, userID string) error {
	user, err := q.LockUserForStatus(ctx, db.LockUserForStatusParams{ID: userID})
	if errors.Is(err, pgx.ErrNoRows) {
		return apierr.New("NOT_FOUND", "user was not found")
	}
	if err != nil {
		return err
	}
	if err := q.RequirePasswordReset(ctx, db.RequirePasswordResetParams{ID: user.ID}); err != nil {
		return err
	}
	if err := q.RevokeUserSessions(ctx, db.RevokeUserSessionsParams{UserID: user.ID}); err != nil {
		return err
	}
	if err := q.RevokeUserRefreshTokens(ctx, db.RevokeUserRefreshTokensParams{UserID: user.ID}); err != nil {
		return err
	}
	return audit.Write(ctx, q, actorType, actorID, "user.password_reset.require", user.ID, "success")
}

func toPublicUser(id, email string, verified bool, status string, createdAt time.Time) User {
	return User{ID: id, Email: email, EmailVerified: verified, Status: status, PublicMetadata: map[string]any{}, CreatedAt: createdAt}
}

func userFromProfileRow(id, email string, verified bool, status, displayName, avatarURL string, encoded []byte, createdAt time.Time) (User, error) {
	metadata := map[string]any{}
	if len(encoded) != 0 {
		if err := json.Unmarshal(encoded, &metadata); err != nil {
			return User{}, err
		}
	}
	return User{ID: id, Email: email, EmailVerified: verified, Status: status, DisplayName: displayName, AvatarURL: avatarURL, PublicMetadata: metadata, CreatedAt: createdAt}, nil
}

func optionalText(value *string) pgtype.Text {
	if value == nil {
		return pgtype.Text{}
	}
	return pgtype.Text{String: *value, Valid: true}
}
func validEmail(v string) bool {
	at := strings.LastIndexByte(v, '@')
	return at > 0 && at < len(v)-1 && !strings.ContainsAny(v[at+1:], "@ ")
}
