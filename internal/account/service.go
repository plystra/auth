package account

import (
	"context"
	"errors"
	"net"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/plystra/auth/internal/apierr"
	"github.com/plystra/auth/internal/audit"
	"github.com/plystra/auth/internal/authorization"
	"github.com/plystra/auth/internal/db"
	"github.com/plystra/auth/internal/ids"
	"github.com/plystra/auth/internal/security"
	"github.com/plystra/auth/internal/session"
	"github.com/plystra/auth/internal/space"
	"github.com/plystra/auth/internal/store"
)

type User struct {
	ID            string    `json:"id"`
	Email         string    `json:"email"`
	EmailVerified bool      `json:"email_verified"`
	Status        string    `json:"status"`
	CreatedAt     time.Time `json:"created_at"`
}
type Service struct {
	Store         *store.Store
	Passwords     security.PasswordHasher
	Sessions      *session.Service
	Settings      *space.Service
	Limiter       *store.RateLimiter
	Authorization *authorization.Service
}
type RegisterInput struct {
	Email    string
	Password string
}
type LoginInput struct {
	Email     string
	Password  string
	IP        net.IP
	UserAgent string
}
type AuthResult struct {
	User   User            `json:"user"`
	Tokens *session.Tokens `json:"tokens,omitempty"`
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
			_, verificationHash, err := opaqueToken("ev_")
			if err != nil {
				return err
			}
			if err := q.CreateEmailVerificationToken(ctx, db.CreateEmailVerificationTokenParams{ID: string(ids.New[ids.ID]("evt")), UserID: u.ID, TokenHash: verificationHash, ExpiresAt: pgTime(time.Now().UTC().Add(24 * time.Hour))}); err != nil {
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
	if s.Limiter != nil {
		ok, e := s.Limiter.Allow(ctx, "login:"+strings.ToLower(strings.TrimSpace(in.Email)), 20, time.Minute)
		if e != nil {
			return AuthResult{}, e
		}
		if !ok {
			return AuthResult{}, apierr.New("rate_limited", "too many login attempts")
		}
	}
	email := strings.TrimSpace(strings.ToLower(in.Email))
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
	memberID := ""
	if s.Authorization != nil {
		if member, memberErr := s.Authorization.GetMemberForUser(ctx, u.ID, DefaultSpaceID); memberErr == nil {
			memberID = member.ID
		} else {
			return AuthResult{}, memberErr
		}
	}
	tokens, e := s.Sessions.CreateForMember(ctx, u.ID, memberID, in.IP, in.UserAgent, 1)
	if e != nil {
		return AuthResult{}, e
	}
	return AuthResult{User: toPublicUser(u.ID, u.Email, u.EmailVerifiedAt.Valid, u.Status, u.CreatedAt.Time), Tokens: &tokens}, nil
}
func (s *Service) Me(ctx context.Context, claims security.Claims) (User, error) {
	u, e := s.Store.Queries().GetUserByID(ctx, db.GetUserByIDParams{ID: claims.Subject})
	if e != nil {
		if errors.Is(e, pgx.ErrNoRows) {
			return User{}, apierr.New("unauthorized", "user no longer exists")
		}
		return User{}, e
	}
	if u.DisabledAt.Valid || u.Status != "active" {
		return User{}, apierr.New("unauthorized", "account is disabled")
	}
	return toPublicUser(u.ID, u.Email, u.EmailVerifiedAt.Valid, u.Status, u.CreatedAt.Time), nil
}

// SetUserStatus changes an account state and revokes all online credentials
// whenever the account is suspended or disabled. The user row, credentials,
// and audit record share one transaction so no session survives a committed
// state change.
func (s *Service) SetUserStatus(ctx context.Context, actorType, actorID, userID, status string) error {
	if status != "pending" && status != "active" && status != "suspended" && status != "disabled" {
		return apierr.New("VALIDATION_FAILED", "user status is invalid")
	}
	return s.Store.InTx(ctx, func(q *db.Queries) error {
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
	})
}

func toPublicUser(id, email string, verified bool, status string, createdAt time.Time) User {
	return User{ID: id, Email: email, EmailVerified: verified, Status: status, CreatedAt: createdAt}
}
func validEmail(v string) bool {
	at := strings.LastIndexByte(v, '@')
	return at > 0 && at < len(v)-1 && !strings.ContainsAny(v[at+1:], "@ ")
}
