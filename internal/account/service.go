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
	hash, e := s.Passwords.Hash(in.Password)
	if e != nil {
		return AuthResult{}, e
	}
	var u db.CreateUserRow
	status := "active"
	var verificationHash []byte
	if settings.RequireEmailVerification {
		status = "pending"
		_, verificationHash, e = opaqueToken("ev_")
		if e != nil {
			return AuthResult{}, e
		}
	}
	e = s.Store.InTx(ctx, func(q *db.Queries) error {
		u, e = q.CreateUser(ctx, db.CreateUserParams{ID: string(ids.New[ids.UserID]("usr")), Email: email, EmailNormalized: email, PasswordHash: hash, Status: status})
		if e != nil {
			return e
		}
		if settings.RequireEmailVerification {
			if e = q.CreateEmailVerificationToken(ctx, db.CreateEmailVerificationTokenParams{ID: string(ids.New[ids.ID]("evt")), UserID: u.ID, TokenHash: verificationHash, ExpiresAt: pgTime(time.Now().UTC().Add(24 * time.Hour))}); e != nil {
				return e
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
	if s.Authorization != nil {
		if e := s.Authorization.EnsureDefaultMembership(ctx, u.ID, email); e != nil {
			return AuthResult{}, e
		}
	}
	if settings.RequireEmailVerification {
		return AuthResult{User: toPublicUser(u.ID, u.Email, u.EmailVerifiedAt.Valid, u.Status, u.CreatedAt.Time)}, nil
	}
	memberID := ""
	if s.Authorization != nil {
		if member, memberErr := s.Authorization.GetMemberForUser(ctx, u.ID, DefaultSpaceID); memberErr == nil {
			memberID = member.ID
		} else {
			return AuthResult{}, memberErr
		}
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
	if u.DisabledAt.Valid || !s.Passwords.Verify(in.Password, u.PasswordHash) {
		return AuthResult{}, apierr.New("invalid_credentials", "email or password is incorrect")
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
func toPublicUser(id, email string, verified bool, status string, createdAt time.Time) User {
	return User{ID: id, Email: email, EmailVerified: verified, Status: status, CreatedAt: createdAt}
}
func validEmail(v string) bool {
	at := strings.LastIndexByte(v, '@')
	return at > 0 && at < len(v)-1 && !strings.ContainsAny(v[at+1:], "@ ")
}
