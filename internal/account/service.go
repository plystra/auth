package account

import (
	"context"
	"errors"
	"net"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/plystra/auth/internal/apierr"
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
	User   User           `json:"user"`
	Tokens session.Tokens `json:"tokens"`
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
	var u db.User
	e = s.Store.InTx(ctx, func(q *db.Queries) error {
		u, e = q.CreateUser(ctx, db.CreateUserParams{ID: string(ids.New[ids.UserID]("usr")), Email: email, EmailNormalized: email, PasswordHash: hash})
		return e
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
	tokens, e := s.Sessions.Create(ctx, u.ID, ip, ua, 1)
	if e != nil {
		return AuthResult{}, e
	}
	return AuthResult{User: toUser(u), Tokens: tokens}, nil
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
	var u db.User
	e := func() error {
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
	tokens, e := s.Sessions.Create(ctx, u.ID, in.IP, in.UserAgent, 1)
	if e != nil {
		return AuthResult{}, e
	}
	return AuthResult{User: toUser(u), Tokens: tokens}, nil
}
func (s *Service) Me(ctx context.Context, claims security.Claims) (User, error) {
	u, e := s.Store.Queries().GetUserByID(ctx, db.GetUserByIDParams{ID: claims.Subject})
	if e != nil {
		if errors.Is(e, pgx.ErrNoRows) {
			return User{}, apierr.New("unauthorized", "user no longer exists")
		}
		return User{}, e
	}
	if u.DisabledAt.Valid {
		return User{}, apierr.New("unauthorized", "account is disabled")
	}
	return toUser(u), nil
}
func toUser(u db.User) User {
	return User{ID: u.ID, Email: u.Email, EmailVerified: u.EmailVerifiedAt.Valid, CreatedAt: u.CreatedAt.Time}
}
func validEmail(v string) bool {
	at := strings.LastIndexByte(v, '@')
	return at > 0 && at < len(v)-1 && !strings.ContainsAny(v[at+1:], "@ ")
}
