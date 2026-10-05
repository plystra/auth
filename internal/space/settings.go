package space

import (
	"context"
	"encoding/json"
	"github.com/plystra/auth/internal/apierr"
	"net/url"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/plystra/auth/internal/db"
	"github.com/plystra/auth/internal/store"
)

type InstanceSettings struct {
	RegistrationMode         string        `json:"registration_mode"`
	RequireEmailVerification bool          `json:"require_email_verification"`
	AllowedOrigins           []string      `json:"allowed_origins"`
	PasswordMinLength        int           `json:"password_min_length"`
	AccessTokenTTL           time.Duration `json:"access_token_ttl"`
	RefreshTokenTTL          time.Duration `json:"refresh_token_ttl"`
	RefreshIdleTTL           time.Duration `json:"refresh_idle_ttl"`
	UpdatedAt                time.Time     `json:"updated_at"`
}
type Service struct{ Store *store.Store }

func (s *Service) Get(ctx context.Context) (InstanceSettings, error) {
	row, e := s.Store.Queries().GetInstanceSettings(ctx)
	if e != nil {
		return InstanceSettings{}, e
	}
	return decode(row), nil
}

type SettingsPatch struct {
	RegistrationMode         *string        `json:"registration_mode,omitempty"`
	RequireEmailVerification *bool          `json:"require_email_verification,omitempty"`
	AllowedOrigins           *[]string      `json:"allowed_origins,omitempty"`
	PasswordMinLength        *int           `json:"password_min_length,omitempty"`
	AccessTokenTTL           *time.Duration `json:"access_token_ttl,omitempty"`
	RefreshTokenTTL          *time.Duration `json:"refresh_token_ttl,omitempty"`
	RefreshIdleTTL           *time.Duration `json:"refresh_idle_ttl,omitempty"`
}

func (s *Service) UpdateTx(ctx context.Context, q *db.Queries, in SettingsPatch, actor string) (InstanceSettings, error) {
	row, err := q.LockInstanceSettings(ctx)
	if err != nil {
		return InstanceSettings{}, err
	}
	v := decode(row)
	if in.RegistrationMode != nil {
		v.RegistrationMode = *in.RegistrationMode
	}
	if in.RequireEmailVerification != nil {
		v.RequireEmailVerification = *in.RequireEmailVerification
	}
	if in.AllowedOrigins != nil {
		v.AllowedOrigins = *in.AllowedOrigins
	}
	if in.PasswordMinLength != nil {
		v.PasswordMinLength = *in.PasswordMinLength
	}
	if in.AccessTokenTTL != nil {
		v.AccessTokenTTL = *in.AccessTokenTTL
	}
	if in.RefreshTokenTTL != nil {
		v.RefreshTokenTTL = *in.RefreshTokenTTL
	}
	if in.RefreshIdleTTL != nil {
		v.RefreshIdleTTL = *in.RefreshIdleTTL
	}
	if err := validate(v); err != nil {
		return InstanceSettings{}, err
	}
	origins, err := json.Marshal(v.AllowedOrigins)
	if err != nil {
		return InstanceSettings{}, err
	}
	row, err = q.UpdateInstanceSettings(ctx, db.UpdateInstanceSettingsParams{
		RegistrationMode:         pgtype.Text{String: v.RegistrationMode, Valid: true},
		RequireEmailVerification: pgtype.Bool{Bool: v.RequireEmailVerification, Valid: true},
		AllowedOrigins:           origins, PasswordMinLength: pgtype.Int4{Int32: int32(v.PasswordMinLength), Valid: true},
		AccessTokenTtlSeconds:  pgtype.Int4{Int32: int32(v.AccessTokenTTL / time.Second), Valid: true},
		RefreshTokenTtlSeconds: pgtype.Int4{Int32: int32(v.RefreshTokenTTL / time.Second), Valid: true},
		RefreshIdleTtlSeconds:  pgtype.Int4{Int32: int32(v.RefreshIdleTTL / time.Second), Valid: true},
		UpdatedBy:              pgtype.Text{String: actor, Valid: true},
	})
	if err != nil {
		return InstanceSettings{}, err
	}
	return decode(row), nil
}

func validate(v InstanceSettings) error {
	invalid := func(message string) error { return apierr.New("VALIDATION_FAILED", message) }
	if v.RegistrationMode != "open" && v.RegistrationMode != "closed" && v.RegistrationMode != "invite_only" {
		return invalid("registration_mode is invalid")
	}
	if v.PasswordMinLength < 8 || v.PasswordMinLength > 128 {
		return invalid("password_min_length must be between 8 and 128")
	}
	if v.AccessTokenTTL < 60*time.Second || v.AccessTokenTTL > 300*time.Second || v.AccessTokenTTL%time.Second != 0 {
		return invalid("access_token_ttl must be 60 to 300 whole seconds")
	}
	if v.RefreshTokenTTL < time.Hour || v.RefreshTokenTTL > 365*24*time.Hour || v.RefreshTokenTTL%time.Second != 0 {
		return invalid("refresh_token_ttl is invalid")
	}
	if v.RefreshIdleTTL < 15*time.Minute || v.RefreshIdleTTL > v.RefreshTokenTTL || v.RefreshIdleTTL%time.Second != 0 {
		return invalid("refresh_idle_ttl must not exceed refresh_token_ttl")
	}
	if len(v.AllowedOrigins) > 100 {
		return invalid("too many allowed origins")
	}
	for _, origin := range v.AllowedOrigins {
		u, err := url.Parse(origin)
		if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Hostname() == "" || u.User != nil || u.Path != "" || u.RawQuery != "" || u.Fragment != "" || strings.ContainsAny(origin, "* \r\n\t") {
			return invalid("allowed_origins must contain exact HTTP or HTTPS origins without paths or wildcards")
		}
	}
	return nil
}
func decode(row db.InstanceSetting) InstanceSettings {
	var origins []string
	_ = json.Unmarshal(row.AllowedOrigins, &origins)
	return InstanceSettings{RegistrationMode: row.RegistrationMode, RequireEmailVerification: row.RequireEmailVerification, AllowedOrigins: origins, PasswordMinLength: int(row.PasswordMinLength), AccessTokenTTL: time.Duration(row.AccessTokenTtlSeconds) * time.Second, RefreshTokenTTL: time.Duration(row.RefreshTokenTtlSeconds) * time.Second, RefreshIdleTTL: time.Duration(row.RefreshIdleTtlSeconds) * time.Second, UpdatedAt: row.UpdatedAt.Time}
}
