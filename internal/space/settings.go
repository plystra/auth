package space

import (
	"context"
	"encoding/json"
	"errors"
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
func (s *Service) Update(ctx context.Context, in InstanceSettings, actor string) (InstanceSettings, error) {
	origins, _ := json.Marshal(in.AllowedOrigins)
	var row db.InstanceSetting
	e := s.Store.InTx(ctx, func(q *db.Queries) error {
		p := db.UpdateInstanceSettingsParams{}
		p.RegistrationMode = pgtype.Text{String: in.RegistrationMode, Valid: in.RegistrationMode != ""}
		p.RequireEmailVerification = pgtype.Bool{Bool: in.RequireEmailVerification, Valid: true}
		p.AllowedOrigins = origins
		p.PasswordMinLength = pgtype.Int4{Int32: int32(in.PasswordMinLength), Valid: in.PasswordMinLength > 0}
		p.AccessTokenTtlSeconds = pgtype.Int4{Int32: int32(in.AccessTokenTTL / time.Second), Valid: in.AccessTokenTTL > 0}
		p.RefreshTokenTtlSeconds = pgtype.Int4{Int32: int32(in.RefreshTokenTTL / time.Second), Valid: in.RefreshTokenTTL > 0}
		p.RefreshIdleTtlSeconds = pgtype.Int4{Int32: int32(in.RefreshIdleTTL / time.Second), Valid: in.RefreshIdleTTL > 0}
		p.UpdatedBy = pgtype.Text{String: actor, Valid: actor != ""}
		var e error
		row, e = q.UpdateInstanceSettings(ctx, p)
		return e
	})
	if e != nil {
		return InstanceSettings{}, e
	}
	return decode(row), nil
}
func decode(row db.InstanceSetting) InstanceSettings {
	var origins []string
	_ = json.Unmarshal(row.AllowedOrigins, &origins)
	return InstanceSettings{RegistrationMode: row.RegistrationMode, RequireEmailVerification: row.RequireEmailVerification, AllowedOrigins: origins, PasswordMinLength: int(row.PasswordMinLength), AccessTokenTTL: time.Duration(row.AccessTokenTtlSeconds) * time.Second, RefreshTokenTTL: time.Duration(row.RefreshTokenTtlSeconds) * time.Second, RefreshIdleTTL: time.Duration(row.RefreshIdleTtlSeconds) * time.Second, UpdatedAt: row.UpdatedAt.Time}
}

var _ = errors.New
