package ops

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"strings"
	"time"

	"github.com/danielgtaylor/huma/v2"
	"github.com/plystra/auth/internal/apierr"
	"github.com/plystra/auth/internal/db"
	"github.com/plystra/auth/internal/operator"
	"github.com/plystra/auth/internal/requestinfo"
	"github.com/plystra/auth/internal/route"
	"github.com/plystra/auth/internal/secret"
	"github.com/plystra/auth/internal/space"
)

type API struct {
	Settings  *space.Service
	Operators *operator.Service
}
type SignInInput struct {
	Body struct {
		Email    string        `json:"email" maxLength:"254"`
		Password secret.Secret `json:"password" minLength:"1" maxLength:"1024"`
		MFACode  secret.Secret `json:"mfa_code" minLength:"6" maxLength:"6"`
	}
	UserAgent string `header:"User-Agent" maxLength:"1024"`
}
type SignInOutput struct {
	Body struct {
		Data struct {
			AccessToken secret.Secret `json:"access_token"`
			TokenType   string        `json:"token_type"`
			ExpiresAt   time.Time     `json:"expires_at"`
		} `json:"data"`
	}
}
type AuthInput struct {
	Authorization string `header:"Authorization"`
}
type StepUpInput struct {
	Authorization string `header:"Authorization"`
	Body          struct {
		Code      secret.Secret       `json:"mfa_code" minLength:"6" maxLength:"6"`
		Operation string              `json:"operation" enum:"ops.settings.update"`
		Request   space.SettingsPatch `json:"request"`
	}
}
type AcceptedOutput struct {
	Body struct {
		Data struct {
			Accepted bool `json:"accepted"`
		} `json:"data"`
	}
}
type SettingsOutput struct {
	Body struct {
		Data space.InstanceSettings `json:"data"`
	}
}
type SettingsInput struct {
	Authorization string `header:"Authorization"`
	Body          space.SettingsPatch
}

func (a *API) Register(api huma.API) {
	route.Register(api, route.Spec{Name: "ops.auth.sign_in", Method: "POST", Path: "/ops/v1/auth/sign-in", Plane: route.Ops, Subjects: []route.Subject{route.Public}}, a.signIn)
	route.Register(api, route.Spec{Name: "ops.auth.step_up", Method: "POST", Path: "/ops/v1/auth/step-up", Plane: route.Ops, Permission: "ops:session", Subjects: []route.Subject{route.Human}}, a.stepUp)
	route.Register(api, route.Spec{Name: "ops.auth.sign_out", Method: "POST", Path: "/ops/v1/auth/sign-out", Plane: route.Ops, Permission: "ops:session", Subjects: []route.Subject{route.Human}}, a.signOut)
	route.Register(api, route.Spec{Name: "ops.settings.get", Method: "GET", Path: "/ops/v1/settings", Plane: route.Ops, Permission: "ops:settings:read", Subjects: []route.Subject{route.Human}}, a.get)
	route.Register(api, route.Spec{Name: "ops.settings.update", Method: "PATCH", Path: "/ops/v1/settings", Plane: route.Ops, Permission: "ops:settings:write", Subjects: []route.Subject{route.Human}, StepUp: true}, a.update)
}
func (a *API) signIn(ctx context.Context, in *SignInInput) (*SignInOutput, error) {
	s, err := a.Operators.SignIn(ctx, in.Body.Email, in.Body.Password.Value(), in.Body.MFACode.Value(), requestinfo.Get(ctx).IP, in.UserAgent)
	if err != nil {
		return nil, err
	}
	out := &SignInOutput{}
	out.Body.Data.AccessToken = s.Token
	out.Body.Data.TokenType = "Bearer"
	out.Body.Data.ExpiresAt = s.ExpiresAt
	return out, nil
}
func (a *API) stepUp(ctx context.Context, in *StepUpInput) (*AcceptedOutput, error) {
	token, err := bearer(in.Authorization)
	if err != nil {
		return nil, err
	}
	digest, err := settingsDigest(in.Body.Request)
	if err != nil {
		return nil, err
	}
	if err = a.Operators.StepUp(ctx, token, in.Body.Code.Value(), in.Body.Operation, digest); err != nil {
		return nil, err
	}
	return accepted(), nil
}
func (a *API) signOut(ctx context.Context, in *AuthInput) (*AcceptedOutput, error) {
	token, err := bearer(in.Authorization)
	if err != nil {
		return nil, err
	}
	if err = a.Operators.SignOut(ctx, token); err != nil {
		return nil, err
	}
	return accepted(), nil
}
func (a *API) get(ctx context.Context, in *AuthInput) (*SettingsOutput, error) {
	token, err := bearer(in.Authorization)
	if err != nil {
		return nil, err
	}
	out := &SettingsOutput{}
	err = a.Operators.Run(ctx, token, "ops.settings.get", "ops:settings:read", nil, func(q *db.Queries, _ operator.Session) error {
		var err error
		out.Body.Data, err = a.Settings.Get(ctx)
		return err
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}
func (a *API) update(ctx context.Context, in *SettingsInput) (*SettingsOutput, error) {
	token, err := bearer(in.Authorization)
	if err != nil {
		return nil, err
	}
	digest, err := settingsDigest(in.Body)
	if err != nil {
		return nil, err
	}
	out := &SettingsOutput{}
	err = a.Operators.Run(ctx, token, "ops.settings.update", "ops:settings:write", digest, func(q *db.Queries, s operator.Session) error {
		var err error
		out.Body.Data, err = a.Settings.UpdateTx(ctx, q, in.Body, s.UserID)
		return err
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}
func settingsDigest(in space.SettingsPatch) ([]byte, error) {
	raw, err := json.Marshal(in)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(raw)
	return sum[:], nil
}
func bearer(value string) (string, error) {
	parts := strings.Fields(value)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
		return "", apierr.New("UNAUTHENTICATED", "An operations session is required.")
	}
	return parts[1], nil
}
func accepted() *AcceptedOutput {
	out := &AcceptedOutput{}
	out.Body.Data.Accepted = true
	return out
}
