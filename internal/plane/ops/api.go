package ops

import (
	"context"
	"strings"
	"time"

	"github.com/danielgtaylor/huma/v2"
	"github.com/plystra/auth/internal/apierr"
	"github.com/plystra/auth/internal/route"
	"github.com/plystra/auth/internal/security"
	"github.com/plystra/auth/internal/space"
)

type API struct {
	Settings *space.Service
	Signer   *security.Signer
}
type AuthInput struct {
	Authorization string `header:"Authorization"`
}
type SettingsOutput struct {
	Body struct {
		Data space.InstanceSettings `json:"data"`
	}
}
type SettingsInput struct {
	Authorization string `header:"Authorization"`
	Body          space.InstanceSettings
}

func (a *API) Register(api huma.API) {
	route.Register(api, route.Spec{Name: "ops.settings.get", Method: "GET", Path: "/ops/v1/settings", Plane: route.Ops, Permission: "ops:settings:read", Subjects: []route.Subject{route.Human}}, a.get)
	route.Register(api, route.Spec{Name: "ops.settings.update", Method: "PATCH", Path: "/ops/v1/settings", Plane: route.Ops, Permission: "ops:settings:write", Subjects: []route.Subject{route.Human}, StepUp: true}, a.update)
}
func (a *API) authorize(value string) (security.Claims, error) {
	parts := strings.Fields(value)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
		return security.Claims{}, apierr.New("unauthorized", "operator bearer token is required")
	}
	c, e := a.Signer.Verify(parts[1], time.Now().UTC(), "principal")
	if e != nil {
		return security.Claims{}, apierr.New("unauthorized", "operator token is invalid")
	}
	return c, nil
}
func (a *API) get(ctx context.Context, in *AuthInput) (*SettingsOutput, error) {
	if _, e := a.authorize(in.Authorization); e != nil {
		return nil, e
	}
	v, e := a.Settings.Get(ctx)
	if e != nil {
		return nil, e
	}
	out := &SettingsOutput{}
	out.Body.Data = v
	return out, nil
}
func (a *API) update(ctx context.Context, in *SettingsInput) (*SettingsOutput, error) {
	c, e := a.authorize(in.Authorization)
	if e != nil {
		return nil, e
	}
	v, e := a.Settings.Update(ctx, in.Body, c.Subject)
	if e != nil {
		return nil, e
	}
	out := &SettingsOutput{}
	out.Body.Data = v
	return out, nil
}
