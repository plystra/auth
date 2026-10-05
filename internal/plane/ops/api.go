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
		Code      secret.Secret   `json:"mfa_code" minLength:"6" maxLength:"6"`
		Operation string          `json:"operation" enum:"ops.settings.update,ops.operators.create,ops.operators.update,ops.operators.disable"`
		Request   json.RawMessage `json:"request" minLength:"2"`
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
type OperatorsInput struct {
	Authorization string `header:"Authorization"`
}
type OperatorChangeInput struct {
	Authorization string `header:"Authorization"`
	ID            string `path:"id"`
	Body          struct {
		Capabilities []string `json:"capabilities" minItems:"1" maxItems:"32"`
	}
}
type OperatorCreateInput struct {
	Authorization string `header:"Authorization"`
	Body          struct {
		UserID       string   `json:"user_id" minLength:"1" maxLength:"128"`
		Capabilities []string `json:"capabilities" minItems:"1" maxItems:"32"`
	}
}
type OperatorDisableInput struct {
	Authorization string `header:"Authorization"`
	ID            string `path:"id"`
}
type OperatorOutput struct {
	Body struct {
		Data operator.Operator `json:"data"`
	}
}
type OperatorsOutput struct {
	Body struct {
		Data []operator.Operator `json:"data"`
	}
}
type OperatorCreateOutput struct {
	Body struct {
		Data operator.OperatorCreate `json:"data"`
	}
}

func (a *API) Register(api huma.API) {
	route.Register(api, route.Spec{Name: "ops.auth.sign_in", Method: "POST", Path: "/ops/v1/auth/sign-in", Plane: route.Ops, Subjects: []route.Subject{route.Public}}, a.signIn)
	route.Register(api, route.Spec{Name: "ops.auth.step_up", Method: "POST", Path: "/ops/v1/auth/step-up", Plane: route.Ops, Permission: "ops:session", Subjects: []route.Subject{route.Human}}, a.stepUp)
	route.Register(api, route.Spec{Name: "ops.auth.sign_out", Method: "POST", Path: "/ops/v1/auth/sign-out", Plane: route.Ops, Permission: "ops:session", Subjects: []route.Subject{route.Human}}, a.signOut)
	route.Register(api, route.Spec{Name: "ops.settings.get", Method: "GET", Path: "/ops/v1/settings", Plane: route.Ops, Permission: "ops:settings:read", Subjects: []route.Subject{route.Human}}, a.get)
	route.Register(api, route.Spec{Name: "ops.settings.update", Method: "PATCH", Path: "/ops/v1/settings", Plane: route.Ops, Permission: "ops:settings:write", Subjects: []route.Subject{route.Human}, StepUp: true}, a.update)
	route.Register(api, route.Spec{Name: "ops.operators.list", Method: "GET", Path: "/ops/v1/operators", Plane: route.Ops, Permission: "ops:operators:read", Subjects: []route.Subject{route.Human}}, a.listOperators)
	route.Register(api, route.Spec{Name: "ops.operators.create", Method: "POST", Path: "/ops/v1/operators", Plane: route.Ops, Permission: "ops:operators:manage", Subjects: []route.Subject{route.Human}, StepUp: true}, a.createOperator)
	route.Register(api, route.Spec{Name: "ops.operators.update", Method: "PATCH", Path: "/ops/v1/operators/{id}", Plane: route.Ops, Permission: "ops:operators:manage", Subjects: []route.Subject{route.Human}, StepUp: true}, a.updateOperator)
	route.Register(api, route.Spec{Name: "ops.operators.disable", Method: "POST", Path: "/ops/v1/operators/{id}/disable", Plane: route.Ops, Permission: "ops:operators:manage", Subjects: []route.Subject{route.Human}, StepUp: true}, a.disableOperator)
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
	digest, err := canonicalDigest(in.Body.Request)
	if err != nil {
		return nil, err
	}
	if err = a.Operators.StepUp(ctx, token, in.Body.Code.Value(), in.Body.Operation, digest); err != nil {
		return nil, err
	}
	return accepted(), nil
}

func (a *API) listOperators(ctx context.Context, in *OperatorsInput) (*OperatorsOutput, error) {
	token, err := bearer(in.Authorization)
	if err != nil {
		return nil, err
	}
	items, err := a.Operators.List(ctx, token)
	if err != nil {
		return nil, err
	}
	out := &OperatorsOutput{}
	out.Body.Data = items
	return out, nil
}

func (a *API) createOperator(ctx context.Context, in *OperatorCreateInput) (*OperatorCreateOutput, error) {
	token, err := bearer(in.Authorization)
	if err != nil {
		return nil, err
	}
	digest, err := canonicalDigestValue(in.Body)
	if err != nil {
		return nil, err
	}
	created, err := a.Operators.Create(ctx, token, in.Body.UserID, in.Body.Capabilities, digest)
	if err != nil {
		return nil, err
	}
	out := &OperatorCreateOutput{}
	out.Body.Data = created
	return out, nil
}

func (a *API) updateOperator(ctx context.Context, in *OperatorChangeInput) (*AcceptedOutput, error) {
	token, err := bearer(in.Authorization)
	if err != nil {
		return nil, err
	}
	digest, err := canonicalDigestValue(struct {
		ID           string   `json:"id"`
		Capabilities []string `json:"capabilities"`
	}{ID: in.ID, Capabilities: in.Body.Capabilities})
	if err != nil {
		return nil, err
	}
	if err = a.Operators.UpdateCapabilities(ctx, token, in.ID, in.Body.Capabilities, digest); err != nil {
		return nil, err
	}
	return accepted(), nil
}

func (a *API) disableOperator(ctx context.Context, in *OperatorDisableInput) (*AcceptedOutput, error) {
	token, err := bearer(in.Authorization)
	if err != nil {
		return nil, err
	}
	digest, err := canonicalDigestValue(struct {
		ID string `json:"id"`
	}{ID: in.ID})
	if err != nil {
		return nil, err
	}
	if err = a.Operators.Disable(ctx, token, in.ID, digest); err != nil {
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
	return canonicalDigestValue(in)
}
func canonicalDigest(raw json.RawMessage) ([]byte, error) {
	var value any
	if err := json.Unmarshal(raw, &value); err != nil {
		return nil, apierr.New("VALIDATION_FAILED", "request must contain valid JSON.")
	}
	return canonicalDigestValue(value)
}
func canonicalDigestValue(value any) ([]byte, error) {
	raw, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	var canonical any
	if err := json.Unmarshal(raw, &canonical); err != nil {
		return nil, apierr.New("VALIDATION_FAILED", "request must contain valid JSON.")
	}
	raw, err = json.Marshal(canonical)
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
