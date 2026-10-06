package principal

import (
	"context"
	"net"
	"strings"
	"time"

	"github.com/danielgtaylor/huma/v2"
	"github.com/plystra/auth/internal/account"
	"github.com/plystra/auth/internal/agent"
	"github.com/plystra/auth/internal/apierr"
	"github.com/plystra/auth/internal/authorization"
	"github.com/plystra/auth/internal/route"
	"github.com/plystra/auth/internal/security"
	"github.com/plystra/auth/internal/session"
)

type API struct {
	Accounts      *account.Service
	Sessions      *session.Service
	Signer        *security.Signer
	Authorization *authorization.Service
	Agents        *agent.Service
}
type AuthBody struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}
type AuthInput struct{ Body AuthBody }
type AuthOutput struct {
	Body struct {
		Data account.AuthResult `json:"data"`
	}
}
type RefreshInput struct {
	Body struct {
		RefreshToken string `json:"refresh_token"`
		MemberID     string `json:"member_id,omitempty"`
	}
}
type RefreshOutput struct {
	Body struct {
		Data session.Tokens `json:"data"`
	}
}
type BearerInput struct {
	Authorization string `header:"Authorization"`
}
type MeOutput struct {
	Body struct {
		Data any `json:"data"`
	}
}
type MembersOutput struct {
	Body struct {
		Data []authorization.Member `json:"data"`
	}
}
type LoginInput struct {
	Body          AuthBody
	XForwardedFor string `header:"X-Forwarded-For"`
	UserAgent     string `header:"User-Agent"`
}
type VerifyEmailInput struct {
	Body struct {
		Token string `json:"token"`
	}
}
type GenericOutput struct {
	Body struct {
		Data struct {
			Accepted bool `json:"accepted"`
		} `json:"data"`
	}
}
type ResetRequestInput struct {
	Body struct {
		Email string `json:"email"`
	}
}
type ResetConfirmInput struct {
	Body struct {
		Token    string `json:"token"`
		Password string `json:"password"`
	}
}
type LogoutOutput struct {
	Body struct {
		Data struct {
			Revoked bool `json:"revoked"`
		} `json:"data"`
	}
}

func (a *API) Register(api huma.API) {
	route.Register(api, route.Spec{Name: "auth.sign_up", Method: "POST", Path: "/v1/auth/sign-up", Plane: route.Principal, Subjects: []route.Subject{route.Public}}, a.register)
	route.Register(api, route.Spec{Name: "auth.sign_in", Method: "POST", Path: "/v1/auth/sign-in", Plane: route.Principal, Subjects: []route.Subject{route.Public}}, a.login)
	route.Register(api, route.Spec{Name: "auth.refresh", Method: "POST", Path: "/v1/auth/refresh", Plane: route.Principal, Subjects: []route.Subject{route.Public}}, a.refresh)
	route.Register(api, route.Spec{Name: "auth.me", Method: "GET", Path: "/v1/me", Plane: route.Principal, Permission: "self:read", Subjects: []route.Subject{route.HumanAgent}}, a.me)
	route.Register(api, route.Spec{Name: "auth.me_members", Method: "GET", Path: "/v1/me/members", Plane: route.Principal, Subjects: []route.Subject{route.User}}, a.meMembers)
	route.Register(api, route.Spec{Name: "auth.sign_out", Method: "POST", Path: "/v1/auth/sign-out", Plane: route.Principal, Subjects: []route.Subject{route.User}}, a.logout)
	route.Register(api, route.Spec{Name: "auth.email_verify", Method: "POST", Path: "/v1/auth/email/verify", Plane: route.Principal, Subjects: []route.Subject{route.Public}}, a.verifyEmail)
	route.Register(api, route.Spec{Name: "auth.password_forgot", Method: "POST", Path: "/v1/auth/password/forgot", Plane: route.Principal, Subjects: []route.Subject{route.Public}}, a.passwordResetRequest)
	route.Register(api, route.Spec{Name: "auth.password_reset", Method: "POST", Path: "/v1/auth/password/reset", Plane: route.Principal, Subjects: []route.Subject{route.Public}}, a.passwordResetConfirm)
	a.registerAgentRoutes(api)
	a.registerAuthorizationRoutes(api)
}
func (a *API) register(ctx context.Context, in *AuthInput) (*AuthOutput, error) {
	r := in.Body
	result, e := a.Accounts.Register(ctx, account.RegisterInput{Email: r.Email, Password: r.Password}, nil, "")
	if e != nil {
		return nil, e
	}
	out := &AuthOutput{}
	out.Body.Data = result
	return out, nil
}
func (a *API) login(ctx context.Context, in *LoginInput) (*AuthOutput, error) {
	var ip net.IP
	if in.XForwardedFor != "" {
		ip = net.ParseIP(strings.TrimSpace(strings.Split(in.XForwardedFor, ",")[0]))
	}
	result, e := a.Accounts.Login(ctx, account.LoginInput{Email: in.Body.Email, Password: in.Body.Password, IP: ip, UserAgent: in.UserAgent})
	if e != nil {
		return nil, e
	}
	out := &AuthOutput{}
	out.Body.Data = result
	return out, nil
}
func (a *API) refresh(ctx context.Context, in *RefreshInput) (*RefreshOutput, error) {
	if strings.TrimSpace(in.Body.RefreshToken) == "" {
		return nil, apierr.New("invalid_request", "refresh_token is required")
	}
	tokens, e := a.Sessions.RefreshForMember(ctx, in.Body.RefreshToken, strings.TrimSpace(in.Body.MemberID))
	if e != nil {
		return nil, e
	}
	out := &RefreshOutput{}
	out.Body.Data = tokens
	return out, nil
}
func (a *API) me(ctx context.Context, in *BearerInput) (*MeOutput, error) {
	parts := strings.Fields(in.Authorization)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
		return nil, apierr.New("UNAUTHENTICATED", "A user access token is required.")
	}
	claims, active, e := a.Sessions.Introspect(ctx, parts[1], security.DefaultApplicationAudience)
	if e != nil {
		return nil, e
	}
	if !active {
		return nil, apierr.New("UNAUTHENTICATED", "A user access token is required.")
	}
	if _, _, err := a.authorizeCurrentMember(ctx, in.Authorization, "self:read"); err != nil {
		return nil, err
	}
	out := &MeOutput{}
	if claims.Type == "agent" {
		if a.Agents == nil {
			return nil, apierr.New("UNAVAILABLE", "agent service is unavailable")
		}
		ag, err := a.Agents.Get(ctx, claims.Subject)
		if err != nil {
			return nil, err
		}
		out.Body.Data = struct {
			Type  string      `json:"type"`
			Agent agent.Agent `json:"agent"`
		}{Type: "agent", Agent: ag}
	} else {
		u, e := a.Accounts.Me(ctx, claims)
		if e != nil {
			return nil, e
		}
		out.Body.Data = u
	}
	return out, nil
}

func (a *API) meMembers(ctx context.Context, in *BearerInput) (*MembersOutput, error) {
	parts := strings.Fields(in.Authorization)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
		return nil, apierr.New("UNAUTHENTICATED", "A user access token is required.")
	}
	if a.Sessions == nil || a.Authorization == nil {
		return nil, apierr.New("UNAVAILABLE", "authentication is unavailable")
	}
	claims, active, err := a.Sessions.Introspect(ctx, parts[1], security.DefaultApplicationAudience)
	if err != nil {
		return nil, err
	}
	if !active {
		return nil, apierr.New("UNAUTHENTICATED", "A user access token is required.")
	}
	if claims.Type != "user" {
		return nil, apierr.New("USER_ACCOUNT_REQUIRED", "this operation requires a user account")
	}
	members, err := a.Authorization.ListMembersForUser(ctx, claims.Subject)
	if err != nil {
		return nil, err
	}
	out := &MembersOutput{}
	out.Body.Data = members
	return out, nil
}

func (a *API) logout(ctx context.Context, in *BearerInput) (*LogoutOutput, error) {
	claims, e := bearer(a.Signer, in.Authorization)
	if e != nil {
		return nil, e
	}
	if claims.Type != "user" {
		return nil, apierr.New("USER_ACCOUNT_REQUIRED", "this operation requires a user account")
	}
	if claims.SessionID == "" {
		return nil, apierr.New("unauthorized", "session claim is required")
	}
	if e = a.Sessions.Revoke(ctx, claims.SessionID); e != nil {
		return nil, e
	}
	out := &LogoutOutput{}
	out.Body.Data.Revoked = true
	return out, nil
}
func bearer(s *security.Signer, value string) (security.Claims, error) {
	parts := strings.Fields(value)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
		return security.Claims{}, apierr.New("unauthorized", "bearer token is required")
	}
	c, e := s.Verify(parts[1], nowUTC(), security.DefaultApplicationAudience)
	if e != nil {
		return security.Claims{}, apierr.New("unauthorized", "access token is invalid")
	}
	return c, nil
}

var nowUTC = func() time.Time { return time.Now().UTC() }

func (a *API) verifyEmail(ctx context.Context, in *VerifyEmailInput) (*GenericOutput, error) {
	if strings.TrimSpace(in.Body.Token) == "" {
		return nil, apierr.New("invalid_request", "token is required")
	}
	if e := a.Accounts.VerifyEmail(ctx, in.Body.Token); e != nil {
		return nil, e
	}
	out := &GenericOutput{}
	out.Body.Data.Accepted = true
	return out, nil
}
func (a *API) passwordResetRequest(ctx context.Context, in *ResetRequestInput) (*GenericOutput, error) {
	_, e := a.Accounts.RequestPasswordReset(ctx, in.Body.Email)
	if e != nil {
		return nil, e
	}
	out := &GenericOutput{}
	out.Body.Data.Accepted = true
	return out, nil
}
func (a *API) passwordResetConfirm(ctx context.Context, in *ResetConfirmInput) (*GenericOutput, error) {
	if e := a.Accounts.ResetPassword(ctx, in.Body.Token, in.Body.Password); e != nil {
		return nil, e
	}
	out := &GenericOutput{}
	out.Body.Data.Accepted = true
	return out, nil
}
