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
	"github.com/plystra/auth/internal/requestinfo"
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
type SignInStartOutput struct {
	Body struct {
		Data account.SignInChallenge `json:"data"`
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
type MembersInput struct {
	Authorization string `header:"Authorization"`
	Type          string `query:"type"`
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
type PermissionsOutput struct {
	Body struct {
		Data []authorization.EffectivePermission `json:"data"`
	}
}
type LoginInput struct {
	Body          AuthBody
	XForwardedFor string `header:"X-Forwarded-For"`
	UserAgent     string `header:"User-Agent"`
}
type SignInStartInput struct {
	Body struct {
		Email string `json:"email"`
	}
	XForwardedFor string `header:"X-Forwarded-For"`
	UserAgent     string `header:"User-Agent"`
}
type SignInAttemptInput struct {
	AttemptID string `path:"attempt_id"`
	Body      struct {
		Password string `json:"password"`
	}
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
type LogoutInput struct {
	Authorization string `header:"Authorization"`
	Body          *struct {
		All bool `json:"all,omitempty"`
	}
}
type SessionPathInput struct {
	Authorization string `header:"Authorization"`
	ID            string `path:"id"`
}
type SessionsOutput struct {
	Body struct {
		Data []session.DeviceSession `json:"data"`
	}
}
type SessionOutput struct {
	Body struct {
		Data struct {
			Revoked bool `json:"revoked"`
		} `json:"data"`
	}
}

func (a *API) Register(api huma.API) {
	route.Register(api, route.Spec{Name: "auth.sign_up", Method: "POST", Path: "/v1/auth/sign-up", Plane: route.Principal, Subjects: []route.Subject{route.Public}}, a.register)
	route.Register(api, route.Spec{Name: "auth.sign_in", Method: "POST", Path: "/v1/auth/sign-in", Plane: route.Principal, Subjects: []route.Subject{route.Public}}, a.login)
	route.Register(api, route.Spec{Name: "auth.sign_in_attempt", Method: "POST", Path: "/v1/auth/sign-in/{attempt_id}", Plane: route.Principal, Subjects: []route.Subject{route.Public}}, a.loginAttempt)
	route.Register(api, route.Spec{Name: "auth.refresh", Method: "POST", Path: "/v1/auth/refresh", Plane: route.Principal, Subjects: []route.Subject{route.Public}}, a.refresh)
	route.Register(api, route.Spec{Name: "auth.me", Method: "GET", Path: "/v1/me", Plane: route.Principal, Permission: "self:read", Subjects: []route.Subject{route.HumanAgent}}, a.me)
	route.Register(api, route.Spec{Name: "auth.me_permissions", Method: "GET", Path: "/v1/me/permissions", Plane: route.Principal, Permission: "self:read", Subjects: []route.Subject{route.HumanAgent}}, a.mePermissions)
	route.Register(api, route.Spec{Name: "auth.me_members", Method: "GET", Path: "/v1/me/members", Plane: route.Principal, Subjects: []route.Subject{route.User}}, a.meMembers)
	route.Register(api, route.Spec{Name: "auth.sign_out", Method: "POST", Path: "/v1/auth/sign-out", Plane: route.Principal, Subjects: []route.Subject{route.User}}, a.logout)
	route.Register(api, route.Spec{Name: "auth.sessions.list", Method: "GET", Path: "/v1/me/sessions", Plane: route.Principal, Subjects: []route.Subject{route.User}}, a.listSessions)
	route.Register(api, route.Spec{Name: "auth.sessions.revoke", Method: "DELETE", Path: "/v1/me/sessions/{id}", Plane: route.Principal, Subjects: []route.Subject{route.User}}, a.revokeSession)
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
func (a *API) login(ctx context.Context, in *SignInStartInput) (*SignInStartOutput, error) {
	ip := requestinfo.Get(ctx).IP
	if len(ip) == 0 && in.XForwardedFor != "" {
		ip = net.ParseIP(strings.TrimSpace(strings.Split(in.XForwardedFor, ",")[0]))
	}
	result, e := a.Accounts.BeginSignIn(ctx, account.LoginInput{Email: in.Body.Email, IP: ip, UserAgent: in.UserAgent})
	if e != nil {
		return nil, e
	}
	out := &SignInStartOutput{}
	out.Body.Data = result
	return out, nil
}
func (a *API) loginAttempt(ctx context.Context, in *SignInAttemptInput) (*AuthOutput, error) {
	ip := requestinfo.Get(ctx).IP
	if len(ip) == 0 && in.XForwardedFor != "" {
		ip = net.ParseIP(strings.TrimSpace(strings.Split(in.XForwardedFor, ",")[0]))
	}
	result, err := a.Accounts.CompleteSignIn(ctx, in.AttemptID, in.Body.Password, ip, in.UserAgent)
	if err != nil {
		return nil, err
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

func (a *API) meMembers(ctx context.Context, in *MembersInput) (*MembersOutput, error) {
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
	members, err := a.Authorization.ListMembersForUser(ctx, claims.Subject, strings.TrimSpace(in.Type))
	if err != nil {
		return nil, err
	}
	out := &MembersOutput{}
	out.Body.Data = members
	return out, nil
}

func (a *API) mePermissions(ctx context.Context, in *BearerInput) (*PermissionsOutput, error) {
	member, _, err := a.authorizeCurrentMember(ctx, in.Authorization, "self:read")
	if err != nil {
		return nil, err
	}
	permissions, err := a.Authorization.ListEffectivePermissions(ctx, member.ID)
	if err != nil {
		return nil, err
	}
	out := &PermissionsOutput{}
	out.Body.Data = permissions
	return out, nil
}

func (a *API) logout(ctx context.Context, in *LogoutInput) (*LogoutOutput, error) {
	claims, e := a.userClaims(ctx, in.Authorization)
	if e != nil {
		return nil, e
	}
	if claims.SessionID == "" {
		return nil, apierr.New("unauthorized", "session claim is required")
	}
	if in.Body != nil && in.Body.All {
		e = a.Sessions.RevokeAllUserSessions(ctx, claims.Subject)
	} else {
		e = a.Sessions.Revoke(ctx, claims.SessionID)
	}
	if e != nil {
		return nil, e
	}
	out := &LogoutOutput{}
	out.Body.Data.Revoked = true
	return out, nil
}

func (a *API) listSessions(ctx context.Context, in *BearerInput) (*SessionsOutput, error) {
	claims, err := a.userClaims(ctx, in.Authorization)
	if err != nil {
		return nil, err
	}
	sessions, err := a.Sessions.ListUserSessions(ctx, claims.Subject)
	if err != nil {
		return nil, err
	}
	out := &SessionsOutput{}
	out.Body.Data = sessions
	return out, nil
}

func (a *API) revokeSession(ctx context.Context, in *SessionPathInput) (*SessionOutput, error) {
	claims, err := a.userClaims(ctx, in.Authorization)
	if err != nil {
		return nil, err
	}
	if err := a.Sessions.RevokeUserSession(ctx, claims.Subject, in.ID); err != nil {
		return nil, err
	}
	out := &SessionOutput{}
	out.Body.Data.Revoked = true
	return out, nil
}

func (a *API) userClaims(ctx context.Context, authorization string) (security.Claims, error) {
	parts := strings.Fields(authorization)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
		return security.Claims{}, apierr.New("UNAUTHENTICATED", "A bearer access token is required.")
	}
	if a.Sessions == nil {
		claims, err := bearer(a.Signer, authorization)
		if err != nil {
			return security.Claims{}, err
		}
		if claims.Type != "user" {
			return security.Claims{}, apierr.New("USER_ACCOUNT_REQUIRED", "this operation requires a user account")
		}
		return security.Claims{}, apierr.New("UNAVAILABLE", "authentication is unavailable")
	}
	claims, active, err := a.Sessions.Introspect(ctx, parts[1], security.DefaultApplicationAudience)
	if err != nil {
		return security.Claims{}, err
	}
	if !active {
		return security.Claims{}, apierr.New("UNAUTHENTICATED", "The access token is invalid.")
	}
	if claims.Type != "user" {
		return security.Claims{}, apierr.New("USER_ACCOUNT_REQUIRED", "this operation requires a user account")
	}
	return claims, nil
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
	if e := a.Accounts.VerifyEmail(ctx, in.Body.Token, requestinfo.Get(ctx).IP); e != nil {
		return nil, e
	}
	out := &GenericOutput{}
	out.Body.Data.Accepted = true
	return out, nil
}
func (a *API) passwordResetRequest(ctx context.Context, in *ResetRequestInput) (*GenericOutput, error) {
	_, e := a.Accounts.RequestPasswordReset(ctx, in.Body.Email, requestinfo.Get(ctx).IP)
	if e != nil {
		return nil, e
	}
	out := &GenericOutput{}
	out.Body.Data.Accepted = true
	return out, nil
}
func (a *API) passwordResetConfirm(ctx context.Context, in *ResetConfirmInput) (*GenericOutput, error) {
	if e := a.Accounts.ResetPassword(ctx, in.Body.Token, in.Body.Password, requestinfo.Get(ctx).IP); e != nil {
		return nil, e
	}
	out := &GenericOutput{}
	out.Body.Data.Accepted = true
	return out, nil
}
