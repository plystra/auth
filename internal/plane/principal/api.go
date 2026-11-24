package principal

import (
	"context"
	"encoding/json"
	"net"
	"strings"

	"github.com/danielgtaylor/huma/v2"
	"github.com/plystra/auth/internal/account"
	"github.com/plystra/auth/internal/agent"
	"github.com/plystra/auth/internal/apierr"
	"github.com/plystra/auth/internal/application"
	"github.com/plystra/auth/internal/approval"
	"github.com/plystra/auth/internal/authorization"
	"github.com/plystra/auth/internal/enterprise"
	"github.com/plystra/auth/internal/factor"
	"github.com/plystra/auth/internal/invitation"
	"github.com/plystra/auth/internal/requestinfo"
	"github.com/plystra/auth/internal/route"
	"github.com/plystra/auth/internal/secret"
	"github.com/plystra/auth/internal/security"
	"github.com/plystra/auth/internal/session"
	"github.com/plystra/auth/internal/stepup"
)

type API struct {
	HostedOrigin  string
	Accounts      *account.Service
	Sessions      *session.Service
	Signer        *security.Signer
	Authorization *authorization.Service
	Agents        *agent.Service
	Invitations   *invitation.Service
	Factors       *factor.Service
	Approvals     *approval.Service
	Applications  *application.Service
	Enterprise    *enterprise.Service
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
type AcceptInvitationInput struct {
	Authorization string `header:"Authorization"`
	Body          struct {
		Token    secret.String `json:"token"`
		Email    string        `json:"email,omitempty"`
		Password secret.String `json:"password,omitempty"`
	}
}
type AcceptInvitationOutput struct {
	Body struct {
		Data invitation.Acceptance `json:"data"`
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
type StepUpInput struct {
	Authorization string `header:"Authorization"`
	Body          struct {
		Code      string          `json:"mfa_code,omitempty" minLength:"6" maxLength:"6"`
		Password  secret.String   `json:"password,omitempty" maxLength:"1024"`
		Operation string          `json:"operation"`
		Request   json.RawMessage `json:"request" minLength:"2"`
	}
}
type StepUpOutput struct {
	Body struct {
		Data struct {
			Accepted bool `json:"accepted"`
		} `json:"data"`
	}
}
type BearerInput struct {
	Authorization string `header:"Authorization"`
}
type MembersInput struct {
	Authorization string `header:"Authorization"`
	Type          string `query:"type"`
}
type MePatchInput struct {
	Authorization string `header:"Authorization"`
	Body          struct {
		Name           *string         `json:"name,omitempty"`
		AvatarURL      *string         `json:"avatar_url,omitempty"`
		PublicMetadata *map[string]any `json:"public_metadata,omitempty"`
	}
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
type FactorsOutput struct {
	Body struct {
		Data []factor.Summary `json:"data"`
	}
}
type FactorsInput struct {
	Authorization string `header:"Authorization"`
	Body          struct {
		Kind        string          `json:"kind" enum:"totp,backup_code,passkey"`
		Name        string          `json:"name,omitempty" maxLength:"100"`
		Count       int             `json:"count,omitempty" minimum:"5" maximum:"20"`
		ChallengeID string          `json:"challenge_id,omitempty"`
		Credential  json.RawMessage `json:"credential,omitempty"`
	}
}
type FactorCreateOutput struct {
	Body struct {
		Data struct {
			Codes    []string                 `json:"codes,omitempty"`
			FactorID string                   `json:"factor_id,omitempty"`
			Secret   string                   `json:"secret,omitempty"`
			URI      string                   `json:"otpauth_uri,omitempty"`
			Passkey  *factor.PasskeyChallenge `json:"passkey,omitempty"`
		} `json:"data"`
	}
}
type FactorPathInput struct {
	Authorization string `header:"Authorization"`
	ID            string `path:"id"`
}
type FactorDeleteOutput struct {
	Body struct {
		Data struct {
			Deleted bool `json:"deleted"`
		} `json:"data"`
	}
}
type LoginInput struct {
	Body          AuthBody
	XForwardedFor string `header:"X-Forwarded-For"`
	UserAgent     string `header:"User-Agent"`
}
type SignInStartInput struct {
	Body struct {
		Email   string `json:"email"`
		Method  string `json:"method,omitempty" enum:"password,passkey"`
		SpaceID string `json:"space_id,omitempty"`
	}
	XForwardedFor string `header:"X-Forwarded-For"`
	UserAgent     string `header:"User-Agent"`
}
type SignInAttemptInput struct {
	AttemptID string `path:"attempt_id"`
	Body      struct {
		Password   string          `json:"password,omitempty"`
		MFACode    string          `json:"mfa_code,omitempty"`
		Credential json.RawMessage `json:"credential,omitempty"`
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
	route.Register(api, route.NewSpec("auth.sign_up", "POST", "/v1/auth/sign-up", route.Principal, "", []route.Subject{route.Public}), a.register)
	route.Register(api, route.NewSpec("invitations.accept", "POST", "/v1/invitations/accept", route.Principal, "", []route.Subject{route.Public, route.User}), a.acceptInvitation)
	route.Register(api, route.NewSpec("auth.sign_in", "POST", "/v1/auth/sign-in", route.Principal, "", []route.Subject{route.Public}), a.login)
	route.Register(api, route.NewSpec("auth.sign_in_attempt", "POST", "/v1/auth/sign-in/{attempt_id}", route.Principal, "", []route.Subject{route.Public}), a.loginAttempt)
	route.Register(api, route.NewSpec("auth.refresh", "POST", "/v1/auth/refresh", route.Principal, "", []route.Subject{route.Public}), a.refresh)
	route.Register(api, route.NewSpec("auth.step_up", "POST", "/v1/auth/step-up", route.Principal, "", []route.Subject{route.User}), a.stepUp)
	route.Register(api, route.NewSpec("auth.me", "GET", "/v1/me", route.Principal, "self:read", []route.Subject{route.HumanAgent}), a.me)
	route.Register(api, route.NewSpec("auth.me_update", "PATCH", "/v1/me", route.Principal, "", []route.Subject{route.User}), a.updateMe)
	route.Register(api, route.NewSpec("auth.me_permissions", "GET", "/v1/me/permissions", route.Principal, "self:read", []route.Subject{route.HumanAgent}), a.mePermissions)
	route.Register(api, route.NewSpec("auth.me_members", "GET", "/v1/me/members", route.Principal, "", []route.Subject{route.User}), a.meMembers)
	route.Register(api, route.NewSpec("auth.factors.list", "GET", "/v1/me/factors", route.Principal, "", []route.Subject{route.User}), a.listFactors)
	route.Register(api, route.NewSpec("auth.factors.create", "POST", "/v1/me/factors", route.Principal, "", []route.Subject{route.User}, route.WithStepUp()), a.createFactor)
	route.Register(api, route.NewSpec("auth.factors.delete", "DELETE", "/v1/me/factors/{id}", route.Principal, "", []route.Subject{route.User}, route.WithStepUp()), a.deleteFactor)
	route.Register(api, route.NewSpec("auth.me_member_remove", "DELETE", "/v1/me/member", route.Principal, "self:read", []route.Subject{route.HumanAgent}, route.WithAuthoritativeCheck()), a.removeCurrentMember)
	route.Register(api, route.NewSpec("auth.sign_out", "POST", "/v1/auth/sign-out", route.Principal, "", []route.Subject{route.User}), a.logout)
	route.Register(api, route.NewSpec("auth.sessions.list", "GET", "/v1/me/sessions", route.Principal, "", []route.Subject{route.User}), a.listSessions)
	route.Register(api, route.NewSpec("auth.sessions.revoke", "DELETE", "/v1/me/sessions/{id}", route.Principal, "", []route.Subject{route.User}), a.revokeSession)
	route.Register(api, route.NewSpec("auth.email_verify", "POST", "/v1/auth/email/verify", route.Principal, "", []route.Subject{route.Public}), a.verifyEmail)
	route.Register(api, route.NewSpec("auth.password_forgot", "POST", "/v1/auth/password/forgot", route.Principal, "", []route.Subject{route.Public}), a.passwordResetRequest)
	route.Register(api, route.NewSpec("auth.password_reset", "POST", "/v1/auth/password/reset", route.Principal, "", []route.Subject{route.Public}), a.passwordResetConfirm)
	a.registerAgentRoutes(api)
	a.registerAuthorizationRoutes(api)
	a.registerApprovalRoutes(api)
	a.registerApplicationRoutes(api)
	a.registerOIDCBrowserRoutes(api)
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
func (a *API) acceptInvitation(ctx context.Context, in *AcceptInvitationInput) (*AcceptInvitationOutput, error) {
	if a.Invitations == nil {
		return nil, apierr.New("UNAVAILABLE", "invitation service is unavailable")
	}
	var accepted invitation.Acceptance
	var err error
	if strings.TrimSpace(in.Authorization) == "" {
		accepted, err = a.Invitations.RegisterNewUser(ctx, in.Body.Token.Value(), in.Body.Email, in.Body.Password.Value())
	} else {
		var claims security.Claims
		claims, err = a.userClaims(ctx, in.Authorization)
		if err == nil {
			accepted, err = a.Invitations.AcceptVerifiedUser(ctx, in.Body.Token.Value(), claims.Subject)
		}
	}
	if err != nil {
		return nil, err
	}
	out := &AcceptInvitationOutput{}
	out.Body.Data = accepted
	return out, nil
}
func (a *API) login(ctx context.Context, in *SignInStartInput) (*SignInStartOutput, error) {
	if a.Enterprise != nil {
		connectionID, err := a.Enterprise.ForcedConnectionForEmail(ctx, in.Body.Email, in.Body.SpaceID)
		if err != nil {
			return nil, err
		}
		if connectionID != "" {
			out := &SignInStartOutput{}
			out.Body.Data = account.SignInChallenge{NextStep: "sso", SSOConnectionID: connectionID}
			return out, nil
		}
	}
	ip := requestinfo.Get(ctx).IP
	if len(ip) == 0 && in.XForwardedFor != "" {
		ip = net.ParseIP(strings.TrimSpace(strings.Split(in.XForwardedFor, ",")[0]))
	}
	login := account.LoginInput{Email: in.Body.Email, SpaceID: strings.TrimSpace(in.Body.SpaceID), IP: ip, UserAgent: in.UserAgent}
	var result account.SignInChallenge
	var e error
	switch in.Body.Method {
	case "passkey":
		result, e = a.Accounts.BeginPasskeySignIn(ctx, login)
	case "", "password":
		result, e = a.Accounts.BeginSignIn(ctx, login)
	default:
		return nil, apierr.New("VALIDATION_FAILED", "sign-in method is invalid")
	}
	if e != nil {
		return nil, e
	}
	out := &SignInStartOutput{}
	out.Body.Data = result
	return out, nil
}
func (a *API) loginAttempt(ctx context.Context, in *SignInAttemptInput) (*AuthOutput, error) {
	steps := 0
	if in.Body.Password != "" {
		steps++
	}
	if in.Body.MFACode != "" {
		steps++
	}
	if len(in.Body.Credential) != 0 {
		steps++
	}
	if steps != 1 {
		return nil, apierr.New("VALIDATION_FAILED", "submit one sign-in step at a time")
	}
	ip := requestinfo.Get(ctx).IP
	if len(ip) == 0 && in.XForwardedFor != "" {
		ip = net.ParseIP(strings.TrimSpace(strings.Split(in.XForwardedFor, ",")[0]))
	}
	var result account.AuthResult
	var err error
	if len(in.Body.Credential) != 0 {
		result, err = a.Accounts.CompletePasskeySignIn(ctx, in.AttemptID, in.Body.Credential, ip, in.UserAgent)
	} else if in.Body.MFACode != "" {
		result, err = a.Accounts.CompleteSignInTOTP(ctx, in.AttemptID, in.Body.MFACode, ip, in.UserAgent)
	} else {
		result, err = a.Accounts.CompleteSignIn(ctx, in.AttemptID, in.Body.Password, ip, in.UserAgent)
	}
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
func (a *API) stepUp(ctx context.Context, in *StepUpInput) (*StepUpOutput, error) {
	claims, err := a.userClaims(ctx, in.Authorization)
	if err != nil {
		return nil, err
	}
	if (in.Body.Code == "") == (in.Body.Password.Value() == "") {
		return nil, apierr.New("VALIDATION_FAILED", "provide exactly one of mfa_code or password")
	}
	if !principalStepUpOperation(in.Body.Operation) {
		return nil, apierr.New("VALIDATION_FAILED", "operation is not supported for principal step-up")
	}
	if in.Body.Password.Value() != "" {
		var request map[string]json.RawMessage
		if err := json.Unmarshal(in.Body.Request, &request); err != nil || len(request) != 2 {
			return nil, apierr.New("VALIDATION_FAILED", "password step-up is only available for first TOTP enrollment")
		}
		var kind, name string
		if err := json.Unmarshal(request["kind"], &kind); err != nil {
			return nil, apierr.New("VALIDATION_FAILED", "first TOTP enrollment request is invalid")
		}
		if err := json.Unmarshal(request["name"], &name); err != nil {
			return nil, apierr.New("VALIDATION_FAILED", "first TOTP enrollment request is invalid")
		}
		if in.Body.Operation != "me.factors.create" || kind != "totp" || name == "" || name != strings.TrimSpace(name) || len(name) > 100 {
			return nil, apierr.New("VALIDATION_FAILED", "password step-up is only available for first TOTP enrollment")
		}
	}
	digest, err := stepup.Digest(in.Body.Request)
	if err != nil {
		return nil, err
	}
	parts := strings.Fields(in.Authorization)
	if len(parts) != 2 || claims.SessionID == "" {
		return nil, apierr.New("UNAUTHENTICATED", "a user access-token session is required")
	}
	if in.Body.Password.Value() != "" {
		err = a.Sessions.StepUpFirstTOTP(ctx, parts[1], in.Body.Password, digest)
	} else {
		err = a.Sessions.StepUp(ctx, parts[1], in.Body.Code, in.Body.Operation, digest)
	}
	if err != nil {
		return nil, err
	}
	out := &StepUpOutput{}
	out.Body.Data.Accepted = true
	return out, nil
}

func principalStepUpOperation(operation string) bool {
	switch operation {
	case "sso_connections.list", "sso_connections.get", "sso_connections.create", enterprise.SSOConnectionUpdateOperation, "sso_connections.delete",
		"domains.list", "domains.create", "domains.verify", "domains.delete",
		"directories.list", "directories.create", "directories.update", "directories.delete":
		return true
	case "members.bindings.create", "members.bindings.revoke", "assignment_rights.list", "assignment_rights.create", "assignment_rights.revoke", "me.agents.create", "me.agents.rotate", "me.factors.create", "me.factors.delete", "approvals.approve", "approvals.reject", "applications.register", "applications.update", "applications.oauth_client_secret.rotate", "applications.keys.create", "applications.keys.rotate", "installations.create", "invitations.create":
		return true
	default:
		return false
	}
}

func (a *API) listFactors(ctx context.Context, in *BearerInput) (*FactorsOutput, error) {
	claims, err := a.userClaims(ctx, in.Authorization)
	if err != nil {
		return nil, err
	}
	if a.Factors == nil {
		return nil, apierr.New("UNAVAILABLE", "factor service is unavailable")
	}
	items, err := a.Factors.List(ctx, claims.Subject)
	if err != nil {
		return nil, err
	}
	out := &FactorsOutput{}
	out.Body.Data = items
	return out, nil
}

func (a *API) createFactor(ctx context.Context, in *FactorsInput) (*FactorCreateOutput, error) {
	claims, err := a.userClaims(ctx, in.Authorization)
	if err != nil {
		return nil, err
	}
	if a.Factors == nil {
		return nil, apierr.New("UNAVAILABLE", "factor service is unavailable")
	}
	if in.Body.Kind != "backup_code" && in.Body.Kind != "totp" && in.Body.Kind != "passkey" {
		return nil, apierr.New("VALIDATION_FAILED", "factor kind is invalid")
	}
	if in.Body.Kind == "passkey" && in.Body.ChallengeID != "" {
		if in.Body.Name != "" || in.Body.Count != 0 || len(in.Body.Credential) == 0 {
			return nil, apierr.New("VALIDATION_FAILED", "passkey response is invalid")
		}
		factorID, err := a.Factors.FinishPasskeyEnrollment(ctx, claims.Subject, claims.SessionID, in.Body.ChallengeID, in.Body.Credential)
		if err != nil {
			return nil, err
		}
		out := &FactorCreateOutput{}
		out.Body.Data.FactorID = factorID
		return out, nil
	}
	if in.Body.ChallengeID != "" || len(in.Body.Credential) != 0 || (in.Body.Kind == "passkey" && in.Body.Count != 0) {
		return nil, apierr.New("VALIDATION_FAILED", "factor creation request is invalid")
	}
	request := map[string]any{"kind": in.Body.Kind}
	if in.Body.Name != "" {
		request["name"] = strings.TrimSpace(in.Body.Name)
	}
	if in.Body.Count != 0 {
		request["count"] = in.Body.Count
	}
	ctx, err = a.principalStepUpContext(ctx, in.Authorization, "me.factors.create", request)
	if err != nil {
		return nil, err
	}
	if in.Body.Kind == "passkey" {
		challenge, err := a.Factors.BeginPasskeyEnrollment(ctx, claims.Subject, claims.SessionID, in.Body.Name)
		if err != nil {
			return nil, err
		}
		out := &FactorCreateOutput{}
		out.Body.Data.Passkey = &challenge
		return out, nil
	}
	if in.Body.Kind == "totp" {
		name := strings.TrimSpace(in.Body.Name)
		if name == "" {
			return nil, apierr.New("VALIDATION_FAILED", "factor name is required for totp")
		}
		if a.Accounts == nil {
			return nil, apierr.New("UNAVAILABLE", "account service is unavailable")
		}
		user, err := a.Accounts.Me(ctx, claims)
		if err != nil {
			return nil, err
		}
		enrollment, err := a.Factors.EnrollTOTPForUser(ctx, claims.Subject, user.Email, name)
		if err != nil {
			return nil, err
		}
		out := &FactorCreateOutput{}
		out.Body.Data.FactorID = enrollment.FactorID
		out.Body.Data.Secret = enrollment.Secret.Value()
		out.Body.Data.URI = enrollment.URI
		return out, nil
	}
	count := in.Body.Count
	if count == 0 {
		count = 10
	}
	if count < 5 || count > 20 {
		return nil, apierr.New("VALIDATION_FAILED", "backup code count must be between 5 and 20")
	}
	codes, err := a.Factors.GenerateBackupCodesForUser(ctx, claims.Subject, count)
	if err != nil {
		return nil, err
	}
	out := &FactorCreateOutput{}
	out.Body.Data.Codes = codes
	return out, nil
}

func (a *API) deleteFactor(ctx context.Context, in *FactorPathInput) (*FactorDeleteOutput, error) {
	claims, err := a.userClaims(ctx, in.Authorization)
	if err != nil {
		return nil, err
	}
	if a.Factors == nil {
		return nil, apierr.New("UNAVAILABLE", "factor service is unavailable")
	}
	request := map[string]any{"factor_id": in.ID}
	ctx, err = a.principalStepUpContext(ctx, in.Authorization, "me.factors.delete", request)
	if err != nil {
		return nil, err
	}
	if err := a.Factors.DeleteForUser(ctx, claims.Subject, in.ID); err != nil {
		return nil, err
	}
	out := &FactorDeleteOutput{}
	out.Body.Data.Deleted = true
	return out, nil
}

func (a *API) principalStepUpContext(ctx context.Context, authorizationHeader, operation string, request any) (context.Context, error) {
	claims, err := a.authenticatePrincipal(ctx, authorizationHeader)
	if err != nil {
		return nil, err
	}
	if claims.Type == "agent" {
		return ctx, nil
	}
	if claims.Type != "user" || claims.SessionID == "" {
		return nil, apierr.New("USER_ACCOUNT_REQUIRED", "step-up requires a user account")
	}
	digest, err := stepup.DigestValue(request)
	if err != nil {
		return nil, err
	}
	return session.WithStepUpRequirement(ctx, session.StepUpRequirement{SessionID: claims.SessionID, Operation: operation, Digest: digest}), nil
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
	if _, _, _, err := a.authorizeCurrentMember(ctx, in.Authorization, "self:read"); err != nil {
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

func (a *API) updateMe(ctx context.Context, in *MePatchInput) (*MeOutput, error) {
	parts := strings.Fields(in.Authorization)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
		return nil, apierr.New("UNAUTHENTICATED", "A user access token is required.")
	}
	if a.Sessions == nil || a.Accounts == nil {
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
	user, err := a.Accounts.UpdateProfile(ctx, claims.Subject, account.ProfileUpdate{
		DisplayName: in.Body.Name, AvatarURL: in.Body.AvatarURL, PublicMetadata: in.Body.PublicMetadata,
	})
	if err != nil {
		return nil, err
	}
	out := &MeOutput{}
	out.Body.Data = user
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

func (a *API) removeCurrentMember(ctx context.Context, in *BearerInput) (*GenericOutput, error) {
	memberID, userID, ctx, err := a.currentMember(ctx, in.Authorization)
	if err != nil {
		return nil, err
	}
	if userID == "" {
		if a.Agents == nil {
			return nil, apierr.New("UNAVAILABLE", "agent service is unavailable")
		}
		if err := a.Agents.RemoveSelf(ctx, memberID, a.Authorization); err != nil {
			return nil, err
		}
	} else {
		if err := a.Authorization.RevokeOwnBinding(ctx, userID, memberID); err != nil {
			return nil, err
		}
	}
	out := &GenericOutput{}
	out.Body.Data.Accepted = true
	return out, nil
}

func (a *API) mePermissions(ctx context.Context, in *BearerInput) (*PermissionsOutput, error) {
	member, _, ctx, err := a.authorizeCurrentMember(ctx, in.Authorization, "self:read")
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
		if a.Signer == nil {
			return security.Claims{}, apierr.New("UNAVAILABLE", "authentication is unavailable")
		}
		claims, err := (&session.Service{Signer: a.Signer}).VerifyAccess(ctx, parts[1])
		if err != nil {
			return security.Claims{}, apierr.New("unauthorized", "access token is invalid")
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
