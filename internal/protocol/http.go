package protocol

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/plystra/auth/internal/account"
	"github.com/plystra/auth/internal/agent"
	"github.com/plystra/auth/internal/apierr"
	"github.com/plystra/auth/internal/application"
	"github.com/plystra/auth/internal/authorization"
	"github.com/plystra/auth/internal/authz/engine"
	"github.com/plystra/auth/internal/ids"
	"github.com/plystra/auth/internal/route"
	"github.com/plystra/auth/internal/security"
	"github.com/plystra/auth/internal/session"
)

type HTTP struct {
	Issuer        string
	Agents        *agent.Service
	Accounts      *account.Service
	Applications  *application.Service
	Sessions      *session.Service
	Authorization *authorization.Service
}

func (h HTTP) Register(mux route.HandlerMux) {
	route.RegisterNonJSON(mux, route.NewSpec("oauth.metadata", "GET", "/.well-known/oauth-authorization-server", route.Principal, "", []route.Subject{route.Public}, route.WithNonJSON()), http.HandlerFunc(h.metadata))
	route.RegisterNonJSON(mux, route.NewSpec("oidc.metadata", "GET", "/.well-known/openid-configuration", route.Principal, "", []route.Subject{route.Public}, route.WithNonJSON()), http.HandlerFunc(h.metadata))
	route.RegisterNonJSON(mux, route.NewSpec("oauth.authorize", "GET", "/oauth/authorize", route.Principal, "", []route.Subject{route.Public}, route.WithNonJSON()), http.HandlerFunc(h.authorize))
	route.RegisterNonJSON(mux, route.NewSpec("oauth.token", "POST", "/oauth/token", route.Principal, "", []route.Subject{route.Public}, route.WithNonJSON()), http.HandlerFunc(h.token))
	route.RegisterNonJSON(mux, route.NewSpec("oauth.revoke", "POST", "/oauth/revoke", route.Principal, "", []route.Subject{route.Public}, route.WithNonJSON()), http.HandlerFunc(h.revoke))
	route.RegisterNonJSON(mux, route.NewSpec("oauth.device_authorization", "POST", "/oauth/device_authorization", route.Principal, "", []route.Subject{route.Public}, route.WithNonJSON()), http.HandlerFunc(h.notImplemented))
	route.RegisterNonJSON(mux, route.NewSpec("oauth.register", "POST", "/oauth/register", route.Principal, "", []route.Subject{route.Public}, route.WithNonJSON()), http.HandlerFunc(h.notImplemented))
	route.RegisterNonJSON(mux, route.NewSpec("oauth.userinfo", "GET", "/oauth/userinfo", route.Principal, "", []route.Subject{route.HumanAgent}, route.WithNonJSON()), http.HandlerFunc(h.userinfo))
	route.RegisterNonJSON(mux, route.NewSpec("scim.users", "GET", "/scim/v2/{dir_id}/Users", route.Principal, "", []route.Subject{route.Public}, route.WithNonJSON()), http.HandlerFunc(h.scimUsers))
	route.RegisterNonJSON(mux, route.NewSpec("sso.start", "GET", "/v1/sso/{connection_id}/start", route.Principal, "", []route.Subject{route.Public}, route.WithNonJSON()), http.HandlerFunc(h.notImplemented))
	route.RegisterNonJSON(mux, route.NewSpec("sso.callback", "POST", "/v1/sso/{connection_id}/callback", route.Principal, "", []route.Subject{route.Public}, route.WithNonJSON()), http.HandlerFunc(h.notImplemented))
}
func (h HTTP) metadata(w http.ResponseWriter, r *http.Request) {
	base := strings.TrimRight(h.Issuer, "/")
	writeJSON(w, http.StatusOK, map[string]any{"issuer": h.Issuer, "authorization_endpoint": base + "/oauth/authorize", "token_endpoint": base + "/oauth/token", "revocation_endpoint": base + "/oauth/revoke", "jwks_uri": base + "/.well-known/jwks.json", "userinfo_endpoint": base + "/oauth/userinfo", "response_types_supported": []string{"code"}, "grant_types_supported": []string{"authorization_code", "refresh_token", "urn:ietf:params:oauth:grant-type:token-exchange"}, "code_challenge_methods_supported": []string{"S256"}})
}
func (h HTTP) authorize(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	if q.Get("response_type") != "code" || q.Get("client_id") == "" || q.Get("redirect_uri") == "" {
		writeErr(w, apierr.New("invalid_request", "response_type, client_id and redirect_uri are required"))
		return
	}
	if q.Get("code_challenge_method") != "S256" || q.Get("code_challenge") == "" {
		writeErr(w, apierr.New("invalid_request", "PKCE S256 is required"))
		return
	}
	if q.Get("state") == "" || q.Get("nonce") == "" {
		writeErr(w, apierr.New("invalid_request", "state and nonce are required"))
		return
	}
	if h.Applications == nil || h.Agents == nil || h.Authorization == nil {
		writeErr(w, apierr.New("temporarily_unavailable", "authorization is unavailable"))
		return
	}
	client, err := h.Applications.OAuthClient(r.Context(), q.Get("client_id"))
	if err != nil {
		writeProtocolErr(w, err)
		return
	}
	if !containsString(client.RedirectURIs, q.Get("redirect_uri")) {
		writeErr(w, apierr.New("invalid_request", "redirect_uri is not registered for this client"))
		return
	}
	claims, err := h.userClaims(r)
	if err != nil {
		writeProtocolErr(w, err)
		return
	}
	memberID := strings.TrimSpace(q.Get("member_id"))
	if memberID == "" {
		memberID = claims.MemberID
	}
	if memberID == "" {
		member, memberErr := h.Authorization.GetMemberForUser(r.Context(), claims.Subject, client.SpaceID)
		if memberErr != nil {
			writeErr(w, apierr.New("invalid_request", "member_id is required when the user has multiple members"))
			return
		}
		memberID = member.ID
	}
	bound, err := h.Authorization.UserBoundToMember(r.Context(), claims.Subject, memberID)
	if err != nil {
		writeProtocolErr(w, err)
		return
	}
	if !bound {
		writeErr(w, apierr.New("invalid_request", "member_id is not bound to the authenticated user"))
		return
	}
	member, err := h.Authorization.GetMemberAnySpace(r.Context(), memberID)
	if err != nil {
		writeProtocolErr(w, err)
		return
	}
	if member.Kind != "human" {
		writeErr(w, apierr.New("invalid_request", "member_id must identify a human member"))
		return
	}
	if member.SpaceID != client.SpaceID {
		writeErr(w, apierr.New("invalid_request", "member_id is not in the client's Space"))
		return
	}
	scopes := uniqueScopes(strings.Fields(q.Get("scope")))
	if len(scopes) == 0 {
		writeErr(w, apierr.New("invalid_scope", "at least one scope is required"))
		return
	}
	effective, err := h.Authorization.ListEffectivePermissions(r.Context(), memberID)
	if err != nil {
		writeErr(w, apierr.New("temporarily_unavailable", "authorization is unavailable"))
		return
	}
	effectivePermissions := make(map[string]struct{}, len(effective))
	for _, permission := range effective {
		effectivePermissions[permission.Permission] = struct{}{}
	}
	for _, scope := range scopes {
		if !containsString(client.AllowedScopes, scope) {
			writeErr(w, apierr.New("invalid_scope", "requested scope is not allowed for this client"))
			return
		}
		if _, ok := effectivePermissions[scope]; !ok {
			writeErr(w, apierr.New("invalid_scope", "the selected member does not hold the requested scope"))
			return
		}
	}
	resource := strings.TrimSpace(q.Get("resource"))
	if resource == "" {
		resource = client.ClientID
	}
	if resource != client.ClientID {
		writeErr(w, apierr.New("invalid_target", "resource is not registered for this client"))
		return
	}
	if err := h.Authorization.ValidateOAuthGrant(r.Context(), memberID, client.SpaceID, scopes); err != nil {
		writeProtocolErr(w, err)
		return
	}
	agentMember, err := h.authorizeOAuthAgent(r, claims, client, memberID, scopes)
	if err != nil {
		writeProtocolErr(w, err)
		return
	}
	code, codeHash, err := newAuthorizationCode()
	if err != nil {
		writeErr(w, apierr.New("temporarily_unavailable", "authorization is unavailable"))
		return
	}
	if err := h.Applications.CreateAuthorizationCode(r.Context(), application.CreateAuthorizationCodeInput{
		ID: string(ids.New[ids.ID]("cod")), ApplicationID: client.ID, UserID: claims.Subject, MemberID: agentMember.ID,
		RedirectURI: q.Get("redirect_uri"), CodeHash: codeHash, CodeChallenge: q.Get("code_challenge"),
		CodeChallengeMethod: "S256", Scope: strings.Join(scopes, " "), Nonce: q.Get("nonce"), Resource: resource,
		ExpiresAt: time.Now().UTC().Add(60 * time.Second),
	}); err != nil {
		writeErr(w, apierr.New("temporarily_unavailable", "authorization is unavailable"))
		return
	}
	redirect, err := url.Parse(q.Get("redirect_uri"))
	if err != nil {
		writeErr(w, apierr.New("invalid_request", "redirect_uri is invalid"))
		return
	}
	params := redirect.Query()
	params.Set("code", code)
	params.Set("state", q.Get("state"))
	redirect.RawQuery = params.Encode()
	http.Redirect(w, r, redirect.String(), http.StatusFound)
}
func (h HTTP) token(w http.ResponseWriter, r *http.Request) {
	if e := r.ParseForm(); e != nil {
		writeErr(w, apierr.New("invalid_request", "form body is invalid"))
		return
	}
	grantType := r.Form.Get("grant_type")
	if grantType == "urn:ietf:params:oauth:grant-type:token-exchange" && r.Form.Get("actor_token") != "" {
		h.tokenExchange(w, r)
		return
	}
	if grantType == "refresh_token" {
		if h.Agents == nil || h.Sessions == nil {
			writeErr(w, apierr.New("temporarily_unavailable", "agent refresh is unavailable"))
			return
		}
		credential, refresh, err := h.Agents.RotateOAuthRefresh(r.Context(), r.Form.Get("refresh_token"))
		if err != nil {
			writeErr(w, apierr.New("invalid_grant", "refresh token is invalid or expired"))
			return
		}
		tokens, err := h.Sessions.CreateAgentAccess(r.Context(), credential.MemberID, credential.SpaceID, r.Form.Get("resource"))
		if err != nil {
			writeErr(w, apierr.New("temporarily_unavailable", "agent refresh is unavailable"))
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"access_token": tokens.AccessToken, "token_type": tokens.TokenType, "expires_in": tokens.ExpiresIn, "refresh_token": refresh})
		return
	}
	if grantType == "authorization_code" {
		h.authorizationCodeToken(w, r)
		return
	}
	if grantType == "agent_key" || (grantType == "urn:ietf:params:oauth:grant-type:token-exchange" && r.Form.Get("agent_key") != "") {
		if h.Agents == nil || h.Sessions == nil {
			writeErr(w, apierr.New("temporarily_unavailable", "agent token exchange is unavailable"))
			return
		}
		credential := r.Form.Get("agent_key")
		if credential == "" {
			credential = r.Form.Get("subject_token")
		}
		c, err := h.Agents.AuthenticateKey(r.Context(), credential)
		if err != nil {
			writeErr(w, apierr.New("invalid_grant", "agent credential is invalid"))
			return
		}
		tokens, err := h.Sessions.CreateAgentAccess(r.Context(), c.MemberID, c.SpaceID, r.Form.Get("resource"))
		if err != nil {
			writeErr(w, apierr.New("temporarily_unavailable", "agent token exchange is unavailable"))
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"access_token": tokens.AccessToken, "token_type": tokens.TokenType, "expires_in": tokens.ExpiresIn})
		return
	}
	writeErr(w, apierr.New("invalid_grant", "authorization grant is invalid or expired"))
}

func (h HTTP) authorizationCodeToken(w http.ResponseWriter, r *http.Request) {
	if h.Applications == nil || h.Agents == nil || h.Sessions == nil {
		writeErr(w, apierr.New("temporarily_unavailable", "authorization code exchange is unavailable"))
		return
	}
	clientID := strings.TrimSpace(r.Form.Get("client_id"))
	redirectURI := strings.TrimSpace(r.Form.Get("redirect_uri"))
	verifier := r.Form.Get("code_verifier")
	code := r.Form.Get("code")
	if clientID == "" || redirectURI == "" || verifier == "" || code == "" {
		writeErr(w, apierr.New("invalid_request", "client_id, redirect_uri, code and code_verifier are required"))
		return
	}
	client, err := h.Applications.OAuthClient(r.Context(), clientID)
	if err != nil {
		writeErr(w, apierr.New("invalid_grant", "authorization code is invalid or expired"))
		return
	}
	if !containsString(client.RedirectURIs, redirectURI) {
		writeErr(w, apierr.New("invalid_grant", "authorization code is invalid or expired"))
		return
	}
	digest := sha256.Sum256([]byte(verifier))
	codeHash := sha256.Sum256([]byte(code))
	consumed, err := h.Applications.ConsumeAuthorizationCode(r.Context(), codeHash[:], client.ID, redirectURI)
	if err != nil {
		writeProtocolErr(w, err)
		return
	}
	if consumed.CodeChallengeMethod != "S256" || subtle.ConstantTimeCompare([]byte(consumed.CodeChallenge), []byte(base64.RawURLEncoding.EncodeToString(digest[:]))) != 1 {
		writeErr(w, apierr.New("invalid_grant", "authorization code is invalid or expired"))
		return
	}
	if consumed.MemberID == "" {
		writeErr(w, apierr.New("invalid_grant", "authorization code is invalid or expired"))
		return
	}
	resource := consumed.Resource
	if requested := strings.TrimSpace(r.Form.Get("resource")); requested != "" && requested != resource {
		writeErr(w, apierr.New("invalid_target", "resource does not match the authorization request"))
		return
	}
	tokens, err := h.Sessions.CreateAgentAccess(r.Context(), consumed.MemberID, client.SpaceID, resource)
	if err != nil {
		writeErr(w, apierr.New("temporarily_unavailable", "authorization code exchange is unavailable"))
		return
	}
	refresh, err := h.Agents.CreateOAuthRefreshCredential(r.Context(), consumed.MemberID, time.Time{})
	if err != nil {
		writeErr(w, apierr.New("temporarily_unavailable", "authorization code exchange is unavailable"))
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"access_token": tokens.AccessToken, "token_type": tokens.TokenType, "expires_in": tokens.ExpiresIn, "refresh_token": refresh, "scope": consumed.Scope})
}

func (h HTTP) userClaims(r *http.Request) (security.Claims, error) {
	parts := strings.Fields(r.Header.Get("Authorization"))
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") || h.Sessions == nil {
		return security.Claims{}, apierr.New("invalid_token", "an authenticated user session is required")
	}
	claims, active, err := h.Sessions.Introspect(r.Context(), parts[1], security.DefaultApplicationAudience)
	if err != nil {
		return security.Claims{}, apierr.New("temporarily_unavailable", "authorization is unavailable")
	}
	if !active || claims.Type != "user" {
		return security.Claims{}, apierr.New("invalid_token", "an authenticated user session is required")
	}
	return claims, nil
}

func (h HTTP) authorizeOAuthAgent(r *http.Request, claims security.Claims, client application.OAuthClient, ownerMemberID string, scopes []string) (agent.Agent, error) {
	agentMember, err := h.Agents.OAuthAgent(r.Context(), ownerMemberID, client.ClientID)
	if err == nil {
		if agentMember.Status != "active" {
			return agent.Agent{}, apierr.New("invalid_request", "the existing OAuth Agent is not active")
		}
		if _, err := h.Authorization.ReplaceOAuthInlineGrants(r.Context(), ownerMemberID, client.SpaceID, agentMember.ID, scopes, "space", client.SpaceID); err != nil {
			return agent.Agent{}, err
		}
		return agentMember, nil
	}
	var publicErr *apierr.Error
	if !errors.As(err, &publicErr) || publicErr.Code != "NOT_FOUND" {
		return agent.Agent{}, err
	}
	name := strings.TrimSpace(client.Name + " OAuth Agent")
	if len([]rune(name)) > 128 {
		name = string([]rune(name)[:128])
	}
	created, err := h.Agents.CreateOAuth(r.Context(), agent.CreateInput{
		OwnerMemberID: ownerMemberID, CreatedByUser: claims.Subject, Name: name,
		Source: "oauth", OAuthClientID: client.ClientID, ExpiresAt: time.Now().UTC().Add(30 * 24 * time.Hour),
	})
	if err != nil {
		return agent.Agent{}, err
	}
	if _, err := h.Authorization.CreateOAuthInlineGrant(r.Context(), ownerMemberID, client.SpaceID, created.ID, scopes, "space", client.SpaceID); err != nil {
		return agent.Agent{}, err
	}
	return created, nil
}

func newAuthorizationCode() (string, []byte, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", nil, err
	}
	code := "ply_ac_" + base64.RawURLEncoding.EncodeToString(raw)
	hash := sha256.Sum256([]byte(code))
	return code, hash[:], nil
}

func containsString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func (h HTTP) revoke(w http.ResponseWriter, r *http.Request) {
	if e := r.ParseForm(); e != nil {
		writeErr(w, apierr.New("invalid_request", "form body is invalid"))
		return
	}
	raw := strings.TrimSpace(r.Form.Get("token"))
	if raw == "" {
		writeErr(w, apierr.New("invalid_request", "token is required"))
		return
	}
	if h.Agents == nil || h.Sessions == nil {
		writeErr(w, apierr.New("temporarily_unavailable", "token revocation is unavailable"))
		return
	}
	if strings.HasPrefix(raw, "ply_rt_") {
		_, err := h.Agents.RevokeOAuthRefreshToken(r.Context(), raw)
		if err != nil {
			writeErr(w, apierr.New("temporarily_unavailable", "token revocation is unavailable"))
			return
		}
		w.WriteHeader(http.StatusOK)
		return
	}
	claims, err := h.Sessions.VerifyAccess(raw)
	if err == nil && claims.Type == "agent" && claims.Subject != "" {
		if err := h.Agents.RevokeOAuth(r.Context(), claims.Subject); err != nil {
			writeErr(w, apierr.New("temporarily_unavailable", "token revocation is unavailable"))
			return
		}
	}
	// RFC 7009 intentionally hides whether an opaque or JWT token was known.
	w.WriteHeader(http.StatusOK)
}

func (h HTTP) userinfo(w http.ResponseWriter, r *http.Request) {
	if h.Sessions == nil {
		writeErr(w, apierr.New("temporarily_unavailable", "userinfo is unavailable"))
		return
	}
	parts := strings.Fields(r.Header.Get("Authorization"))
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
		writeErr(w, apierr.New("invalid_token", "a bearer access token is required"))
		return
	}
	claims, active, err := h.Sessions.Introspect(r.Context(), parts[1], security.DefaultApplicationAudience)
	if err != nil {
		writeErr(w, apierr.New("temporarily_unavailable", "userinfo is unavailable"))
		return
	}
	if !active {
		writeErr(w, apierr.New("invalid_token", "the access token is invalid"))
		return
	}
	if claims.Type == "user" {
		if h.Accounts == nil {
			writeErr(w, apierr.New("temporarily_unavailable", "userinfo is unavailable"))
			return
		}
		user, err := h.Accounts.Me(r.Context(), claims)
		if err != nil {
			writeErr(w, apierr.New("invalid_token", "the access token is invalid"))
			return
		}
		body := map[string]any{"sub": user.ID, "email": user.Email, "email_verified": user.EmailVerified}
		if user.DisplayName != "" {
			body["name"] = user.DisplayName
		}
		if user.AvatarURL != "" {
			body["picture"] = user.AvatarURL
		}
		writeJSON(w, http.StatusOK, body)
		return
	}
	if claims.Type == "agent" {
		writeJSON(w, http.StatusOK, map[string]any{"sub": claims.Subject, "member_id": claims.MemberID, "space_id": claims.SpaceID, "principal_type": "agent"})
		return
	}
	writeErr(w, apierr.New("invalid_token", "the access token is invalid"))
}

func (h HTTP) tokenExchange(w http.ResponseWriter, r *http.Request) {
	if h.Agents == nil || h.Sessions == nil {
		writeErr(w, apierr.New("temporarily_unavailable", "token exchange is unavailable"))
		return
	}
	actor, err := h.Agents.AuthenticateKey(r.Context(), r.Form.Get("actor_token"))
	if err != nil {
		writeErr(w, apierr.New("invalid_grant", "actor token is invalid"))
		return
	}
	if err := h.Agents.ValidateActive(r.Context(), actor.MemberID); err != nil {
		writeErr(w, apierr.New("invalid_grant", "actor token is invalid"))
		return
	}
	parentClaims, active, err := h.Sessions.Introspect(r.Context(), r.Form.Get("subject_token"), security.DefaultApplicationAudience)
	if err != nil || !active || parentClaims.Type != "agent" {
		writeErr(w, apierr.New("invalid_grant", "subject token is invalid"))
		return
	}
	owner, err := h.Agents.Owner(r.Context(), actor.MemberID)
	if err != nil || owner != parentClaims.Subject {
		writeErr(w, apierr.New("invalid_grant", "actor token is not delegated by the subject"))
		return
	}
	if h.Authorization == nil {
		writeErr(w, apierr.New("temporarily_unavailable", "authorization is unavailable"))
		return
	}
	requested := uniqueScopes(strings.Fields(r.Form.Get("scope")))
	parentScopes := uniqueScopes(parentClaims.Scopes)
	if len(requested) == 0 && len(parentScopes) > 0 {
		// An omitted scope inherits the parent token's restriction. It must
		// never turn a previously narrowed delegation back into an unscoped
		// token.
		requested = parentScopes
	}
	if len(parentScopes) > 0 {
		for _, permission := range requested {
			if !scopeContains(parentScopes, permission) {
				writeErr(w, apierr.New("invalid_scope", "requested scope exceeds the subject token scope"))
				return
			}
		}
	}
	for _, permission := range requested {
		decision, _, checkErr := h.Authorization.Check(r.Context(), authorization.CheckRequest{MemberID: actor.MemberID, Permission: permission, ResourceSpace: actor.SpaceID})
		if checkErr != nil {
			writeErr(w, apierr.New("temporarily_unavailable", "authorization is unavailable"))
			return
		}
		if decision.Effect != engine.Allow {
			writeErr(w, apierr.New("invalid_scope", "requested scope is not held by the delegated Agent"))
			return
		}
	}
	tokens, err := h.Sessions.CreateAgentDelegatedAccess(r.Context(), actor.MemberID, actor.SpaceID, r.Form.Get("resource"), parentClaims.Subject, requested, parentClaims.ExpiresAt)
	if err != nil {
		writeErr(w, apierr.New("temporarily_unavailable", "token exchange is unavailable"))
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"access_token": tokens.AccessToken, "token_type": tokens.TokenType, "expires_in": tokens.ExpiresIn, "issued_token_type": "urn:ietf:params:oauth:token-type:access_token"})
}
func (h HTTP) notImplemented(w http.ResponseWriter, r *http.Request) {
	writeErr(w, apierr.New("not_implemented", "protocol operation is not enabled for this deployment"))
}
func (h HTTP) scimUsers(w http.ResponseWriter, r *http.Request) {
	if !strings.HasPrefix(r.Header.Get("Authorization"), "Bearer ") {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"schemas": []string{"urn:ietf:params:scim:api:messages:2.0:Error"}, "detail": "SCIM bearer token required", "status": "401"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"schemas": []string{"urn:ietf:params:scim:api:messages:2.0:ListResponse"}, "totalResults": 0, "Resources": []any{}})
}
func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
func writeErr(w http.ResponseWriter, e *apierr.Error) {
	writeJSON(w, apierr.Status(e.Code), map[string]any{"error": map[string]any{"code": e.Code, "message": e.Message}})
}

func writeProtocolErr(w http.ResponseWriter, err error) {
	var publicErr *apierr.Error
	if errors.As(err, &publicErr) {
		writeErr(w, publicErr)
		return
	}
	writeErr(w, apierr.New("temporarily_unavailable", "protocol operation is unavailable"))
}

func uniqueScopes(scopes []string) []string {
	seen := make(map[string]struct{}, len(scopes))
	out := make([]string, 0, len(scopes))
	for _, scope := range scopes {
		scope = strings.TrimSpace(scope)
		if scope == "" {
			continue
		}
		if _, ok := seen[scope]; ok {
			continue
		}
		seen[scope] = struct{}{}
		out = append(out, scope)
	}
	return out
}

func scopeContains(scopes []string, want string) bool {
	for _, scope := range scopes {
		if scope == want {
			return true
		}
	}
	return false
}
