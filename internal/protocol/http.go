package protocol

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/plystra/auth/internal/account"
	"github.com/plystra/auth/internal/agent"
	"github.com/plystra/auth/internal/apierr"
	"github.com/plystra/auth/internal/application"
	"github.com/plystra/auth/internal/authorization"
	"github.com/plystra/auth/internal/enterprise"
	"github.com/plystra/auth/internal/route"
	"github.com/plystra/auth/internal/secret"
	"github.com/plystra/auth/internal/security"
	"github.com/plystra/auth/internal/session"
)

type HTTP struct {
	Issuer        string
	HostedOrigin  string
	Agents        *agent.Service
	Accounts      *account.Service
	Applications  *application.Service
	Sessions      *session.Service
	Authorization *authorization.Service
	Enterprise    *enterprise.Service
}

func (h HTTP) Register(mux route.HandlerMux) {
	route.RegisterNonJSON(mux, route.NewSpec("oauth.metadata", "GET", "/.well-known/oauth-authorization-server", route.Principal, "", []route.Subject{route.Public}, route.WithNonJSON()), http.HandlerFunc(h.metadata))
	route.RegisterNonJSON(mux, route.NewSpec("oidc.metadata", "GET", "/.well-known/openid-configuration", route.Principal, "", []route.Subject{route.Public}, route.WithNonJSON()), http.HandlerFunc(h.metadata))
	route.RegisterNonJSON(mux, route.NewSpec("oauth.authorize", "GET", "/oauth/authorize", route.Principal, "", []route.Subject{route.Public}, route.WithNonJSON()), http.HandlerFunc(h.authorize))
	route.RegisterNonJSON(mux, route.NewSpec("oauth.consent", "POST", "/oauth/authorize", route.Principal, "", []route.Subject{route.User}, route.WithNonJSON(), route.WithMaxBodyBytes(64<<10)), http.HandlerFunc(h.consent))
	route.RegisterNonJSON(mux, route.NewSpec("oauth.token", "POST", "/oauth/token", route.Principal, "", []route.Subject{route.Public}, route.WithNonJSON()), http.HandlerFunc(h.token))
	route.RegisterNonJSON(mux, route.NewSpec("oauth.revoke", "POST", "/oauth/revoke", route.Principal, "", []route.Subject{route.Public}, route.WithNonJSON()), http.HandlerFunc(h.revoke))
	route.RegisterNonJSON(mux, route.NewSpec("oauth.device_authorization", "POST", "/oauth/device_authorization", route.Principal, "", []route.Subject{route.Public}, route.WithNonJSON()), http.HandlerFunc(h.notImplemented))
	route.RegisterNonJSON(mux, route.NewSpec("oauth.register", "POST", "/oauth/register", route.Principal, "", []route.Subject{route.Public}, route.WithNonJSON()), http.HandlerFunc(h.notImplemented))
	route.RegisterNonJSON(mux, route.NewSpec("oauth.userinfo", "GET", "/oauth/userinfo", route.Principal, "", []route.Subject{route.HumanAgent}, route.WithNonJSON()), http.HandlerFunc(h.userinfo))
	h.registerSCIMDiscovery(mux)
	route.RegisterNonJSON(mux, route.NewSpec("scim.users.create", "POST", "/scim/v2/{dir_id}/Users", route.Principal, "", []route.Subject{route.Public}, route.WithNonJSON(), route.WithMaxBodyBytes(256<<10)), http.HandlerFunc(h.scimUsers))
	route.RegisterNonJSON(mux, route.NewSpec("scim.users", "GET", "/scim/v2/{dir_id}/Users", route.Principal, "", []route.Subject{route.Public}, route.WithNonJSON()), http.HandlerFunc(h.scimUsers))
	route.RegisterNonJSON(mux, route.NewSpec("scim.users.search", "POST", "/scim/v2/{dir_id}/Users/.search", route.Principal, "", []route.Subject{route.Public}, route.WithNonJSON(), route.WithMaxBodyBytes(scimSearchLimit)), h.scimSearch("userName", scimUser))
	route.RegisterNonJSON(mux, route.NewSpec("scim.user.get", "GET", "/scim/v2/{dir_id}/Users/{id}", route.Principal, "", []route.Subject{route.Public}, route.WithNonJSON()), http.HandlerFunc(h.scimUsers))
	route.RegisterNonJSON(mux, route.NewSpec("scim.user.replace", "PUT", "/scim/v2/{dir_id}/Users/{id}", route.Principal, "", []route.Subject{route.Public}, route.WithNonJSON(), route.WithMaxBodyBytes(256<<10)), http.HandlerFunc(h.scimUsers))
	route.RegisterNonJSON(mux, route.NewSpec("scim.user.patch", "PATCH", "/scim/v2/{dir_id}/Users/{id}", route.Principal, "", []route.Subject{route.Public}, route.WithNonJSON(), route.WithMaxBodyBytes(256<<10)), http.HandlerFunc(h.scimUsers))
	route.RegisterNonJSON(mux, route.NewSpec("scim.user.delete", "DELETE", "/scim/v2/{dir_id}/Users/{id}", route.Principal, "", []route.Subject{route.Public}, route.WithNonJSON()), http.HandlerFunc(h.scimUsers))
	route.RegisterNonJSON(mux, route.NewSpec("scim.groups.create", "POST", "/scim/v2/{dir_id}/Groups", route.Principal, "", []route.Subject{route.Public}, route.WithNonJSON(), route.WithMaxBodyBytes(256<<10)), http.HandlerFunc(h.scimGroups))
	route.RegisterNonJSON(mux, route.NewSpec("scim.groups", "GET", "/scim/v2/{dir_id}/Groups", route.Principal, "", []route.Subject{route.Public}, route.WithNonJSON()), http.HandlerFunc(h.scimGroups))
	route.RegisterNonJSON(mux, route.NewSpec("scim.groups.search", "POST", "/scim/v2/{dir_id}/Groups/.search", route.Principal, "", []route.Subject{route.Public}, route.WithNonJSON(), route.WithMaxBodyBytes(scimSearchLimit)), h.scimSearch("displayName", scimGroup))
	route.RegisterNonJSON(mux, route.NewSpec("scim.group.get", "GET", "/scim/v2/{dir_id}/Groups/{id}", route.Principal, "", []route.Subject{route.Public}, route.WithNonJSON()), http.HandlerFunc(h.scimGroups))
	route.RegisterNonJSON(mux, route.NewSpec("scim.group.replace", "PUT", "/scim/v2/{dir_id}/Groups/{id}", route.Principal, "", []route.Subject{route.Public}, route.WithNonJSON(), route.WithMaxBodyBytes(256<<10)), http.HandlerFunc(h.scimGroups))
	route.RegisterNonJSON(mux, route.NewSpec("scim.group.patch", "PATCH", "/scim/v2/{dir_id}/Groups/{id}", route.Principal, "", []route.Subject{route.Public}, route.WithNonJSON(), route.WithMaxBodyBytes(256<<10)), http.HandlerFunc(h.scimGroups))
	route.RegisterNonJSON(mux, route.NewSpec("scim.group.delete", "DELETE", "/scim/v2/{dir_id}/Groups/{id}", route.Principal, "", []route.Subject{route.Public}, route.WithNonJSON()), http.HandlerFunc(h.scimGroups))
	route.RegisterNonJSON(mux, route.NewSpec("sso.start", "GET", "/v1/sso/{connection_id}/start", route.Principal, "", []route.Subject{route.Public}, route.WithNonJSON()), http.HandlerFunc(h.ssoStart))
	route.RegisterNonJSON(mux, route.NewSpec("sso.callback", "POST", "/v1/sso/{connection_id}/callback", route.Principal, "", []route.Subject{route.Public}, route.WithNonJSON(), route.WithMaxBodyBytes(64<<10)), http.HandlerFunc(h.ssoCallback))
	route.RegisterNonJSON(mux, route.NewSpec("oidc.interactions.saml.receive", "POST", route.SAMLBrowserCallbackPrefix+"{connection_id}", route.Principal, "", []route.Subject{route.Public}, route.WithNonJSON(), route.WithMaxBodyBytes(samlBrowserFormLimit)), http.HandlerFunc(h.samlBrowserCallback))
}
func (h HTTP) metadata(w http.ResponseWriter, r *http.Request) {
	base := strings.TrimRight(h.Issuer, "/")
	document := map[string]any{
		"issuer": h.Issuer, "authorization_endpoint": base + "/oauth/authorize", "token_endpoint": base + "/oauth/token",
		"revocation_endpoint": base + "/oauth/revoke", "jwks_uri": base + "/.well-known/jwks.json", "userinfo_endpoint": base + "/oauth/userinfo",
		"response_types_supported": []string{"code"}, "grant_types_supported": []string{"authorization_code", "refresh_token", "urn:ietf:params:oauth:grant-type:token-exchange"},
		"code_challenge_methods_supported":           []string{"S256"},
		"token_endpoint_auth_methods_supported":      []string{"client_secret_basic", "client_secret_post", "none"},
		"revocation_endpoint_auth_methods_supported": []string{"client_secret_basic", "client_secret_post", "none"},
	}
	if r.URL.Path == "/.well-known/openid-configuration" {
		document["subject_types_supported"] = []string{"public"}
		document["id_token_signing_alg_values_supported"] = []string{"ES256"}
		document["scopes_supported"] = []string{"openid", "email", "profile"}
		document["claims_supported"] = []string{"iss", "sub", "aud", "exp", "iat", "nonce", "auth_time", "email", "email_verified", "name", "picture"}
	}
	writeJSON(w, http.StatusOK, document)
}
func (h HTTP) authorize(w http.ResponseWriter, r *http.Request) {
	q, queryErr := url.ParseQuery(r.URL.RawQuery)
	if queryErr != nil {
		writeErr(w, apierr.New("invalid_request", "authorization query is invalid"))
		return
	}
	for _, values := range q {
		if len(values) != 1 {
			writeErr(w, apierr.New("invalid_request", "authorization parameters must appear once"))
			return
		}
	}
	if q.Get("response_type") != "code" || q.Get("client_id") == "" || q.Get("redirect_uri") == "" {
		writeErr(w, apierr.New("invalid_request", "response_type, client_id and redirect_uri are required"))
		return
	}
	challenge := q.Get("code_challenge")
	decodedChallenge, challengeErr := base64.RawURLEncoding.DecodeString(challenge)
	if q.Get("code_challenge_method") != "S256" || challengeErr != nil || len(decodedChallenge) != sha256.Size || base64.RawURLEncoding.EncodeToString(decodedChallenge) != challenge {
		writeErr(w, apierr.New("invalid_request", "PKCE S256 is required"))
		return
	}
	if q.Get("state") == "" || q.Get("nonce") == "" {
		writeErr(w, apierr.New("invalid_request", "state and nonce are required"))
		return
	}
	if h.Applications == nil {
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
	scopes := parseAuthorizationScopes(q.Get("scope"))
	if len(scopes) == 0 {
		writeErr(w, apierr.New("invalid_scope", "scope must contain OAuth scope tokens separated by a single space"))
		return
	}
	if containsString(scopes, "openid") {
		if q.Get("resource") != "" {
			writeErr(w, apierr.New("invalid_target", "user sign-in does not accept a business resource"))
			return
		}
		request, err := h.Applications.StartOIDCLogin(r.Context(), application.OIDCLoginRequestInput{
			ApplicationID: client.ID, ClientID: client.ClientID, RedirectURI: q.Get("redirect_uri"), Scope: scopes,
			State: q.Get("state"), Nonce: q.Get("nonce"), CodeChallenge: challenge,
		})
		if err != nil {
			writeProtocolErr(w, err)
			return
		}
		writeJSON(w, http.StatusOK, request)
		return
	}
	if len(scopes) > 100 {
		writeErr(w, apierr.New("invalid_scope", "at most 100 scopes can be requested"))
		return
	}
	for _, scope := range scopes {
		if !containsString(client.AllowedScopes, scope) {
			writeErr(w, apierr.New("invalid_scope", "requested scope is not allowed for this client"))
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
	handle, expiresAt, err := h.Applications.CreateOAuthAuthorizationRequest(r.Context(), application.OAuthAuthorizationRequestInput{
		ApplicationID: client.ID, RedirectURI: q.Get("redirect_uri"), CodeChallenge: challenge,
		Scopes: scopes, State: q.Get("state"), Nonce: q.Get("nonce"), Resource: resource,
	})
	if err != nil {
		writeProtocolErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"request_id": handle.Value(), "expires_at": expiresAt, "client_id": client.ClientID,
		"client_name": client.Name, "permissions": scopes, "redirect_uri": q.Get("redirect_uri"),
	})
}

func (h HTTP) consent(w http.ResponseWriter, r *http.Request) {
	claims, err := h.userClaims(r)
	if err != nil {
		writeProtocolErr(w, err)
		return
	}
	mediaType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" {
		writeErr(w, apierr.New("invalid_request", "JSON request body is required"))
		return
	}
	var body struct {
		RequestID   string   `json:"request_id"`
		Decision    string   `json:"decision"`
		MemberID    *string  `json:"member_id"`
		Permissions []string `json:"permissions"`
	}
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&body); err != nil {
		writeErr(w, apierr.New("invalid_request", "authorization decision body is invalid"))
		return
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		writeErr(w, apierr.New("invalid_request", "authorization decision body is invalid"))
		return
	}
	bearer := secret.New(strings.Fields(r.Header.Get("Authorization"))[1])
	var redirectTo string
	if strings.HasPrefix(body.RequestID, application.OIDCLoginRequestPrefix) {
		if body.MemberID != nil || body.Permissions != nil {
			writeErr(w, apierr.New("invalid_request", "user sign-in does not select a member or business permissions"))
			return
		}
		redirectTo, err = h.Applications.DecideOIDCLogin(r.Context(), h.Sessions, secret.New(body.RequestID), bearer, body.Decision)
	} else {
		var memberID string
		if body.MemberID != nil {
			memberID = *body.MemberID
		}
		redirectTo, err = (application.OAuthConsent{Applications: h.Applications, Agents: h.Agents, Authorization: h.Authorization, Sessions: h.Sessions}).Decide(r.Context(), application.OAuthConsentInput{
			RequestID: secret.New(body.RequestID), AccessToken: bearer, UserID: claims.Subject, Decision: body.Decision,
			MemberID: memberID, Permissions: body.Permissions,
		})
	}
	if err != nil {
		writeProtocolErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"redirect_to": redirectTo})
}
func (h HTTP) token(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	if err := parseOAuthForm(r); err != nil {
		writeStandardOAuthError(w, err)
		return
	}
	grantType := r.PostForm.Get("grant_type")
	if (len(r.Header.Values("Authorization")) > 0 || r.PostForm.Has("client_secret")) && grantType != "authorization_code" && grantType != "refresh_token" {
		writeOAuthErr(w, apierr.New("invalid_client", "client authentication is not used with this grant"))
		return
	}
	if grantType == "urn:ietf:params:oauth:grant-type:token-exchange" && r.Form.Get("actor_token") != "" {
		h.tokenExchange(w, r)
		return
	}
	if grantType == "refresh_token" {
		if h.Agents == nil || h.Sessions == nil || h.Applications == nil {
			writeErr(w, apierr.New("temporarily_unavailable", "agent refresh is unavailable"))
			return
		}
		client, err := oauthClientCredentials(r, true)
		if err != nil {
			writeOAuthErr(w, err)
			return
		}
		tokens, scope, err := (tokenService{applications: h.Applications, agents: h.Agents, sessions: h.Sessions, authorization: h.Authorization}).refresh(
			r.Context(), client, secret.New(r.Form.Get("refresh_token")), r.Form.Get("resource"), r.Form.Get("scope"))
		if err != nil {
			writeOAuthErr(w, err)
			return
		}
		body := map[string]any{"access_token": tokens.AccessToken, "token_type": tokens.TokenType, "expires_in": tokens.ExpiresIn, "refresh_token": tokens.RefreshToken}
		if scope != "" {
			body["scope"] = scope
		}
		writeJSON(w, http.StatusOK, body)
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
		tokens, err := (tokenService{agents: h.Agents, sessions: h.Sessions}).agentKey(r.Context(), secret.New(credential), r.Form.Get("resource"))
		if err != nil {
			writeOAuthErr(w, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"access_token": tokens.AccessToken, "token_type": tokens.TokenType, "expires_in": tokens.ExpiresIn})
		return
	}
	writeErr(w, apierr.New("invalid_grant", "authorization grant is invalid or expired"))
}

func (h HTTP) authorizationCodeToken(w http.ResponseWriter, r *http.Request) {
	if strings.HasPrefix(r.Form.Get("code"), "olc_") {
		h.exchangeHumanLogin(w, r)
		return
	}
	if h.Applications == nil || h.Agents == nil || h.Sessions == nil {
		writeErr(w, apierr.New("temporarily_unavailable", "authorization code exchange is unavailable"))
		return
	}
	client, err := oauthClientCredentials(r, true)
	if err != nil {
		writeOAuthErr(w, err)
		return
	}
	redirectURI := strings.TrimSpace(r.Form.Get("redirect_uri"))
	verifier := r.Form.Get("code_verifier")
	code := r.Form.Get("code")
	if redirectURI == "" || verifier == "" || code == "" {
		writeErr(w, apierr.New("invalid_request", "client_id, redirect_uri, code and code_verifier are required"))
		return
	}
	tokens, scope, err := (tokenService{applications: h.Applications, agents: h.Agents, sessions: h.Sessions}).authorizationCode(r.Context(), codeExchangeInput{
		client: client, redirectURI: redirectURI, code: secret.New(code), verifier: secret.New(verifier),
		resource: strings.TrimSpace(r.Form.Get("resource")),
	})
	if err != nil {
		writeOAuthErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"access_token": tokens.AccessToken, "token_type": tokens.TokenType, "expires_in": tokens.ExpiresIn, "refresh_token": tokens.RefreshToken, "scope": scope})
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

func containsString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func (h HTTP) userinfo(w http.ResponseWriter, r *http.Request) {
	if h.Sessions == nil {
		writeErr(w, apierr.New("temporarily_unavailable", "userinfo is unavailable"))
		return
	}
	authorization := r.Header.Get("Authorization")
	unauthorized := func(message string) {
		w.Header().Set("WWW-Authenticate", route.BearerChallenge(authorization))
		writeErr(w, apierr.New("invalid_token", message))
	}
	parts := strings.Fields(authorization)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
		unauthorized("a bearer access token is required")
		return
	}
	if strings.HasPrefix(parts[1], userInfoPrefix) {
		h.humanUserInfo(w, r, parts[1])
		return
	}
	claims, active, err := h.Sessions.Introspect(r.Context(), parts[1], security.DefaultApplicationAudience)
	if err != nil {
		writeErr(w, apierr.New("temporarily_unavailable", "userinfo is unavailable"))
		return
	}
	if !active {
		unauthorized("the access token is invalid")
		return
	}
	if claims.Type == "user" {
		if h.Accounts == nil {
			writeErr(w, apierr.New("temporarily_unavailable", "userinfo is unavailable"))
			return
		}
		user, err := h.Accounts.Me(r.Context(), claims)
		if err != nil {
			var public *apierr.Error
			if errors.As(err, &public) && public.GetStatus() == http.StatusUnauthorized {
				unauthorized("the access token is invalid")
			} else {
				writeErr(w, apierr.New("temporarily_unavailable", "userinfo is unavailable"))
			}
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
	unauthorized("the access token is invalid")
}

func (h HTTP) tokenExchange(w http.ResponseWriter, r *http.Request) {
	if h.Agents == nil || h.Sessions == nil || h.Authorization == nil {
		writeErr(w, apierr.New("temporarily_unavailable", "token exchange is unavailable"))
		return
	}
	tokens, scope, err := (tokenService{applications: h.Applications, agents: h.Agents, sessions: h.Sessions, authorization: h.Authorization}).delegated(
		r.Context(), secret.New(r.Form.Get("subject_token")), secret.New(r.Form.Get("actor_token")), strings.Fields(r.Form.Get("scope")), r.Form.Get("resource"))
	if err != nil {
		writeOAuthErr(w, err)
		return
	}
	response := map[string]any{"access_token": tokens.AccessToken, "token_type": tokens.TokenType, "expires_in": tokens.ExpiresIn, "issued_token_type": "urn:ietf:params:oauth:token-type:access_token"}
	if scope != "" {
		response["scope"] = scope
	}
	writeJSON(w, http.StatusOK, response)
}
func (h HTTP) notImplemented(w http.ResponseWriter, r *http.Request) {
	writeErr(w, apierr.New("not_implemented", "protocol operation is not enabled for this deployment"))
}

func (h HTTP) ssoStart(w http.ResponseWriter, r *http.Request) {
	if h.Enterprise == nil {
		writeErr(w, apierr.New("temporarily_unavailable", "enterprise SSO is unavailable"))
		return
	}
	result, err := h.Enterprise.Start(r.Context(), r.PathValue("connection_id"), r.URL.Query().Get("redirect_uri"))
	if err != nil {
		writeProtocolErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"data": result})
}

func (h HTTP) ssoCallback(w http.ResponseWriter, r *http.Request) {
	if h.Enterprise == nil {
		writeErr(w, apierr.New("temporarily_unavailable", "enterprise SSO is unavailable"))
		return
	}
	mediaType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err == nil && (mediaType == "application/x-www-form-urlencoded" || mediaType == "multipart/form-data") {
		w.Header().Set("Referrer-Policy", "no-referrer")
		if r.URL.RawQuery != "" || r.URL.ForceQuery {
			writeErr(w, apierr.New("invalid_request", "the SAML callback URL cannot contain a query"))
			return
		}
		var formErr error
		if mediaType == "multipart/form-data" {
			formErr = r.ParseMultipartForm(samlBrowserFormLimit)
		} else {
			formErr = r.ParseForm()
		}
		if formErr != nil {
			writeErr(w, apierr.New("invalid_request", "SAML callback body is invalid"))
			return
		}
		payload, relay := r.PostForm["SAMLResponse"], r.PostForm["RelayState"]
		if len(payload) != 1 || payload[0] == "" || len(relay) > 1 {
			writeErr(w, apierr.New("invalid_request", "one SAMLResponse and at most one RelayState are required"))
			return
		}
		result, err := h.Enterprise.Callback(r.Context(), enterprise.CallbackInput{
			ConnectionID: r.PathValue("connection_id"), State: r.PostForm.Get("RelayState"), SAMLResponse: payload[0],
		})
		if err != nil {
			writeProtocolErr(w, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"data": result})
		return
	}
	if err != nil || mediaType != "application/json" {
		writeErr(w, apierr.New("invalid_request", "JSON or SAML form body is required"))
		return
	}
	var body struct {
		State       string `json:"state"`
		Code        string `json:"code"`
		RedirectURI string `json:"redirect_uri"`
	}
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&body); err != nil {
		writeErr(w, apierr.New("invalid_request", "SSO callback body is invalid"))
		return
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		writeErr(w, apierr.New("invalid_request", "SSO callback body is invalid"))
		return
	}
	result, err := h.Enterprise.Callback(r.Context(), enterprise.CallbackInput{
		ConnectionID: r.PathValue("connection_id"), State: body.State, Code: body.Code, RedirectURI: body.RedirectURI,
	})
	if err != nil {
		writeProtocolErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"data": result})
}
func (h HTTP) scimUsers(w http.ResponseWriter, r *http.Request) {
	if h.Enterprise == nil {
		route.WriteSCIMError(w, apierr.New("temporarily_unavailable", "SCIM is unavailable"))
		return
	}
	token, err := scimBearerToken(r)
	if err != nil {
		route.WriteSCIMError(w, err)
		return
	}
	directoryID := r.PathValue("dir_id")
	resourceID := r.PathValue("id")
	query, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil {
		route.WriteSCIMError(w, apierr.New("invalid_request", "SCIM query is invalid"))
		return
	}
	projection, err := parseSCIMProjection(query, scimUser)
	if err != nil {
		route.WriteSCIMError(w, err)
		return
	}
	switch r.Method {
	case http.MethodPost:
		if resourceID != "" {
			route.WriteSCIMError(w, apierr.New("invalid_request", "a collection URL is required"))
			return
		}
		var body scimUserBody
		if err := decodeSCIMJSON(w, r, &body); err != nil {
			route.WriteSCIMError(w, err)
			return
		}
		created, err := h.Enterprise.CreateSCIMUser(r.Context(), directoryID, token, body.input(true))
		if err != nil {
			route.WriteSCIMError(w, err)
			return
		}
		projection.write(w, http.StatusCreated, created, directoryID)
	case http.MethodGet:
		if resourceID != "" {
			user, err := h.Enterprise.GetSCIMUser(r.Context(), directoryID, token, resourceID)
			if err != nil {
				route.WriteSCIMError(w, err)
				return
			}
			projection.write(w, http.StatusOK, user, directoryID)
			return
		}
		start, count, err := scimPagination(r)
		if err != nil {
			route.WriteSCIMError(w, err)
			return
		}
		filter, err := parseSCIMCollectionFilter(query.Get("filter"), "userName")
		if err != nil {
			route.WriteSCIMError(w, err)
			return
		}
		h.listSCIMUsers(w, r, token, scimListQuery{filter, projection, start, count})
	case http.MethodPut, http.MethodPatch:
		if resourceID == "" {
			route.WriteSCIMError(w, apierr.New("invalid_request", "a resource URL is required"))
			return
		}
		version, err := parseSCIMIfMatch(r.Header.Get("If-Match"))
		if err != nil {
			route.WriteSCIMError(w, err)
			return
		}
		var body scimUserBody
		if err := decodeSCIMJSON(w, r, &body); err != nil {
			route.WriteSCIMError(w, err)
			return
		}
		var updated enterprise.SCIMUser
		if r.Method == http.MethodPatch {
			input, inputErr := body.patchInput()
			if inputErr != nil {
				route.WriteSCIMError(w, inputErr)
				return
			}
			updated, err = h.Enterprise.PatchSCIMUser(r.Context(), directoryID, token, resourceID, input, version)
		} else {
			updated, err = h.Enterprise.ReplaceSCIMUser(r.Context(), directoryID, token, resourceID, body.input(false), version)
		}
		if err != nil {
			route.WriteSCIMError(w, err)
			return
		}
		projection.write(w, http.StatusOK, updated, directoryID)
	case http.MethodDelete:
		if resourceID == "" {
			route.WriteSCIMError(w, apierr.New("invalid_request", "a resource URL is required"))
			return
		}
		version, err := parseSCIMIfMatch(r.Header.Get("If-Match"))
		if err != nil {
			route.WriteSCIMError(w, err)
			return
		}
		if _, err := h.Enterprise.DeleteSCIMUser(r.Context(), directoryID, token, resourceID, version); err != nil {
			route.WriteSCIMError(w, err)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	default:
		route.WriteSCIMError(w, apierr.New("invalid_request", "SCIM method is not supported"))
	}
}

func (h HTTP) scimGroups(w http.ResponseWriter, r *http.Request) {
	if h.Enterprise == nil {
		route.WriteSCIMError(w, apierr.New("temporarily_unavailable", "SCIM is unavailable"))
		return
	}
	token, err := scimBearerToken(r)
	if err != nil {
		route.WriteSCIMError(w, err)
		return
	}
	directoryID, resourceID := r.PathValue("dir_id"), r.PathValue("id")
	switch r.Method {
	case http.MethodPost:
		if resourceID != "" {
			route.WriteSCIMError(w, apierr.New("invalid_request", "a collection URL is required"))
			return
		}
		var body scimGroupBody
		if err := decodeSCIMJSON(w, r, &body); err != nil {
			route.WriteSCIMError(w, err)
			return
		}
		input, inputErr := body.input()
		if inputErr != nil {
			route.WriteSCIMError(w, inputErr)
			return
		}
		created, err := h.Enterprise.CreateSCIMGroup(r.Context(), directoryID, token, input)
		if err != nil {
			route.WriteSCIMError(w, err)
			return
		}
		writeSCIMResource(w, http.StatusCreated, scimGroupResource(created, directoryID, true))
	case http.MethodGet:
		includeMembers := !scimExcludesGroupMembers(r.URL.Query())
		if resourceID != "" {
			group, err := h.Enterprise.GetSCIMGroup(r.Context(), directoryID, token, resourceID, includeMembers)
			if err != nil {
				route.WriteSCIMError(w, err)
				return
			}
			writeSCIMResource(w, http.StatusOK, scimGroupResource(group, directoryID, includeMembers))
			return
		}
		filter, err := parseSCIMCollectionFilter(r.URL.Query().Get("filter"), "displayName")
		if err != nil {
			route.WriteSCIMError(w, err)
			return
		}
		start, count, err := scimPagination(r)
		if err != nil {
			route.WriteSCIMError(w, err)
			return
		}
		h.listSCIMGroups(w, r, token, scimListQuery{filter: filter, start: start, count: count}, includeMembers)
	case http.MethodPut, http.MethodPatch:
		if resourceID == "" {
			route.WriteSCIMError(w, apierr.New("invalid_request", "a resource URL is required"))
			return
		}
		version, err := parseSCIMIfMatch(r.Header.Get("If-Match"))
		if err != nil {
			route.WriteSCIMError(w, err)
			return
		}
		var body scimGroupBody
		if err := decodeSCIMJSON(w, r, &body); err != nil {
			route.WriteSCIMError(w, err)
			return
		}
		var updated enterprise.SCIMGroup
		if r.Method == http.MethodPatch {
			operations, inputErr := body.patchOperations()
			if inputErr != nil {
				route.WriteSCIMError(w, inputErr)
				return
			}
			updated, err = h.Enterprise.PatchSCIMGroup(r.Context(), directoryID, token, resourceID, operations, version)
		} else {
			input, inputErr := body.input()
			if inputErr != nil {
				route.WriteSCIMError(w, inputErr)
				return
			}
			updated, err = h.Enterprise.ReplaceSCIMGroup(r.Context(), directoryID, token, resourceID, input, version)
		}
		if err != nil {
			route.WriteSCIMError(w, err)
			return
		}
		writeSCIMResource(w, http.StatusOK, scimGroupResource(updated, directoryID, true))
	case http.MethodDelete:
		if resourceID == "" {
			route.WriteSCIMError(w, apierr.New("invalid_request", "a resource URL is required"))
			return
		}
		version, err := parseSCIMIfMatch(r.Header.Get("If-Match"))
		if err != nil {
			route.WriteSCIMError(w, err)
			return
		}
		if err := h.Enterprise.DeleteSCIMGroup(r.Context(), directoryID, token, resourceID, version); err != nil {
			route.WriteSCIMError(w, err)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	default:
		route.WriteSCIMError(w, apierr.New("invalid_request", "SCIM method is not supported"))
	}
}

// SCIM clients may echo these read-only fields on a full resource write.
type scimReadOnlyFields struct {
	ID   json.RawMessage `json:"id,omitempty"`
	Meta json.RawMessage `json:"meta,omitempty"`
}

func (f scimReadOnlyFields) hasReadOnlyFields() bool {
	return f.ID != nil || f.Meta != nil
}

type scimUserBody struct {
	scimReadOnlyFields
	Schemas     []string               `json:"schemas,omitempty"`
	ExternalID  string                 `json:"externalId,omitempty"`
	UserName    string                 `json:"userName,omitempty"`
	DisplayName *string                `json:"displayName,omitempty"`
	Name        enterprise.SCIMName    `json:"name,omitempty"`
	Emails      []enterprise.SCIMEmail `json:"emails,omitempty"`
	Active      *bool                  `json:"active,omitempty"`
	Operations  []scimOperation        `json:"Operations,omitempty"`
}

func (b scimUserBody) input(patch bool) enterprise.SCIMUserInput {
	active := true
	activeSet := b.Active != nil
	if b.Active != nil {
		active = *b.Active
	}
	displayName := ""
	if b.DisplayName != nil {
		displayName = *b.DisplayName
	}
	return enterprise.SCIMUserInput{ExternalID: b.ExternalID, UserName: b.UserName, DisplayName: displayName, DisplayNameSet: b.DisplayName != nil, Name: b.Name, Emails: b.Emails, Active: active, ActiveSet: activeSet || !patch}
}

func (b scimUserBody) patchInput() (enterprise.SCIMUserInput, error) {
	if b.hasReadOnlyFields() {
		return enterprise.SCIMUserInput{}, apierr.New("invalid_request", "SCIM PATCH requires a PatchOp document")
	}
	if err := validateSCIMPatch(b.Schemas, len(b.Operations)); err != nil {
		return enterprise.SCIMUserInput{}, err
	}
	input := enterprise.SCIMUserInput{}
	for _, operation := range b.Operations {
		op := strings.ToLower(strings.TrimSpace(operation.Op))
		rawPath := strings.TrimSpace(operation.Path)
		path := strings.ToLower(rawPath)
		if op != "add" && op != "replace" && op != "remove" {
			return enterprise.SCIMUserInput{}, apierr.New("invalid_request", "SCIM PATCH operation is unsupported")
		}
		if path == "" {
			object, ok := operation.Value.(map[string]any)
			if !ok || op == "remove" || len(object) == 0 {
				return enterprise.SCIMUserInput{}, apierr.New("invalid_request", "SCIM PATCH value is invalid")
			}
			seen := map[string]bool{}
			for key, value := range object {
				name := strings.ToLower(key)
				if seen[name] {
					return enterprise.SCIMUserInput{}, apierr.New("invalid_request", "duplicate SCIM PATCH attribute")
				}
				seen[name] = true
				switch name {
				case "username":
					v, ok := value.(string)
					if !ok || strings.TrimSpace(v) == "" {
						return enterprise.SCIMUserInput{}, apierr.New("invalid_request", "userName must be a nonempty string")
					}
					input.UserName = v
				case "displayname":
					v, ok := value.(string)
					if !ok {
						return enterprise.SCIMUserInput{}, apierr.New("invalid_request", "displayName must be a string")
					}
					input.DisplayName, input.DisplayNameSet = v, true
				case "active":
					v, ok := value.(bool)
					if !ok {
						return enterprise.SCIMUserInput{}, apierr.New("invalid_request", "active must be a boolean")
					}
					input.Active, input.ActiveSet = v, true
				case "name":
					value, err := scimNamePatch(op, name, value)
					if err != nil {
						return enterprise.SCIMUserInput{}, err
					}
					input.NamePatches = append(input.NamePatches, value)
				case "emails":
					patch, err := scimEmailsPatch(op, name, value)
					if err != nil {
						return enterprise.SCIMUserInput{}, err
					}
					input.EmailPatches = append(input.EmailPatches, patch)
				default:
					return enterprise.SCIMUserInput{}, apierr.New("invalid_request", "SCIM PATCH attribute is unsupported")
				}
			}
			continue
		}
		switch path {
		case "username":
			if op == "remove" {
				return enterprise.SCIMUserInput{}, apierr.New("invalid_request", "userName cannot be removed")
			}
			value, ok := operation.Value.(string)
			if !ok || strings.TrimSpace(value) == "" {
				return enterprise.SCIMUserInput{}, apierr.New("invalid_request", "userName must be a string")
			}
			input.UserName = value
		case "displayname":
			if op == "remove" {
				input.DisplayName, input.DisplayNameSet = "", true
				continue
			}
			value, ok := operation.Value.(string)
			if !ok {
				return enterprise.SCIMUserInput{}, apierr.New("invalid_request", "displayName must be a string")
			}
			input.DisplayName, input.DisplayNameSet = value, true
		case "active":
			if op == "remove" {
				input.Active, input.ActiveSet = false, true
				continue
			}
			value, ok := operation.Value.(bool)
			if !ok {
				return enterprise.SCIMUserInput{}, apierr.New("invalid_request", "active must be a boolean")
			}
			input.Active, input.ActiveSet = value, true
		default:
			if path == "emails" || strings.HasPrefix(path, "emails[") {
				patch, err := scimEmailsPatch(op, rawPath, operation.Value)
				if err != nil {
					return enterprise.SCIMUserInput{}, err
				}
				input.EmailPatches = append(input.EmailPatches, patch)
				continue
			}
			if path != "name" && !strings.HasPrefix(path, "name.") {
				return enterprise.SCIMUserInput{}, apierr.New("invalid_request", "SCIM PATCH path is unsupported")
			}
			value, err := scimNamePatch(op, path, operation.Value)
			if err != nil {
				return enterprise.SCIMUserInput{}, err
			}
			input.NamePatches = append(input.NamePatches, value)
		}
	}
	return input, nil
}

func scimNamePatch(op, path string, value any) (enterprise.SCIMName, error) {
	if op == "remove" {
		if path == "name" {
			return nil, nil
		}
		value = nil
	}
	if field, ok := strings.CutPrefix(path, "name."); ok {
		value = map[string]any{field: value}
	} else if _, ok := value.(map[string]any); !ok {
		return nil, apierr.New("invalid_request", "SCIM name must be an object")
	}
	var name enterprise.SCIMName
	data, err := json.Marshal(value)
	if err != nil || json.Unmarshal(data, &name) != nil {
		return nil, apierr.New("invalid_request", "SCIM name is invalid")
	}
	return name, nil
}

type scimGroupBody struct {
	scimReadOnlyFields
	Schemas     []string `json:"schemas,omitempty"`
	ExternalID  string   `json:"externalId,omitempty"`
	DisplayName string   `json:"displayName,omitempty"`
	Members     []struct {
		Value string `json:"value"`
		Type  string `json:"type,omitempty"`
	} `json:"members,omitempty"`
	Operations []scimOperation `json:"Operations,omitempty"`
}

type scimOperation struct {
	Op    string `json:"op"`
	Path  string `json:"path,omitempty"`
	Value any    `json:"value,omitempty"`
}

func (b scimGroupBody) input() (enterprise.SCIMGroupInput, error) {
	members := make([]string, 0, len(b.Members))
	for _, member := range b.Members {
		if member.Type != "" && !strings.EqualFold(member.Type, "User") {
			return enterprise.SCIMGroupInput{}, apierr.New("invalid_request", "group members must have type User")
		}
		members = append(members, member.Value)
	}
	return enterprise.SCIMGroupInput{ExternalID: b.ExternalID, DisplayName: b.DisplayName, MemberIDs: members}, nil
}

func (b scimGroupBody) patchOperations() ([]enterprise.SCIMGroupOperation, error) {
	if b.hasReadOnlyFields() {
		return nil, apierr.New("invalid_request", "SCIM PATCH requires a PatchOp document")
	}
	if err := validateSCIMPatch(b.Schemas, len(b.Operations)); err != nil {
		return nil, err
	}
	operations := make([]enterprise.SCIMGroupOperation, 0, len(b.Operations))
	var appendOp func(scimOperation) error
	appendOp = func(op scimOperation) error {
		kind := strings.ToLower(strings.TrimSpace(op.Op))
		path := strings.ToLower(strings.TrimSpace(op.Path))
		if kind != "add" && kind != "replace" && kind != "remove" {
			return apierr.New("invalid_request", "SCIM PATCH operation is unsupported")
		}
		if path == "" {
			object, ok := op.Value.(map[string]any)
			if !ok || kind == "remove" || len(object) == 0 {
				return apierr.New("invalid_request", "SCIM PATCH value is invalid")
			}
			seen := make(map[string]bool, len(object))
			for key, value := range object {
				name := strings.ToLower(strings.TrimSpace(key))
				if name == "" || seen[name] {
					return apierr.New("invalid_request", "SCIM PATCH attribute is empty or duplicated")
				}
				seen[name] = true
				if err := appendOp(scimOperation{Op: kind, Path: key, Value: value}); err != nil {
					return err
				}
			}
			return nil
		}
		out := enterprise.SCIMGroupOperation{Op: kind, Path: path}
		switch {
		case path == "displayname":
			value, ok := op.Value.(string)
			if !ok || kind == "remove" {
				return apierr.New("invalid_request", "displayName must be a string")
			}
			out.DisplayName = value
		case path == "members":
			if kind == "remove" && op.Value == nil {
				out.MemberIDs = nil
				break
			}
			values, ok := scimMemberValues(op.Value)
			if !ok {
				return apierr.New("invalid_request", "members must contain SCIM user values")
			}
			out.MemberIDs = values
		case kind == "remove" && strings.HasPrefix(path, "members["):
			value, err := scimMemberSelector(op.Path)
			if err != nil {
				return err
			}
			out.Path = "members"
			out.MemberIDs = []string{value}
		default:
			return apierr.New("invalid_request", "SCIM PATCH path is unsupported")
		}
		operations = append(operations, out)
		return nil
	}
	for _, op := range b.Operations {
		if err := appendOp(op); err != nil {
			return nil, err
		}
	}
	return operations, nil
}

func validateSCIMPatch(schemas []string, count int) error {
	if count < 1 || count > 100 || len(schemas) != 1 || schemas[0] != "urn:ietf:params:scim:api:messages:2.0:PatchOp" {
		return apierr.New("invalid_request", "SCIM PATCH requires its schema and 1 to 100 operations")
	}
	return nil
}

func scimMemberSelector(path string) (string, error) {
	path = strings.TrimSpace(path)
	_, selection, _ := strings.Cut(path, "[")
	if len(path) <= 4096 && strings.HasSuffix(selection, "]") {
		attribute, operator, literal := splitSCIMComparison(strings.TrimSuffix(selection, "]"))
		if strings.EqualFold(attribute, "value") && strings.EqualFold(operator, "eq") {
			if value, valid := decodeSCIMFilterValue(literal); valid && len(value) <= 512 {
				return value, nil
			}
		}
	}
	return "", apierr.New("invalid_filter", "SCIM member filter requires equality on value")
}

func scimMemberValues(raw any) ([]string, bool) {
	var values []any
	switch value := raw.(type) {
	case []any:
		values = value
	case map[string]any:
		values = []any{value}
	default:
		return nil, false
	}
	if len(values) > 1000 {
		return nil, false
	}
	out := make([]string, 0, len(values))
	for _, rawValue := range values {
		object, ok := rawValue.(map[string]any)
		if !ok {
			return nil, false
		}
		var value string
		var hasType bool
		for name, raw := range object {
			switch strings.ToLower(name) {
			case "value":
				id, ok := raw.(string)
				if value != "" || !ok || strings.TrimSpace(id) == "" {
					return nil, false
				}
				value = id
			case "type":
				kind, ok := raw.(string)
				if hasType || !ok || !strings.EqualFold(kind, "User") {
					return nil, false
				}
				hasType = true
			}
		}
		if value == "" {
			return nil, false
		}
		out = append(out, value)
	}
	return out, true
}

func scimBearerToken(r *http.Request) (secret.String, error) {
	parts := strings.Fields(r.Header.Get("Authorization"))
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") || parts[1] == "" {
		return "", apierr.New("unauthenticated", "SCIM bearer token required")
	}
	return secret.New(parts[1]), nil
}

func decodeSCIMJSON(w http.ResponseWriter, r *http.Request, value any) error {
	return decodeSCIMJSONWithin(w, r, value, 256<<10)
}

func decodeSCIMJSONWithin(w http.ResponseWriter, r *http.Request, value any, limit int64) error {
	mediaType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || (mediaType != "application/scim+json" && mediaType != "application/json") {
		return apierr.New("invalid_request", "SCIM JSON body is required")
	}
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, limit))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(value); err != nil {
		return apierr.New("invalid_request", "SCIM JSON body is invalid")
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return apierr.New("invalid_request", "SCIM JSON body is invalid")
	}
	return nil
}

func scimPagination(r *http.Request) (int32, int32, error) {
	query := r.URL.Query()
	start, count := int64(1), int64(enterprise.MaxSCIMPageSize)
	var err error
	if raw := strings.TrimSpace(query.Get("startIndex")); raw != "" {
		start, err = strconv.ParseInt(raw, 10, 32)
		if err != nil {
			return 0, 0, apierr.New("invalid_request", "startIndex is invalid")
		}
	}
	if raw := strings.TrimSpace(query.Get("count")); raw != "" {
		count, err = strconv.ParseInt(raw, 10, 32)
		if err != nil {
			return 0, 0, apierr.New("invalid_request", "count is invalid")
		}
	}
	page, size := normalizeSCIMPage(int32(start), int32(count))
	return page, size, nil
}

func normalizeSCIMPage(start, count int32) (int32, int32) {
	return max(start, 1), min(max(count, 0), enterprise.MaxSCIMPageSize)
}

func parseSCIMCollectionFilter(raw, nameAttribute string) (enterprise.SCIMCollectionFilter, error) {
	var filter enterprise.SCIMCollectionFilter
	// Allow JSON escaping of each byte in a 512-byte external ID.
	if len(raw) > 4096 {
		return filter, apierr.New("invalid_filter", "SCIM filter is too long")
	}
	expression := strings.TrimSpace(raw)
	if expression == "" && len(raw) <= 512 {
		return filter, nil
	}
	attribute, operator, literal := splitSCIMComparison(expression)
	external := strings.EqualFold(attribute, "externalId")
	if (!external && !strings.EqualFold(attribute, nameAttribute)) || !strings.EqualFold(operator, "eq") {
		return filter, apierr.New("invalid_filter", "only equality on "+nameAttribute+" and externalId is supported")
	}
	if !external && len(raw) > 512 {
		return filter, apierr.New("invalid_filter", "SCIM filter is too long")
	}
	value, valid := decodeSCIMFilterValue(literal)
	if !valid {
		return filter, apierr.New("invalid_filter", "the SCIM filter value is invalid")
	}
	switch {
	case external:
		if len(value) > 512 {
			return filter, apierr.New("invalid_filter", "the externalId filter value is too long")
		}
		filter.ExternalID = value
	case nameAttribute == "userName":
		value = strings.ToLower(value)
		if !enterprise.ValidSCIMUserName(value) || strings.ContainsAny(value, `"\`) {
			return filter, apierr.New("invalid_filter", "the userName filter value is invalid")
		}
		filter.Name = value
	default:
		if len(value) > 128 {
			return filter, apierr.New("invalid_filter", "the displayName filter value is too long")
		}
		filter.Name = value
	}
	return filter, nil
}

func splitSCIMComparison(expression string) (attribute, operator, literal string) {
	attribute, rest, _ := strings.Cut(strings.TrimSpace(expression), " ")
	operator, literal, _ = strings.Cut(strings.TrimLeft(rest, " "), " ")
	return attribute, operator, strings.TrimSpace(literal)
}

func decodeSCIMFilterValue(literal string) (string, bool) {
	var value string
	if !strings.HasPrefix(literal, `"`) || !utf8.ValidString(literal) ||
		json.Unmarshal([]byte(literal), &value) != nil || strings.TrimSpace(value) == "" ||
		strings.ContainsFunc(value, unicode.IsControl) || strings.ContainsRune(value, utf8.RuneError) {
		return "", false
	}
	return value, true
}

func scimExcludesGroupMembers(query url.Values) bool {
	for _, exclusion := range query["excludedAttributes"] {
		for attribute := range strings.SplitSeq(exclusion, ",") {
			if strings.EqualFold(strings.TrimSpace(attribute), "members") {
				return true
			}
		}
	}
	return false
}

func parseSCIMIfMatch(raw string) (int64, error) {
	raw = strings.TrimSpace(raw)
	if !strings.HasPrefix(raw, `W/"`) || !strings.HasSuffix(raw, `"`) {
		return 0, apierr.New("precondition_failed", "If-Match must contain the resource version")
	}
	version, err := strconv.ParseInt(strings.TrimSuffix(strings.TrimPrefix(raw, `W/"`), `"`), 10, 64)
	if err != nil || version < 1 {
		return 0, apierr.New("precondition_failed", "If-Match must contain the resource version")
	}
	return version, nil
}

func scimUserResource(user enterprise.SCIMUser, directoryID string) map[string]any {
	resource := map[string]any{"schemas": []string{scimUser}, "id": user.ID, "externalId": user.ExternalID, "userName": user.UserName, "displayName": user.DisplayName, "active": user.Active, "meta": scimMeta("User", user.Version, user.CreatedAt, user.UpdatedAt, "/scim/v2/"+directoryID+"/Users/"+user.ID)}
	if len(user.Name) > 0 {
		resource["name"] = user.Name
	}
	if len(user.Emails) > 0 {
		resource["emails"] = user.Emails
	}
	return resource
}

func scimGroupResource(group enterprise.SCIMGroup, directoryID string, includeMembers bool) map[string]any {
	resource := map[string]any{"schemas": []string{scimGroup}, "id": group.ID, "externalId": group.ExternalID,
		"displayName": group.DisplayName, "meta": scimMeta("Group", group.Version, group.CreatedAt, group.UpdatedAt, "/scim/v2/"+directoryID+"/Groups/"+group.ID)}
	if includeMembers {
		members := make([]map[string]string, 0, len(group.MemberIDs))
		for _, id := range group.MemberIDs {
			members = append(members, map[string]string{"value": id, "type": "User"})
		}
		resource["members"] = members
	}
	return resource
}

func scimMeta(resourceType string, version int64, createdAt, updatedAt time.Time, location string) map[string]any {
	return map[string]any{"resourceType": resourceType, "location": location, "version": `W/"` + strconv.FormatInt(version, 10) + `"`, "created": createdAt.UTC().Format(time.RFC3339Nano), "lastModified": updatedAt.UTC().Format(time.RFC3339Nano)}
}

func writeSCIMResource(w http.ResponseWriter, status int, resource map[string]any) {
	writeSCIMResourceHeaders(w, resource)
	writeSCIMJSON(w, status, resource)
}

func writeSCIMResourceHeaders(w http.ResponseWriter, resource map[string]any) {
	if meta, ok := resource["meta"].(map[string]any); ok {
		if location, ok := meta["location"].(string); ok {
			w.Header().Set("Location", location)
		}
		if version, ok := meta["version"].(string); ok {
			w.Header().Set("ETag", version)
		}
	}
}

func writeSCIMJSON(w http.ResponseWriter, status int, resource map[string]any) {
	w.Header().Set("Content-Type", "application/scim+json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(resource)
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

func writeOAuthErr(w http.ResponseWriter, err error) {
	var publicErr *apierr.Error
	if errors.As(err, &publicErr) {
		if publicErr.Code == "invalid_client" {
			writeStandardOAuthError(w, publicErr)
			return
		}
		writeErr(w, publicErr)
		return
	}
	writeErr(w, apierr.New("temporarily_unavailable", "OAuth token exchange is unavailable"))
}

func writeStandardOAuthError(w http.ResponseWriter, err error) {
	writeOAuthEndpointError(w, err, "oauth/token")
}

func writeOAuthEndpointError(w http.ResponseWriter, err error, realm string) {
	var public *apierr.Error
	if !errors.As(err, &public) {
		public = apierr.New("temporarily_unavailable", "OAuth operation is unavailable")
	}
	if public.Code == "invalid_client" {
		w.Header().Set("WWW-Authenticate", `Basic realm="`+realm+`"`)
	}
	writeJSON(w, apierr.Status(public.Code), map[string]string{"error": public.Code, "error_description": public.Message})
}

func parseOAuthForm(r *http.Request) error {
	mediaType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/x-www-form-urlencoded" || r.URL.RawQuery != "" || r.URL.ForceQuery {
		return apierr.New("invalid_request", "OAuth parameters must be sent in the form body")
	}
	if err := r.ParseForm(); err != nil {
		return apierr.New("invalid_request", "form body is invalid")
	}
	for _, values := range r.PostForm {
		if len(values) != 1 {
			return apierr.New("invalid_request", "OAuth parameters must occur once")
		}
	}
	return nil
}

type clientCredentials struct {
	id, method string
	secret     secret.String
}

func oauthClientCredentials(r *http.Request, required bool) (clientCredentials, error) {
	formID := r.PostForm.Get("client_id")
	if headers := r.Header.Values("Authorization"); len(headers) > 0 {
		id, password, ok := r.BasicAuth()
		id, idErr := url.QueryUnescape(id)
		password, passwordErr := url.QueryUnescape(password)
		if len(headers) != 1 || !ok || id == "" || idErr != nil || passwordErr != nil || r.PostForm.Has("client_secret") || (r.PostForm.Has("client_id") && id != formID) {
			return clientCredentials{}, apierr.New("invalid_client", "supply one client authentication method")
		}
		return clientCredentials{id: id, secret: secret.New(password), method: "client_secret_basic"}, nil
	}
	if formID == "" && (required || r.PostForm.Has("client_secret") || r.PostForm.Has("client_id")) {
		return clientCredentials{}, apierr.New("invalid_client", "OAuth client authentication failed")
	}
	if r.PostForm.Has("client_secret") {
		return clientCredentials{id: formID, secret: secret.New(r.PostForm.Get("client_secret")), method: "client_secret_post"}, nil
	}
	return clientCredentials{id: formID, method: "none"}, nil
}

func parseAuthorizationScopes(raw string) []string {
	var scopes []string
	for scope := range strings.SplitSeq(raw, " ") {
		// RFC 6749 section 3.3 excludes double quotes and backslashes from the printable ASCII token.
		if scope == "" || strings.ContainsFunc(scope, func(c rune) bool {
			return c < '!' || c > '~' || c == '"' || c == '\\'
		}) {
			return nil
		}
		scopes = append(scopes, scope)
	}
	return uniqueScopes(scopes)
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
