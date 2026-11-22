package protocol

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/plystra/auth/internal/account"
	"github.com/plystra/auth/internal/agent"
	"github.com/plystra/auth/internal/apierr"
	"github.com/plystra/auth/internal/application"
	"github.com/plystra/auth/internal/audit"
	"github.com/plystra/auth/internal/authorization"
	"github.com/plystra/auth/internal/enterprise"
	"github.com/plystra/auth/internal/route"
	"github.com/plystra/auth/internal/secret"
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
	route.RegisterNonJSON(mux, route.NewSpec("scim.users.create", "POST", "/scim/v2/{dir_id}/Users", route.Principal, "", []route.Subject{route.Public}, route.WithNonJSON(), route.WithMaxBodyBytes(256<<10)), http.HandlerFunc(h.scimUsers))
	route.RegisterNonJSON(mux, route.NewSpec("scim.users", "GET", "/scim/v2/{dir_id}/Users", route.Principal, "", []route.Subject{route.Public}, route.WithNonJSON()), http.HandlerFunc(h.scimUsers))
	route.RegisterNonJSON(mux, route.NewSpec("scim.user.get", "GET", "/scim/v2/{dir_id}/Users/{id}", route.Principal, "", []route.Subject{route.Public}, route.WithNonJSON()), http.HandlerFunc(h.scimUsers))
	route.RegisterNonJSON(mux, route.NewSpec("scim.user.replace", "PUT", "/scim/v2/{dir_id}/Users/{id}", route.Principal, "", []route.Subject{route.Public}, route.WithNonJSON(), route.WithMaxBodyBytes(256<<10)), http.HandlerFunc(h.scimUsers))
	route.RegisterNonJSON(mux, route.NewSpec("scim.user.patch", "PATCH", "/scim/v2/{dir_id}/Users/{id}", route.Principal, "", []route.Subject{route.Public}, route.WithNonJSON(), route.WithMaxBodyBytes(256<<10)), http.HandlerFunc(h.scimUsers))
	route.RegisterNonJSON(mux, route.NewSpec("scim.user.delete", "DELETE", "/scim/v2/{dir_id}/Users/{id}", route.Principal, "", []route.Subject{route.Public}, route.WithNonJSON()), http.HandlerFunc(h.scimUsers))
	route.RegisterNonJSON(mux, route.NewSpec("scim.groups.create", "POST", "/scim/v2/{dir_id}/Groups", route.Principal, "", []route.Subject{route.Public}, route.WithNonJSON(), route.WithMaxBodyBytes(256<<10)), http.HandlerFunc(h.scimGroups))
	route.RegisterNonJSON(mux, route.NewSpec("scim.groups", "GET", "/scim/v2/{dir_id}/Groups", route.Principal, "", []route.Subject{route.Public}, route.WithNonJSON()), http.HandlerFunc(h.scimGroups))
	route.RegisterNonJSON(mux, route.NewSpec("scim.group.get", "GET", "/scim/v2/{dir_id}/Groups/{id}", route.Principal, "", []route.Subject{route.Public}, route.WithNonJSON()), http.HandlerFunc(h.scimGroups))
	route.RegisterNonJSON(mux, route.NewSpec("scim.group.replace", "PUT", "/scim/v2/{dir_id}/Groups/{id}", route.Principal, "", []route.Subject{route.Public}, route.WithNonJSON(), route.WithMaxBodyBytes(256<<10)), http.HandlerFunc(h.scimGroups))
	route.RegisterNonJSON(mux, route.NewSpec("scim.group.patch", "PATCH", "/scim/v2/{dir_id}/Groups/{id}", route.Principal, "", []route.Subject{route.Public}, route.WithNonJSON(), route.WithMaxBodyBytes(256<<10)), http.HandlerFunc(h.scimGroups))
	route.RegisterNonJSON(mux, route.NewSpec("scim.group.delete", "DELETE", "/scim/v2/{dir_id}/Groups/{id}", route.Principal, "", []route.Subject{route.Public}, route.WithNonJSON()), http.HandlerFunc(h.scimGroups))
	route.RegisterNonJSON(mux, route.NewSpec("sso.start", "GET", "/v1/sso/{connection_id}/start", route.Principal, "", []route.Subject{route.Public}, route.WithNonJSON()), http.HandlerFunc(h.ssoStart))
	route.RegisterNonJSON(mux, route.NewSpec("sso.callback", "POST", "/v1/sso/{connection_id}/callback", route.Principal, "", []route.Subject{route.Public}, route.WithNonJSON(), route.WithMaxBodyBytes(64<<10)), http.HandlerFunc(h.ssoCallback))
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
	scopes := uniqueScopes(strings.Fields(q.Get("scope")))
	if len(scopes) == 0 || len(scopes) > 100 {
		writeErr(w, apierr.New("invalid_scope", "at least one scope is required"))
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
		MemberID    string   `json:"member_id"`
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
	redirectTo, err := (application.OAuthConsent{Applications: h.Applications, Agents: h.Agents, Authorization: h.Authorization, Sessions: h.Sessions}).Decide(r.Context(), application.OAuthConsentInput{
		RequestID: secret.New(body.RequestID), AccessToken: secret.New(strings.Fields(r.Header.Get("Authorization"))[1]), UserID: claims.Subject, Decision: body.Decision,
		MemberID: body.MemberID, Permissions: body.Permissions,
	})
	if err != nil {
		writeProtocolErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"redirect_to": redirectTo})
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
		if h.Agents == nil || h.Sessions == nil || h.Applications == nil {
			writeErr(w, apierr.New("temporarily_unavailable", "agent refresh is unavailable"))
			return
		}
		clientID, clientSecret, err := oauthClientCredentials(r)
		if err != nil {
			writeOAuthErr(w, err)
			return
		}
		tokens, scope, err := (tokenService{applications: h.Applications, agents: h.Agents, sessions: h.Sessions, authorization: h.Authorization}).refresh(
			r.Context(), clientID, secret.New(clientSecret), secret.New(r.Form.Get("refresh_token")), r.Form.Get("resource"), r.Form.Get("scope"))
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
	if h.Applications == nil || h.Agents == nil || h.Sessions == nil {
		writeErr(w, apierr.New("temporarily_unavailable", "authorization code exchange is unavailable"))
		return
	}
	clientID, clientSecret, err := oauthClientCredentials(r)
	if err != nil {
		writeOAuthErr(w, err)
		return
	}
	redirectURI := strings.TrimSpace(r.Form.Get("redirect_uri"))
	verifier := r.Form.Get("code_verifier")
	code := r.Form.Get("code")
	if clientID == "" || redirectURI == "" || verifier == "" || code == "" {
		writeErr(w, apierr.New("invalid_request", "client_id, redirect_uri, code and code_verifier are required"))
		return
	}
	tokens, scope, err := (tokenService{applications: h.Applications, agents: h.Agents, sessions: h.Sessions}).authorizationCode(r.Context(), codeExchangeInput{
		clientID: clientID, clientSecret: secret.New(clientSecret), redirectURI: redirectURI, code: secret.New(code), verifier: secret.New(verifier),
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
		ctx := audit.WithCaller(r.Context(), audit.Caller{CredentialType: "oauth_refresh_token"})
		_, err := h.Agents.RevokeOAuthRefreshToken(ctx, raw)
		if err != nil {
			writeErr(w, apierr.New("temporarily_unavailable", "token revocation is unavailable"))
			return
		}
		w.WriteHeader(http.StatusOK)
		return
	}
	if err := (tokenService{agents: h.Agents, sessions: h.Sessions}).revokeOAuthAccess(r.Context(), secret.New(raw)); err != nil {
		writeErr(w, apierr.New("temporarily_unavailable", "token revocation is unavailable"))
		return
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
		if err := r.ParseForm(); err != nil {
			writeErr(w, apierr.New("invalid_request", "SAML callback body is invalid"))
			return
		}
		result, err := h.Enterprise.Callback(r.Context(), enterprise.CallbackInput{
			ConnectionID: r.PathValue("connection_id"), State: r.FormValue("RelayState"), SAMLResponse: r.FormValue("SAMLResponse"),
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
		writeSCIMError(w, apierr.New("temporarily_unavailable", "SCIM is unavailable"))
		return
	}
	token, err := scimBearerToken(r)
	if err != nil {
		writeSCIMError(w, err)
		return
	}
	directoryID := r.PathValue("dir_id")
	resourceID := r.PathValue("id")
	switch r.Method {
	case http.MethodPost:
		if resourceID != "" {
			writeSCIMError(w, apierr.New("invalid_request", "a collection URL is required"))
			return
		}
		var body scimUserBody
		if err := decodeSCIMJSON(w, r, &body); err != nil {
			writeSCIMError(w, err)
			return
		}
		created, err := h.Enterprise.CreateSCIMUser(r.Context(), directoryID, token, body.input(true))
		if err != nil {
			writeSCIMError(w, err)
			return
		}
		writeSCIMResource(w, http.StatusCreated, scimUserResource(created))
	case http.MethodGet:
		if resourceID != "" {
			user, err := h.Enterprise.GetSCIMUser(r.Context(), directoryID, token, resourceID)
			if err != nil {
				writeSCIMError(w, err)
				return
			}
			writeSCIMResource(w, http.StatusOK, scimUserResource(user))
			return
		}
		start, count, err := scimPagination(r)
		if err != nil {
			writeSCIMError(w, err)
			return
		}
		filter, err := parseSCIMUserFilter(r.URL.Query().Get("filter"))
		if err != nil {
			writeSCIMError(w, err)
			return
		}
		users, total, err := h.Enterprise.ListSCIMUsers(r.Context(), directoryID, token, filter, start, count)
		if err != nil {
			writeSCIMError(w, err)
			return
		}
		resources := make([]any, 0, len(users))
		for _, user := range users {
			resources = append(resources, scimUserResource(user))
		}
		writeJSON(w, http.StatusOK, map[string]any{"schemas": []string{"urn:ietf:params:scim:api:messages:2.0:ListResponse"}, "totalResults": total, "startIndex": start, "itemsPerPage": len(resources), "Resources": resources})
	case http.MethodPut, http.MethodPatch:
		if resourceID == "" {
			writeSCIMError(w, apierr.New("invalid_request", "a resource URL is required"))
			return
		}
		version, err := parseSCIMIfMatch(r.Header.Get("If-Match"))
		if err != nil {
			writeSCIMError(w, err)
			return
		}
		var body scimUserBody
		if err := decodeSCIMJSON(w, r, &body); err != nil {
			writeSCIMError(w, err)
			return
		}
		var updated enterprise.SCIMUser
		if r.Method == http.MethodPatch {
			updated, err = h.Enterprise.PatchSCIMUser(r.Context(), directoryID, token, resourceID, body.input(true), version)
		} else {
			updated, err = h.Enterprise.ReplaceSCIMUser(r.Context(), directoryID, token, resourceID, body.input(false), version)
		}
		if err != nil {
			writeSCIMError(w, err)
			return
		}
		writeSCIMResource(w, http.StatusOK, scimUserResource(updated))
	case http.MethodDelete:
		if resourceID == "" {
			writeSCIMError(w, apierr.New("invalid_request", "a resource URL is required"))
			return
		}
		version, err := parseSCIMIfMatch(r.Header.Get("If-Match"))
		if err != nil {
			writeSCIMError(w, err)
			return
		}
		if _, err := h.Enterprise.DeleteSCIMUser(r.Context(), directoryID, token, resourceID, version); err != nil {
			writeSCIMError(w, err)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	default:
		writeSCIMError(w, apierr.New("invalid_request", "SCIM method is not supported"))
	}
}

func (h HTTP) scimGroups(w http.ResponseWriter, r *http.Request) {
	if h.Enterprise == nil {
		writeSCIMError(w, apierr.New("temporarily_unavailable", "SCIM is unavailable"))
		return
	}
	token, err := scimBearerToken(r)
	if err != nil {
		writeSCIMError(w, err)
		return
	}
	directoryID, resourceID := r.PathValue("dir_id"), r.PathValue("id")
	switch r.Method {
	case http.MethodPost:
		if resourceID != "" {
			writeSCIMError(w, apierr.New("invalid_request", "a collection URL is required"))
			return
		}
		var body scimGroupBody
		if err := decodeSCIMJSON(w, r, &body); err != nil {
			writeSCIMError(w, err)
			return
		}
		created, err := h.Enterprise.CreateSCIMGroup(r.Context(), directoryID, token, body.input())
		if err != nil {
			writeSCIMError(w, err)
			return
		}
		writeSCIMResource(w, http.StatusCreated, scimGroupResource(created))
	case http.MethodGet:
		if resourceID != "" {
			group, err := h.Enterprise.GetSCIMGroup(r.Context(), directoryID, token, resourceID)
			if err != nil {
				writeSCIMError(w, err)
				return
			}
			writeSCIMResource(w, http.StatusOK, scimGroupResource(group))
			return
		}
		start, count, err := scimPagination(r)
		if err != nil {
			writeSCIMError(w, err)
			return
		}
		groups, total, err := h.Enterprise.ListSCIMGroups(r.Context(), directoryID, token, start, count)
		if err != nil {
			writeSCIMError(w, err)
			return
		}
		resources := make([]any, 0, len(groups))
		for _, group := range groups {
			resources = append(resources, scimGroupResource(group))
		}
		writeJSON(w, http.StatusOK, map[string]any{"schemas": []string{"urn:ietf:params:scim:api:messages:2.0:ListResponse"}, "totalResults": total, "startIndex": start, "itemsPerPage": len(resources), "Resources": resources})
	case http.MethodPut, http.MethodPatch:
		if resourceID == "" {
			writeSCIMError(w, apierr.New("invalid_request", "a resource URL is required"))
			return
		}
		version, err := parseSCIMIfMatch(r.Header.Get("If-Match"))
		if err != nil {
			writeSCIMError(w, err)
			return
		}
		var body scimGroupBody
		if err := decodeSCIMJSON(w, r, &body); err != nil {
			writeSCIMError(w, err)
			return
		}
		updated, err := h.Enterprise.ReplaceSCIMGroup(r.Context(), directoryID, token, resourceID, body.input(), version)
		if err != nil {
			writeSCIMError(w, err)
			return
		}
		writeSCIMResource(w, http.StatusOK, scimGroupResource(updated))
	case http.MethodDelete:
		if resourceID == "" {
			writeSCIMError(w, apierr.New("invalid_request", "a resource URL is required"))
			return
		}
		version, err := parseSCIMIfMatch(r.Header.Get("If-Match"))
		if err != nil {
			writeSCIMError(w, err)
			return
		}
		if err := h.Enterprise.DeleteSCIMGroup(r.Context(), directoryID, token, resourceID, version); err != nil {
			writeSCIMError(w, err)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	default:
		writeSCIMError(w, apierr.New("invalid_request", "SCIM method is not supported"))
	}
}

type scimUserBody struct {
	Schemas     []string `json:"schemas,omitempty"`
	ExternalID  string   `json:"externalId,omitempty"`
	UserName    string   `json:"userName,omitempty"`
	DisplayName string   `json:"displayName,omitempty"`
	Active      *bool    `json:"active,omitempty"`
}

func (b scimUserBody) input(patch bool) enterprise.SCIMUserInput {
	active := true
	activeSet := b.Active != nil
	if b.Active != nil {
		active = *b.Active
	}
	return enterprise.SCIMUserInput{ExternalID: b.ExternalID, UserName: b.UserName, DisplayName: b.DisplayName, Active: active, ActiveSet: activeSet || !patch}
}

type scimGroupBody struct {
	Schemas     []string `json:"schemas,omitempty"`
	ExternalID  string   `json:"externalId,omitempty"`
	DisplayName string   `json:"displayName,omitempty"`
	Members     []struct {
		Value string `json:"value"`
	} `json:"members,omitempty"`
}

func (b scimGroupBody) input() enterprise.SCIMGroupInput {
	members := make([]string, 0, len(b.Members))
	for _, member := range b.Members {
		members = append(members, member.Value)
	}
	return enterprise.SCIMGroupInput{ExternalID: b.ExternalID, DisplayName: b.DisplayName, MemberIDs: members}
}

func scimBearerToken(r *http.Request) (string, error) {
	parts := strings.Fields(r.Header.Get("Authorization"))
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") || parts[1] == "" {
		return "", apierr.New("unauthenticated", "SCIM bearer token required")
	}
	return parts[1], nil
}

func decodeSCIMJSON(w http.ResponseWriter, r *http.Request, value any) error {
	mediaType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || (mediaType != "application/scim+json" && mediaType != "application/json") {
		return apierr.New("invalid_request", "SCIM JSON body is required")
	}
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 256<<10))
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
	start, count := int64(1), int64(100)
	var err error
	if raw := strings.TrimSpace(r.URL.Query().Get("startIndex")); raw != "" {
		start, err = strconv.ParseInt(raw, 10, 32)
		if err != nil {
			return 0, 0, apierr.New("invalid_request", "startIndex is invalid")
		}
	}
	if raw := strings.TrimSpace(r.URL.Query().Get("count")); raw != "" {
		count, err = strconv.ParseInt(raw, 10, 32)
		if err != nil {
			return 0, 0, apierr.New("invalid_request", "count is invalid")
		}
	}
	if start < 1 || count < 1 || count > 100 {
		return 0, 0, apierr.New("invalid_request", "SCIM pagination is invalid")
	}
	return int32(start), int32(count), nil
}

func parseSCIMUserFilter(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", nil
	}
	const prefix = `userName eq "`
	if !strings.HasPrefix(raw, prefix) || !strings.HasSuffix(raw, `"`) || len(raw) <= len(prefix)+1 {
		return "", apierr.New("invalid_filter", "only userName eq \"…\" is supported")
	}
	value := strings.TrimSuffix(strings.TrimPrefix(raw, prefix), `"`)
	if strings.Contains(value, `"`) || !validSCIMFilterEmail(value) {
		return "", apierr.New("invalid_filter", "the userName filter is invalid")
	}
	return strings.ToLower(value), nil
}

func validSCIMFilterEmail(value string) bool {
	if len(value) == 0 || len(value) > 320 || strings.ContainsAny(value, " \t\r\n") {
		return false
	}
	at := strings.LastIndexByte(value, '@')
	return at > 0 && at < len(value)-1 && !strings.Contains(value[at+1:], "@")
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

func scimUserResource(user enterprise.SCIMUser) map[string]any {
	return map[string]any{"schemas": []string{"urn:ietf:params:scim:schemas:core:2.0:User"}, "id": user.ID, "externalId": user.ExternalID, "userName": user.UserName, "displayName": user.DisplayName, "active": user.Active, "meta": scimMeta("User", user.Version, user.CreatedAt, user.UpdatedAt)}
}

func scimGroupResource(group enterprise.SCIMGroup) map[string]any {
	members := make([]map[string]string, 0, len(group.MemberIDs))
	for _, id := range group.MemberIDs {
		members = append(members, map[string]string{"value": id, "type": "User"})
	}
	return map[string]any{"schemas": []string{"urn:ietf:params:scim:schemas:core:2.0:Group"}, "id": group.ID, "externalId": group.ExternalID, "displayName": group.DisplayName, "members": members, "meta": scimMeta("Group", group.Version, group.CreatedAt, group.UpdatedAt)}
}

func scimMeta(resourceType string, version int64, createdAt, updatedAt time.Time) map[string]any {
	return map[string]any{"resourceType": resourceType, "version": `W/"` + strconv.FormatInt(version, 10) + `"`, "created": createdAt.UTC().Format(time.RFC3339Nano), "lastModified": updatedAt.UTC().Format(time.RFC3339Nano)}
}

func writeSCIMResource(w http.ResponseWriter, status int, resource map[string]any) {
	w.Header().Set("Content-Type", "application/scim+json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(resource)
}

func writeSCIMError(w http.ResponseWriter, err error) {
	var public *apierr.Error
	if !errors.As(err, &public) {
		public = apierr.New("temporarily_unavailable", "SCIM operation is unavailable")
	}
	status := apierr.Status(public.Code)
	scimType := ""
	if public.Code == "invalid_filter" {
		status, scimType = http.StatusBadRequest, "invalidFilter"
	}
	if public.Code == "precondition_failed" {
		status = http.StatusPreconditionFailed
	}
	w.Header().Set("Content-Type", "application/scim+json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{"schemas": []string{"urn:ietf:params:scim:api:messages:2.0:Error"}, "detail": public.Message, "status": strconv.Itoa(status), "scimType": scimType})
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
			w.Header().Set("WWW-Authenticate", `Basic realm="oauth/token"`)
		}
		writeErr(w, publicErr)
		return
	}
	writeErr(w, apierr.New("temporarily_unavailable", "OAuth token exchange is unavailable"))
}

func oauthClientCredentials(r *http.Request) (string, string, error) {
	formID := strings.TrimSpace(r.Form.Get("client_id"))
	formSecret := r.Form.Get("client_secret")
	basicID, basicSecret, basicOK := r.BasicAuth()
	if basicOK {
		if formID != "" && formID != basicID {
			return "", "", apierr.New("invalid_client", "OAuth client authentication failed")
		}
		return strings.TrimSpace(basicID), basicSecret, nil
	}
	if formID == "" {
		return "", "", apierr.New("invalid_request", "client_id is required")
	}
	return formID, formSecret, nil
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
