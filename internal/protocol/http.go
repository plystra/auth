package protocol

import (
	"encoding/json"
	"net/http"
	"net/url"
	"strings"

	"github.com/plystra/auth/internal/apierr"
	"github.com/plystra/auth/internal/route"
)

type HTTP struct{ Issuer string }

func (h HTTP) Register(mux *http.ServeMux) {
	route.RegisterNonJSON(mux, route.Spec{Name: "oauth.metadata", Method: "GET", Path: "/.well-known/oauth-authorization-server", Plane: route.Principal, Subjects: []route.Subject{route.Public}, NonJSON: true}, http.HandlerFunc(h.metadata))
	route.RegisterNonJSON(mux, route.Spec{Name: "oidc.metadata", Method: "GET", Path: "/.well-known/openid-configuration", Plane: route.Principal, Subjects: []route.Subject{route.Public}, NonJSON: true}, http.HandlerFunc(h.metadata))
	route.RegisterNonJSON(mux, route.Spec{Name: "oauth.authorize", Method: "GET", Path: "/oauth/authorize", Plane: route.Principal, Subjects: []route.Subject{route.Public}, NonJSON: true}, http.HandlerFunc(h.authorize))
	route.RegisterNonJSON(mux, route.Spec{Name: "oauth.token", Method: "POST", Path: "/oauth/token", Plane: route.Principal, Subjects: []route.Subject{route.Public}, NonJSON: true}, http.HandlerFunc(h.token))
	route.RegisterNonJSON(mux, route.Spec{Name: "oauth.revoke", Method: "POST", Path: "/oauth/revoke", Plane: route.Principal, Subjects: []route.Subject{route.Public}, NonJSON: true}, http.HandlerFunc(h.notImplemented))
	route.RegisterNonJSON(mux, route.Spec{Name: "oauth.device_authorization", Method: "POST", Path: "/oauth/device_authorization", Plane: route.Principal, Subjects: []route.Subject{route.Public}, NonJSON: true}, http.HandlerFunc(h.notImplemented))
	route.RegisterNonJSON(mux, route.Spec{Name: "oauth.register", Method: "POST", Path: "/oauth/register", Plane: route.Principal, Subjects: []route.Subject{route.Public}, NonJSON: true}, http.HandlerFunc(h.notImplemented))
	route.RegisterNonJSON(mux, route.Spec{Name: "oauth.userinfo", Method: "GET", Path: "/oauth/userinfo", Plane: route.Principal, Subjects: []route.Subject{route.HumanAgent}, NonJSON: true}, http.HandlerFunc(h.notImplemented))
	route.RegisterNonJSON(mux, route.Spec{Name: "scim.users", Method: "GET", Path: "/scim/v2/{dir_id}/Users", Plane: route.Principal, Subjects: []route.Subject{route.Public}, NonJSON: true}, http.HandlerFunc(h.scimUsers))
	route.RegisterNonJSON(mux, route.Spec{Name: "sso.start", Method: "GET", Path: "/v1/sso/{connection_id}/start", Plane: route.Principal, Subjects: []route.Subject{route.Public}, NonJSON: true}, http.HandlerFunc(h.notImplemented))
	route.RegisterNonJSON(mux, route.Spec{Name: "sso.callback", Method: "POST", Path: "/v1/sso/{connection_id}/callback", Plane: route.Principal, Subjects: []route.Subject{route.Public}, NonJSON: true}, http.HandlerFunc(h.notImplemented))
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
	writeErr(w, apierr.New("not_implemented", "authorization requires an authenticated consent session"))
}
func (h HTTP) token(w http.ResponseWriter, r *http.Request) {
	if e := r.ParseForm(); e != nil {
		writeErr(w, apierr.New("invalid_request", "form body is invalid"))
		return
	}
	if r.Form.Get("grant_type") == "authorization_code" && r.Form.Get("code_verifier") == "" {
		writeErr(w, apierr.New("invalid_request", "code_verifier is required"))
		return
	}
	writeErr(w, apierr.New("invalid_grant", "authorization grant is invalid or expired"))
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

var _ = url.Values{}
