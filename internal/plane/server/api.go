package server

import (
	"context"
	"strings"

	"github.com/danielgtaylor/huma/v2"
	"github.com/plystra/auth/internal/apierr"
	"github.com/plystra/auth/internal/application"
	"github.com/plystra/auth/internal/authz/engine"
	"github.com/plystra/auth/internal/member"
	"github.com/plystra/auth/internal/route"
	"github.com/plystra/auth/internal/session"
)

type API struct {
	Applications *application.Service
	Members      *member.Service
	Sessions     *session.Service
}
type CheckBody struct {
	MemberID      string `json:"member_id"`
	Permission    string `json:"permission"`
	ResourceSpace string `json:"resource_space"`
	ResourceOwner string `json:"resource_owner,omitempty"`
}
type CheckInput struct {
	Authorization string `header:"Authorization"`
	Body          CheckBody
}
type CheckOutput struct {
	Body struct {
		Data engine.Decision `json:"data"`
	}
}
type IntrospectInput struct {
	Authorization string `header:"Authorization"`
	Body          struct {
		Token string `json:"token"`
	}
}
type IntrospectOutput struct {
	Body struct {
		Data struct {
			Active    bool   `json:"active"`
			Subject   string `json:"sub,omitempty"`
			SessionID string `json:"sid,omitempty"`
			ExpiresAt int64  `json:"exp,omitempty"`
		} `json:"data"`
	}
}

func (a *API) Register(api huma.API) {
	route.Register(api, route.Spec{Name: "authz.check", Method: "POST", Path: "/server/v1/authz/check", Plane: route.Server, Permission: "auth.authz:check", Subjects: []route.Subject{route.HumanAgent}, AuthoritativeCheck: true}, a.check)
	route.Register(api, route.Spec{Name: "tokens.introspect", Method: "POST", Path: "/server/v1/tokens/introspect", Plane: route.Server, Permission: "auth.tokens:introspect", Subjects: []route.Subject{route.HumanAgent}}, a.introspect)
}
func (a *API) check(ctx context.Context, in *CheckInput) (*CheckOutput, error) {
	key, e := a.key(ctx, in.Authorization)
	if e != nil {
		return nil, e
	}
	if !contains(key.Scopes, "auth.authz:check") {
		return nil, apierr.New("forbidden", "API key is not scoped for authz checks")
	}
	perms, e := a.Members.Permissions(ctx, in.Body.MemberID)
	if e != nil {
		return nil, e
	}
	keys := make([]string, 0, len(perms))
	for _, p := range perms {
		keys = append(keys, p.Key)
	}
	decision := engine.Check(engine.Request{MemberID: in.Body.MemberID, Permission: in.Body.Permission, ResourceSpace: in.Body.ResourceSpace, ResourceOwner: in.Body.ResourceOwner, Assignments: []engine.Assignment{{MemberID: in.Body.MemberID, Role: "member", Permissions: keys, Scope: engine.Scope{Anchor: key.SpaceID, IncludeDescendants: true}}}})
	out := &CheckOutput{}
	out.Body.Data = decision
	return out, nil
}
func (a *API) introspect(ctx context.Context, in *IntrospectInput) (*IntrospectOutput, error) {
	key, e := a.key(ctx, in.Authorization)
	if e != nil {
		return nil, e
	}
	if !contains(key.Scopes, "auth.tokens:introspect") {
		return nil, apierr.New("forbidden", "API key is not scoped for token introspection")
	}
	if strings.TrimSpace(in.Body.Token) == "" {
		return nil, apierr.New("invalid_request", "token is required")
	}
	if a.Sessions == nil {
		return nil, apierr.New("unavailable", "token introspection is unavailable")
	}
	claims, active, e := a.Sessions.Introspect(ctx, in.Body.Token, key.ClientID)
	if e != nil {
		return nil, e
	}
	out := &IntrospectOutput{}
	out.Body.Data.Active = active
	if active {
		out.Body.Data.Subject = claims.Subject
		out.Body.Data.SessionID = claims.SessionID
		out.Body.Data.ExpiresAt = claims.ExpiresAt
	}
	return out, nil
}
func (a *API) key(ctx context.Context, value string) (application.Key, error) {
	parts := strings.Fields(value)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
		return application.Key{}, apierr.New("unauthorized", "application API key is required")
	}
	return a.Applications.AuthenticateKey(ctx, parts[1])
}
func contains(ss []string, w string) bool {
	for _, s := range ss {
		if s == w {
			return true
		}
	}
	return false
}
