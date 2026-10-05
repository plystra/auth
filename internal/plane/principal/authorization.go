package principal

import (
	"context"
	"strings"

	"github.com/danielgtaylor/huma/v2"
	"github.com/plystra/auth/internal/apierr"
	"github.com/plystra/auth/internal/authorization"
	"github.com/plystra/auth/internal/authz/engine"
	"github.com/plystra/auth/internal/route"
	"github.com/plystra/auth/internal/security"
)

type createSpaceInput struct {
	Authorization string `header:"Authorization"`
	Body          struct {
		Name string `json:"name"`
		Slug string `json:"slug"`
	}
}

type spacePathInput struct {
	Authorization string `header:"Authorization"`
	ID            string `path:"id"`
}

type createMemberInput struct {
	Authorization string `header:"Authorization"`
	ID            string `path:"id"`
	Body          struct {
		Name          string `json:"name"`
		Kind          string `json:"type"`
		BindingPolicy string `json:"binding_policy"`
		UserID        string `json:"user_id,omitempty"`
	}
}

type createRoleInput struct {
	Authorization string `header:"Authorization"`
	ID            string `path:"id"`
	Body          struct {
		Name        string   `json:"name"`
		Description string   `json:"description,omitempty"`
		Permissions []string `json:"permissions"`
	}
}

type createGrantInput struct {
	Authorization string `header:"Authorization"`
	ID            string `path:"id"`
	Body          struct {
		GranteeMemberID string   `json:"grantee_member_id"`
		RoleID          string   `json:"role_id"`
		Permissions     []string `json:"permissions,omitempty"`
		Scope           string   `json:"scope,omitempty"`
		AnchorSpaceID   string   `json:"anchor_space_id,omitempty"`
	}
}

type revokeGrantInput struct {
	Authorization string `header:"Authorization"`
	ID            string `path:"id"`
	GrantID       string `path:"grant_id"`
}

type memberPathInput struct {
	Authorization string `header:"Authorization"`
	ID            string `path:"id"`
	MemberID      string `path:"mid"`
}

type bindUserInput struct {
	Authorization string `header:"Authorization"`
	ID            string `path:"id"`
	MemberID      string `path:"mid"`
	Body          struct {
		UserID string `json:"user_id"`
	}
}

type unbindUserInput struct {
	Authorization string `header:"Authorization"`
	ID            string `path:"id"`
	MemberID      string `path:"mid"`
	UserID        string `path:"user_id"`
}

type memberPatchInput struct {
	Authorization string `header:"Authorization"`
	ID            string `path:"id"`
	MemberID      string `path:"mid"`
	Body          struct {
		BindingPolicy string `json:"binding_policy"`
	}
}

type authorizationDataOutput[T any] struct {
	Body struct {
		Data T `json:"data"`
	}
}

type acceptedData struct {
	Accepted bool `json:"accepted"`
}

type createdSpaceData struct {
	Space  authorization.Space  `json:"space"`
	Member authorization.Member `json:"member"`
}

func (a *API) registerAuthorizationRoutes(api huma.API) {
	route.Register(api, route.Spec{Name: "spaces.create", Method: "POST", Path: "/v1/spaces", Plane: route.Principal, Permission: "self:read", Subjects: []route.Subject{route.HumanAgent}}, a.createSpace)
	route.Register(api, route.Spec{Name: "spaces.get", Method: "GET", Path: "/v1/spaces/{id}", Plane: route.Principal, Permission: "auth.members:read", Subjects: []route.Subject{route.HumanAgent}}, a.getSpace)
	route.Register(api, route.Spec{Name: "spaces.children", Method: "GET", Path: "/v1/spaces/{id}/children", Plane: route.Principal, Permission: "auth.members:read", Subjects: []route.Subject{route.HumanAgent}}, a.listChildren)
	route.Register(api, route.Spec{Name: "members.list", Method: "GET", Path: "/v1/spaces/{id}/members", Plane: route.Principal, Permission: "auth.members:read", Subjects: []route.Subject{route.HumanAgent}}, a.listMembers)
	route.Register(api, route.Spec{Name: "members.create", Method: "POST", Path: "/v1/spaces/{id}/members", Plane: route.Principal, Permission: "auth.members:manage", Subjects: []route.Subject{route.HumanAgent}, AuthoritativeCheck: true}, a.createMember)
	route.Register(api, route.Spec{Name: "members.update", Method: "PATCH", Path: "/v1/spaces/{id}/members/{mid}", Plane: route.Principal, Permission: "auth.bindings:manage", Subjects: []route.Subject{route.HumanAgent}, AuthoritativeCheck: true}, a.updateMember)
	route.Register(api, route.Spec{Name: "members.suspend", Method: "POST", Path: "/v1/spaces/{id}/members/{mid}/suspend", Plane: route.Principal, Permission: "auth.members:manage", Subjects: []route.Subject{route.HumanAgent}}, a.suspendMember)
	route.Register(api, route.Spec{Name: "members.resume", Method: "POST", Path: "/v1/spaces/{id}/members/{mid}/resume", Plane: route.Principal, Permission: "auth.members:manage", Subjects: []route.Subject{route.HumanAgent}}, a.resumeMember)
	route.Register(api, route.Spec{Name: "members.remove", Method: "POST", Path: "/v1/spaces/{id}/members/{mid}/remove", Plane: route.Principal, Permission: "auth.members:manage", Subjects: []route.Subject{route.HumanAgent}}, a.removeMember)
	route.Register(api, route.Spec{Name: "members.bindings.list", Method: "GET", Path: "/v1/spaces/{id}/members/{mid}/users", Plane: route.Principal, Permission: "auth.members:read", Subjects: []route.Subject{route.HumanAgent}}, a.listBindings)
	route.Register(api, route.Spec{Name: "members.bindings.create", Method: "POST", Path: "/v1/spaces/{id}/members/{mid}/users", Plane: route.Principal, Permission: "auth.bindings:manage", Subjects: []route.Subject{route.HumanAgent}, StepUp: true, AuthoritativeCheck: true}, a.bindUser)
	route.Register(api, route.Spec{Name: "members.bindings.revoke", Method: "DELETE", Path: "/v1/spaces/{id}/members/{mid}/users/{user_id}", Plane: route.Principal, Permission: "auth.bindings:manage", Subjects: []route.Subject{route.HumanAgent}, StepUp: true}, a.unbindUser)
	route.Register(api, route.Spec{Name: "roles.list", Method: "GET", Path: "/v1/spaces/{id}/roles", Plane: route.Principal, Permission: "auth.roles:manage", Subjects: []route.Subject{route.HumanAgent}}, a.listRoles)
	route.Register(api, route.Spec{Name: "roles.create", Method: "POST", Path: "/v1/spaces/{id}/roles", Plane: route.Principal, Permission: "auth.roles:manage", Subjects: []route.Subject{route.HumanAgent}, AuthoritativeCheck: true}, a.createRole)
	route.Register(api, route.Spec{Name: "grants.create", Method: "POST", Path: "/v1/spaces/{id}/grants", Plane: route.Principal, Permission: "auth.grants:assign", Subjects: []route.Subject{route.HumanAgent}, AuthoritativeCheck: true}, a.createGrant)
	route.Register(api, route.Spec{Name: "grants.revoke", Method: "DELETE", Path: "/v1/spaces/{id}/grants/{grant_id}", Plane: route.Principal, Permission: "auth.grants:assign", Subjects: []route.Subject{route.HumanAgent}}, a.revokeGrant)
}

func (a *API) createSpace(ctx context.Context, in *createSpaceInput) (*authorizationDataOutput[createdSpaceData], error) {
	if a.Authorization == nil {
		return nil, apierr.New("UNAVAILABLE", "authorization is unavailable")
	}
	claims, err := a.authenticateHuman(ctx, in.Authorization)
	if err != nil {
		return nil, err
	}
	space, member, err := a.Authorization.CreateSpace(ctx, claims.Subject, in.Body.Name, in.Body.Slug)
	if err != nil {
		return nil, err
	}
	out := &authorizationDataOutput[createdSpaceData]{}
	out.Body.Data.Space = space
	out.Body.Data.Member = member
	return out, nil
}

func (a *API) getSpace(ctx context.Context, in *spacePathInput) (*authorizationDataOutput[authorization.Space], error) {
	actor, err := a.actorForSpace(ctx, in.Authorization, in.ID, "auth.members:read")
	if err != nil {
		return nil, err
	}
	if actor.ID == "" {
		return nil, apierr.New("PERMISSION_DENIED", "Space membership is required")
	}
	space, err := a.Authorization.GetSpace(ctx, in.ID)
	if err != nil {
		return nil, err
	}
	out := &authorizationDataOutput[authorization.Space]{}
	out.Body.Data = space
	return out, nil
}

func (a *API) listChildren(ctx context.Context, in *spacePathInput) (*authorizationDataOutput[[]authorization.Space], error) {
	if _, err := a.actorForSpace(ctx, in.Authorization, in.ID, "auth.members:read"); err != nil {
		return nil, err
	}
	children, err := a.Authorization.ListChildren(ctx, in.ID)
	if err != nil {
		return nil, err
	}
	out := &authorizationDataOutput[[]authorization.Space]{}
	out.Body.Data = children
	return out, nil
}

func (a *API) listMembers(ctx context.Context, in *spacePathInput) (*authorizationDataOutput[[]authorization.Member], error) {
	_, err := a.actorForSpace(ctx, in.Authorization, in.ID, "auth.members:read")
	if err != nil {
		return nil, err
	}
	members, err := a.Authorization.ListMembers(ctx, in.ID)
	if err != nil {
		return nil, err
	}
	out := &authorizationDataOutput[[]authorization.Member]{}
	out.Body.Data = members
	return out, nil
}

func (a *API) createMember(ctx context.Context, in *createMemberInput) (*authorizationDataOutput[authorization.Member], error) {
	actor, err := a.actorForSpace(ctx, in.Authorization, in.ID, "auth.members:manage")
	if err != nil {
		return nil, err
	}
	policy := in.Body.BindingPolicy
	if policy == "" {
		policy = "single"
	}
	kind := in.Body.Kind
	if kind == "" {
		kind = "human"
	}
	member, err := a.Authorization.CreateMember(ctx, actor.ID, in.Body.UserID, in.ID, in.Body.Name, kind, policy)
	if err != nil {
		return nil, err
	}
	out := &authorizationDataOutput[authorization.Member]{}
	out.Body.Data = member
	return out, nil
}

func (a *API) updateMember(ctx context.Context, in *memberPatchInput) (*authorizationDataOutput[acceptedData], error) {
	actor, err := a.actorForSpace(ctx, in.Authorization, in.ID, "auth.bindings:manage")
	if err != nil {
		return nil, err
	}
	if err := a.Authorization.SetBindingPolicy(ctx, actor.ID, in.ID, in.MemberID, in.Body.BindingPolicy); err != nil {
		return nil, err
	}
	return acceptedResponse(), nil
}

func (a *API) suspendMember(ctx context.Context, in *memberPathInput) (*authorizationDataOutput[acceptedData], error) {
	return a.setMemberStatus(ctx, in, "suspended")
}

func (a *API) resumeMember(ctx context.Context, in *memberPathInput) (*authorizationDataOutput[acceptedData], error) {
	return a.setMemberStatus(ctx, in, "active")
}

func (a *API) removeMember(ctx context.Context, in *memberPathInput) (*authorizationDataOutput[acceptedData], error) {
	return a.setMemberStatus(ctx, in, "removed")
}

func (a *API) setMemberStatus(ctx context.Context, in *memberPathInput, status string) (*authorizationDataOutput[acceptedData], error) {
	actor, err := a.actorForSpace(ctx, in.Authorization, in.ID, "auth.members:manage")
	if err != nil {
		return nil, err
	}
	if err := a.Authorization.SetMemberStatus(ctx, actor.ID, in.ID, in.MemberID, status); err != nil {
		return nil, err
	}
	return acceptedResponse(), nil
}

func (a *API) listBindings(ctx context.Context, in *memberPathInput) (*authorizationDataOutput[[]authorization.Binding], error) {
	if _, err := a.actorForSpace(ctx, in.Authorization, in.ID, "auth.members:read"); err != nil {
		return nil, err
	}
	if _, err := a.Authorization.GetMember(ctx, in.MemberID, in.ID); err != nil {
		return nil, err
	}
	bindings, err := a.Authorization.ListBindings(ctx, in.MemberID)
	if err != nil {
		return nil, err
	}
	out := &authorizationDataOutput[[]authorization.Binding]{}
	out.Body.Data = bindings
	return out, nil
}

func (a *API) bindUser(ctx context.Context, in *bindUserInput) (*authorizationDataOutput[acceptedData], error) {
	actor, err := a.actorForSpace(ctx, in.Authorization, in.ID, "auth.bindings:manage")
	if err != nil {
		return nil, err
	}
	if err := a.Authorization.BindUser(ctx, actor.ID, in.ID, in.MemberID, in.Body.UserID); err != nil {
		return nil, err
	}
	return acceptedResponse(), nil
}

func (a *API) unbindUser(ctx context.Context, in *unbindUserInput) (*authorizationDataOutput[acceptedData], error) {
	actor, err := a.actorForSpace(ctx, in.Authorization, in.ID, "auth.bindings:manage")
	if err != nil {
		return nil, err
	}
	if err := a.Authorization.UnbindUser(ctx, actor.ID, in.ID, in.MemberID, in.UserID); err != nil {
		return nil, err
	}
	return acceptedResponse(), nil
}

func acceptedResponse() *authorizationDataOutput[acceptedData] {
	out := &authorizationDataOutput[acceptedData]{}
	out.Body.Data.Accepted = true
	return out
}

func (a *API) listRoles(ctx context.Context, in *spacePathInput) (*authorizationDataOutput[[]authorization.Role], error) {
	_, err := a.actorForSpace(ctx, in.Authorization, in.ID, "auth.roles:manage")
	if err != nil {
		return nil, err
	}
	roles, err := a.Authorization.ListRoles(ctx, in.ID)
	if err != nil {
		return nil, err
	}
	out := &authorizationDataOutput[[]authorization.Role]{}
	out.Body.Data = roles
	return out, nil
}

func (a *API) createRole(ctx context.Context, in *createRoleInput) (*authorizationDataOutput[authorization.Role], error) {
	actor, err := a.actorForSpace(ctx, in.Authorization, in.ID, "auth.roles:manage")
	if err != nil {
		return nil, err
	}
	role, err := a.Authorization.CreateRole(ctx, actor.ID, in.ID, in.Body.Name, in.Body.Description, in.Body.Permissions)
	if err != nil {
		return nil, err
	}
	out := &authorizationDataOutput[authorization.Role]{}
	out.Body.Data = role
	return out, nil
}

func (a *API) createGrant(ctx context.Context, in *createGrantInput) (*authorizationDataOutput[authorization.Grant], error) {
	actor, err := a.actorForSpace(ctx, in.Authorization, in.ID, "auth.grants:assign")
	if err != nil {
		return nil, err
	}
	var grant authorization.Grant
	if len(in.Body.Permissions) > 0 {
		grant, err = a.Authorization.CreateInlineGrant(ctx, actor.ID, in.ID, in.Body.GranteeMemberID, in.Body.Permissions, in.Body.Scope, in.Body.AnchorSpaceID)
	} else {
		if strings.TrimSpace(in.Body.RoleID) == "" {
			return nil, apierr.New("VALIDATION_FAILED", "role_id or permissions is required")
		}
		grant, err = a.Authorization.CreateGrant(ctx, actor.ID, in.ID, in.Body.GranteeMemberID, in.Body.RoleID, in.Body.Scope, in.Body.AnchorSpaceID)
	}
	if err != nil {
		return nil, err
	}
	out := &authorizationDataOutput[authorization.Grant]{}
	out.Body.Data = grant
	return out, nil
}

func (a *API) revokeGrant(ctx context.Context, in *revokeGrantInput) (*authorizationDataOutput[acceptedData], error) {
	actor, err := a.actorForSpace(ctx, in.Authorization, in.ID, "auth.grants:assign")
	if err != nil {
		return nil, err
	}
	if err := a.Authorization.RevokeGrant(ctx, actor.ID, in.ID, in.GrantID); err != nil {
		return nil, err
	}
	out := &authorizationDataOutput[acceptedData]{}
	out.Body.Data.Accepted = true
	return out, nil
}

func (a *API) actorForSpace(ctx context.Context, authorizationHeader, spaceID, permission string) (authorization.Member, error) {
	claims, err := a.authenticatePrincipal(ctx, authorizationHeader)
	if err != nil {
		return authorization.Member{}, err
	}
	if a.Authorization == nil {
		return authorization.Member{}, apierr.New("UNAVAILABLE", "authorization is unavailable")
	}
	var member authorization.Member
	if claims.Type == "agent" {
		memberID := claims.MemberID
		if memberID == "" {
			memberID = claims.Subject
		}
		member, err = a.Authorization.GetMemberAnySpace(ctx, memberID)
	} else if claims.MemberID != "" {
		bound, boundErr := a.Authorization.UserBoundToMember(ctx, claims.Subject, claims.MemberID)
		if boundErr != nil {
			return authorization.Member{}, boundErr
		}
		if !bound {
			return authorization.Member{}, apierr.New("BINDING_REVOKED", "the current member binding is no longer active")
		}
		member, err = a.Authorization.GetMemberAnySpace(ctx, claims.MemberID)
	} else {
		member, err = a.Authorization.GetMemberForUser(ctx, claims.Subject, spaceID)
	}
	if err != nil {
		return authorization.Member{}, err
	}
	decision, _, err := a.Authorization.Check(ctx, authorization.CheckRequest{MemberID: member.ID, Permission: permission, ResourceSpace: spaceID})
	if err != nil {
		return authorization.Member{}, err
	}
	if decision.Effect != engine.Allow {
		return authorization.Member{}, &apierr.Error{Code: decision.Code, Message: "The authorization engine denied this operation.", Details: map[string]string{"permission": permission}}
	}
	return member, nil
}

func (a *API) authenticatePrincipal(ctx context.Context, authorizationHeader string) (security.Claims, error) {
	parts := strings.Fields(authorizationHeader)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
		return security.Claims{}, apierr.New("UNAUTHENTICATED", "A bearer access token is required.")
	}
	if a.Sessions == nil {
		return security.Claims{}, apierr.New("UNAVAILABLE", "authentication is unavailable")
	}
	claims, active, err := a.Sessions.Introspect(ctx, parts[1], security.DefaultApplicationAudience)
	if err != nil {
		return security.Claims{}, err
	}
	if !active || claims.Subject == "" || (claims.Type != "user" && claims.Type != "agent" && claims.Type != "access") {
		return security.Claims{}, apierr.New("UNAUTHENTICATED", "The access token is invalid.")
	}
	return claims, nil
}

func (a *API) authenticateHuman(ctx context.Context, authorizationHeader string) (security.Claims, error) {
	claims, err := a.authenticatePrincipal(ctx, authorizationHeader)
	if err != nil {
		return security.Claims{}, err
	}
	if claims.Type == "agent" {
		return security.Claims{}, apierr.New("USER_ACCOUNT_REQUIRED", "A user account is required for this operation.")
	}
	return claims, nil
}
