package principal

import (
	"context"
	"encoding/json"
	"strings"
	"time"

	"github.com/danielgtaylor/huma/v2"
	"github.com/plystra/auth/internal/account"
	"github.com/plystra/auth/internal/apierr"
	"github.com/plystra/auth/internal/approval"
	"github.com/plystra/auth/internal/authorization"
	"github.com/plystra/auth/internal/authz/engine"
	"github.com/plystra/auth/internal/invitation"
	"github.com/plystra/auth/internal/route"
	"github.com/plystra/auth/internal/security"
	"github.com/plystra/auth/internal/stepup"
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

type updateRoleInput struct {
	Authorization string `header:"Authorization"`
	ID            string `path:"id"`
	RoleID        string `path:"role_id"`
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
		Grantee struct {
			MemberID string `json:"member_id,omitempty"`
			GroupID  string `json:"group_id,omitempty"`
		} `json:"grantee"`
		RoleID        string   `json:"role_id,omitempty"`
		Permissions   []string `json:"permissions,omitempty"`
		Scope         string   `json:"scope,omitempty"`
		AnchorSpaceID string   `json:"anchor_space_id,omitempty"`
		AnchorGroupID string   `json:"anchor_group_id,omitempty"`
	}
}

type revokeGrantInput struct {
	Authorization string `header:"Authorization"`
	ID            string `path:"id"`
	GrantID       string `path:"grant_id"`
}

type assignmentRightsInput struct {
	Authorization string `header:"Authorization"`
	ID            string `path:"id"`
}

type assignmentRightPathInput struct {
	Authorization string `header:"Authorization"`
	ID            string `path:"id"`
	RightID       string `path:"ar_id"`
}

type createAssignmentRightInput struct {
	Authorization string `header:"Authorization"`
	ID            string `path:"id"`
	Body          struct {
		HolderMemberID string     `json:"holder_member_id"`
		Permissions    []string   `json:"permissions"`
		AnchorSpaceID  string     `json:"anchor_space_id,omitempty"`
		AnchorGroupID  string     `json:"anchor_group_id,omitempty"`
		CoversSubtree  bool       `json:"covers_subtree"`
		CanRedelegate  bool       `json:"can_redelegate"`
		ExpiresAt      *time.Time `json:"expires_at,omitempty"`
	}
}

type memberPathInput struct {
	Authorization string `header:"Authorization"`
	ID            string `path:"id"`
	MemberID      string `path:"mid"`
}

type bindUserInput struct {
	Authorization string `header:"Authorization"`
	ApprovalID    string `header:"Approval-Id"`
	ID            string `path:"id"`
	MemberID      string `path:"mid"`
	Body          struct {
		UserID string `json:"user_id"`
	}
}

type unbindUserInput struct {
	Authorization string `header:"Authorization"`
	ApprovalID    string `header:"Approval-Id"`
	ID            string `path:"id"`
	MemberID      string `path:"mid"`
	UserID        string `path:"user_id"`
}

type memberPatchInput struct {
	Authorization string `header:"Authorization"`
	ApprovalID    string `header:"Approval-Id"`
	ID            string `path:"id"`
	MemberID      string `path:"mid"`
	Body          struct {
		BindingPolicy string `json:"binding_policy"`
	}
}

type groupMemberPathInput struct {
	Authorization string `header:"Authorization"`
	ID            string `path:"id"`
	GroupID       string `path:"group_id"`
	MemberID      string `path:"mid"`
}

type groupMoveInput struct {
	Authorization string `header:"Authorization"`
	ID            string `path:"id"`
	GroupID       string `path:"group_id"`
	Body          struct {
		ParentGroupID string `json:"parent_group_id,omitempty"`
	}
}

type createGroupInput struct {
	Authorization string `header:"Authorization"`
	ID            string `path:"id"`
	Body          struct {
		Name          string `json:"name"`
		ParentGroupID string `json:"parent_group_id,omitempty"`
	}
}

type createInvitationInput struct {
	Authorization string `header:"Authorization"`
	ID            string `path:"id"`
	Body          struct {
		Email     string    `json:"email"`
		MemberID  string    `json:"member_id,omitempty"`
		ExpiresAt time.Time `json:"expires_at,omitempty"`
	}
}

type invitationResponse struct {
	ID              string    `json:"id"`
	SpaceID         string    `json:"space_id"`
	MemberID        string    `json:"member_id,omitempty"`
	EmailNormalized string    `json:"email_normalized"`
	ExpiresAt       time.Time `json:"expires_at"`
	Token           string    `json:"token"`
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
	route.Register(api, route.NewSpec("spaces.create", "POST", "/v1/spaces", route.Principal, "self:read", []route.Subject{route.HumanAgent}), a.createSpace)
	route.Register(api, route.NewSpec("spaces.get", "GET", "/v1/spaces/{id}", route.Principal, "auth.members:read", []route.Subject{route.HumanAgent}), a.getSpace)
	route.Register(api, route.NewSpec("audit_logs.list", "GET", "/v1/spaces/{id}/audit-logs", route.Principal, "auth.audit:read", []route.Subject{route.HumanAgent}), a.listAuditLogs)
	route.Register(api, route.NewSpec("spaces.children", "GET", "/v1/spaces/{id}/children", route.Principal, "auth.members:read", []route.Subject{route.HumanAgent}), a.listChildren)
	route.Register(api, route.NewSpec("members.list", "GET", "/v1/spaces/{id}/members", route.Principal, "auth.members:read", []route.Subject{route.HumanAgent}), a.listMembers)
	route.Register(api, route.NewSpec("members.create", "POST", "/v1/spaces/{id}/members", route.Principal, "auth.members:manage", []route.Subject{route.HumanAgent}, route.WithAuthoritativeCheck()), a.createMember)
	route.Register(api, route.NewSpec("members.update", "PATCH", "/v1/spaces/{id}/members/{mid}", route.Principal, "auth.bindings:manage", []route.Subject{route.HumanAgent}, route.WithAuthoritativeCheck()), a.updateMember)
	route.Register(api, route.NewSpec("members.suspend", "POST", "/v1/spaces/{id}/members/{mid}/suspend", route.Principal, "auth.members:manage", []route.Subject{route.HumanAgent}), a.suspendMember)
	route.Register(api, route.NewSpec("members.resume", "POST", "/v1/spaces/{id}/members/{mid}/resume", route.Principal, "auth.members:manage", []route.Subject{route.HumanAgent}), a.resumeMember)
	route.Register(api, route.NewSpec("members.remove", "POST", "/v1/spaces/{id}/members/{mid}/remove", route.Principal, "auth.members:manage", []route.Subject{route.HumanAgent}), a.removeMember)
	route.Register(api, route.NewSpec("members.bindings.list", "GET", "/v1/spaces/{id}/members/{mid}/users", route.Principal, "auth.members:read", []route.Subject{route.HumanAgent}), a.listBindings)
	route.Register(api, route.NewSpec("members.bindings.create", "POST", "/v1/spaces/{id}/members/{mid}/users", route.Principal, "auth.bindings:manage", []route.Subject{route.HumanAgent}, route.WithStepUp(), route.WithAuthoritativeCheck()), a.bindUser)
	route.Register(api, route.NewSpec("members.bindings.revoke", "DELETE", "/v1/spaces/{id}/members/{mid}/users/{user_id}", route.Principal, "auth.bindings:manage", []route.Subject{route.HumanAgent}, route.WithStepUp()), a.unbindUser)
	route.Register(api, route.NewSpec("roles.list", "GET", "/v1/spaces/{id}/roles", route.Principal, "auth.roles:manage", []route.Subject{route.HumanAgent}), a.listRoles)
	route.Register(api, route.NewSpec("roles.create", "POST", "/v1/spaces/{id}/roles", route.Principal, "auth.roles:manage", []route.Subject{route.HumanAgent}, route.WithAuthoritativeCheck()), a.createRole)
	route.Register(api, route.NewSpec("roles.update", "PATCH", "/v1/spaces/{id}/roles/{role_id}", route.Principal, "auth.roles:manage", []route.Subject{route.HumanAgent}, route.WithAuthoritativeCheck()), a.updateRole)
	route.Register(api, route.NewSpec("grants.create", "POST", "/v1/spaces/{id}/grants", route.Principal, "auth.grants:assign", []route.Subject{route.HumanAgent}, route.WithAuthoritativeCheck()), a.createGrant)
	route.Register(api, route.NewSpec("grants.revoke", "DELETE", "/v1/spaces/{id}/grants/{grant_id}", route.Principal, "auth.grants:assign", []route.Subject{route.HumanAgent}), a.revokeGrant)
	route.Register(api, route.NewSpec("assignment_rights.list", "GET", "/v1/spaces/{id}/assign-rights", route.Principal, "auth.assign_rights:manage", []route.Subject{route.HumanAgent}, route.WithStepUp()), a.listAssignmentRights)
	route.Register(api, route.NewSpec("assignment_rights.create", "POST", "/v1/spaces/{id}/assign-rights", route.Principal, "auth.assign_rights:manage", []route.Subject{route.HumanAgent}, route.WithStepUp(), route.WithAuthoritativeCheck()), a.createAssignmentRight)
	route.Register(api, route.NewSpec("assignment_rights.revoke", "DELETE", "/v1/spaces/{id}/assign-rights/{ar_id}", route.Principal, "auth.assign_rights:manage", []route.Subject{route.HumanAgent}, route.WithStepUp()), a.revokeAssignmentRight)
	route.Register(api, route.NewSpec("groups.create", "POST", "/v1/spaces/{id}/groups", route.Principal, "auth.groups:manage", []route.Subject{route.HumanAgent}, route.WithAuthoritativeCheck()), a.createGroup)
	route.Register(api, route.NewSpec("invitations.create", "POST", "/v1/spaces/{id}/invitations", route.Principal, "auth.members:manage", []route.Subject{route.HumanAgent}, route.WithConditionalPermission("auth.bindings:manage"), route.WithStepUp(), route.WithAuthoritativeCheck()), a.createInvitation)
	route.Register(api, route.NewSpec("groups.members.add", "PUT", "/v1/spaces/{id}/groups/{group_id}/members/{mid}", route.Principal, "auth.groups:manage", []route.Subject{route.HumanAgent}, route.WithAuthoritativeCheck()), a.addGroupMember)
	route.Register(api, route.NewSpec("groups.move", "POST", "/v1/spaces/{id}/groups/{group_id}/move", route.Principal, "auth.groups:manage", []route.Subject{route.HumanAgent}, route.WithAuthoritativeCheck()), a.moveGroup)
}

func (a *API) createSpace(ctx context.Context, in *createSpaceInput) (*authorizationDataOutput[createdSpaceData], error) {
	if a.Authorization == nil {
		return nil, apierr.New("UNAVAILABLE", "authorization is unavailable")
	}
	claims, err := a.authenticatePrincipal(ctx, in.Authorization)
	if err != nil {
		return nil, err
	}
	currentSpace := claims.SpaceID
	if currentSpace == "" && claims.MemberID == "" && claims.Type != "agent" {
		currentSpace = account.DefaultSpaceID
	}
	actor, ctx, err := a.actorForSpaceSelf(ctx, in.Authorization, currentSpace, "self:read")
	if err != nil {
		return nil, err
	}
	var space authorization.Space
	var member authorization.Member
	if claims.Type == "agent" {
		ownerUserID, ownerErr := a.Authorization.OwnerUserID(ctx, actor.ID)
		if ownerErr != nil {
			return nil, ownerErr
		}
		space, member, err = a.Authorization.CreateSpaceByAgent(ctx, actor.ID, ownerUserID, in.Body.Name, in.Body.Slug)
	} else {
		space, member, err = a.Authorization.CreateSpace(ctx, claims.Subject, in.Body.Name, in.Body.Slug)
	}
	if err != nil {
		return nil, err
	}
	out := &authorizationDataOutput[createdSpaceData]{}
	out.Body.Data.Space = space
	out.Body.Data.Member = member
	return out, nil
}

func (a *API) getSpace(ctx context.Context, in *spacePathInput) (*authorizationDataOutput[authorization.Space], error) {
	actor, ctx, err := a.actorForSpace(ctx, in.Authorization, in.ID, "auth.members:read")
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
	if _, _, err := a.actorForSpace(ctx, in.Authorization, in.ID, "auth.members:read"); err != nil {
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
	_, _, err := a.actorForSpace(ctx, in.Authorization, in.ID, "auth.members:read")
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
	actor, ctx, err := a.actorForSpace(ctx, in.Authorization, in.ID, "auth.members:manage")
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
	if in.Body.BindingPolicy != "single" && in.Body.BindingPolicy != "shared" {
		return nil, apierr.New("VALIDATION_FAILED", "binding_policy must be single or shared")
	}
	request := map[string]any{"operation": "members.update", "space_id": in.ID, "member_id": in.MemberID, "binding_policy": in.Body.BindingPolicy}
	actor, ctx, err := a.actorForGovernanceTarget(ctx, in.Authorization, in.ApprovalID, in.ID, in.MemberID, "auth.bindings:manage", "members.update", request)
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
	actor, ctx, err := a.actorForSpaceTarget(ctx, in.Authorization, in.ID, "auth.members:manage", in.MemberID)
	if err != nil {
		return nil, err
	}
	if err := a.Authorization.SetMemberStatus(ctx, actor.ID, in.ID, in.MemberID, status); err != nil {
		return nil, err
	}
	return acceptedResponse(), nil
}

func (a *API) listBindings(ctx context.Context, in *memberPathInput) (*authorizationDataOutput[[]authorization.Binding], error) {
	if _, _, err := a.actorForSpaceTarget(ctx, in.Authorization, in.ID, "auth.members:read", in.MemberID); err != nil {
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
	if in.Body.UserID == "" {
		return nil, apierr.New("VALIDATION_FAILED", "user_id is required")
	}
	request := map[string]any{"operation": "members.bindings.create", "space_id": in.ID, "member_id": in.MemberID, "user_id": in.Body.UserID}
	actor, ctx, err := a.actorForGovernanceTarget(ctx, in.Authorization, in.ApprovalID, in.ID, in.MemberID, "auth.bindings:manage", "members.bindings.create", request)
	if err != nil {
		return nil, err
	}
	ctx, err = a.principalStepUpContext(ctx, in.Authorization, "members.bindings.create", map[string]any{"space_id": in.ID, "member_id": in.MemberID, "user_id": in.Body.UserID})
	if err != nil {
		return nil, err
	}
	if err := a.Authorization.BindUser(ctx, actor.ID, in.ID, in.MemberID, in.Body.UserID); err != nil {
		return nil, err
	}
	return acceptedResponse(), nil
}

func (a *API) unbindUser(ctx context.Context, in *unbindUserInput) (*authorizationDataOutput[acceptedData], error) {
	request := map[string]any{"operation": "members.bindings.revoke", "space_id": in.ID, "member_id": in.MemberID, "user_id": in.UserID}
	actor, ctx, err := a.actorForGovernanceTarget(ctx, in.Authorization, in.ApprovalID, in.ID, in.MemberID, "auth.bindings:manage", "members.bindings.revoke", request)
	if err != nil {
		return nil, err
	}
	ctx, err = a.principalStepUpContext(ctx, in.Authorization, "members.bindings.revoke", map[string]any{"space_id": in.ID, "member_id": in.MemberID, "user_id": in.UserID})
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

func (a *API) addGroupMember(ctx context.Context, in *groupMemberPathInput) (*authorizationDataOutput[acceptedData], error) {
	actor, ctx, err := a.actorForNode(ctx, in.Authorization, in.ID, in.GroupID, "auth.groups:manage")
	if err != nil {
		return nil, err
	}
	if err := a.Authorization.AddMemberToGroup(ctx, actor.ID, in.ID, in.GroupID, in.MemberID); err != nil {
		return nil, err
	}
	return acceptedResponse(), nil
}

func (a *API) moveGroup(ctx context.Context, in *groupMoveInput) (*authorizationDataOutput[acceptedData], error) {
	actor, ctx, err := a.actorForNode(ctx, in.Authorization, in.ID, in.GroupID, "auth.groups:manage")
	if err != nil {
		return nil, err
	}
	if err := a.Authorization.MoveGroup(ctx, actor.ID, in.ID, in.GroupID, in.Body.ParentGroupID); err != nil {
		return nil, err
	}
	return acceptedResponse(), nil
}

func (a *API) listRoles(ctx context.Context, in *spacePathInput) (*authorizationDataOutput[[]authorization.Role], error) {
	_, _, err := a.actorForSpace(ctx, in.Authorization, in.ID, "auth.roles:manage")
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
	actor, ctx, err := a.actorForSpace(ctx, in.Authorization, in.ID, "auth.roles:manage")
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

func (a *API) updateRole(ctx context.Context, in *updateRoleInput) (*authorizationDataOutput[authorization.Role], error) {
	actor, ctx, err := a.actorForSpace(ctx, in.Authorization, in.ID, "auth.roles:manage")
	if err != nil {
		return nil, err
	}
	role, err := a.Authorization.UpdateRole(ctx, actor.ID, in.ID, in.RoleID, in.Body.Name, in.Body.Description, in.Body.Permissions)
	if err != nil {
		return nil, err
	}
	out := &authorizationDataOutput[authorization.Role]{}
	out.Body.Data = role
	return out, nil
}

func (a *API) createGrant(ctx context.Context, in *createGrantInput) (*authorizationDataOutput[authorization.Grant], error) {
	if (in.Body.Grantee.MemberID == "") == (in.Body.Grantee.GroupID == "") {
		return nil, apierr.New("VALIDATION_FAILED", "grantee must identify exactly one member or group")
	}
	if (in.Body.RoleID == "") == (len(in.Body.Permissions) == 0) {
		return nil, apierr.New("VALIDATION_FAILED", "provide exactly one of role_id or permissions")
	}
	if in.Body.Grantee.GroupID != "" || in.Body.AnchorGroupID != "" || in.Body.Scope == "group" || in.Body.Scope == "group_tree" {
		return nil, apierr.New("UNAVAILABLE", "group grants are not yet available")
	}
	actor, ctx, err := a.actorForSpaceTarget(ctx, in.Authorization, in.ID, "auth.grants:assign", in.Body.Grantee.MemberID)
	if err != nil {
		return nil, err
	}
	var grant authorization.Grant
	if len(in.Body.Permissions) > 0 {
		grant, err = a.Authorization.CreateInlineGrant(ctx, actor.ID, in.ID, in.Body.Grantee.MemberID, in.Body.Permissions, in.Body.Scope, in.Body.AnchorSpaceID)
	} else {
		grant, err = a.Authorization.CreateGrant(ctx, actor.ID, in.ID, in.Body.Grantee.MemberID, in.Body.RoleID, in.Body.Scope, in.Body.AnchorSpaceID)
	}
	if err != nil {
		return nil, err
	}
	out := &authorizationDataOutput[authorization.Grant]{}
	out.Body.Data = grant
	return out, nil
}

func (a *API) revokeGrant(ctx context.Context, in *revokeGrantInput) (*authorizationDataOutput[acceptedData], error) {
	// Revoke resolves the grant and its grantee inside the same transaction as
	// the authorization check. Do not pre-authorize against the whole Space,
	// because a group-scoped grant must be checked against its target group.
	actor, ctx, err := a.resolvePrincipalMember(ctx, in.Authorization, in.ID)
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

func (a *API) listAssignmentRights(ctx context.Context, in *assignmentRightsInput) (*authorizationDataOutput[[]authorization.AssignmentRight], error) {
	if _, _, err := a.actorForSpace(ctx, in.Authorization, in.ID, "auth.assign_rights:manage"); err != nil {
		return nil, err
	}
	var err error
	ctx, err = a.principalStepUpContext(ctx, in.Authorization, "assignment_rights.list", map[string]any{"space_id": in.ID})
	if err != nil {
		return nil, err
	}
	rights, err := a.Authorization.ListAssignmentRights(ctx, in.ID)
	if err != nil {
		return nil, err
	}
	out := &authorizationDataOutput[[]authorization.AssignmentRight]{}
	out.Body.Data = rights
	return out, nil
}

func (a *API) createAssignmentRight(ctx context.Context, in *createAssignmentRightInput) (*authorizationDataOutput[authorization.AssignmentRight], error) {
	resourceSpace := in.ID
	resourceGroup := in.Body.AnchorGroupID
	if in.Body.AnchorGroupID == "" && in.Body.AnchorSpaceID != "" {
		resourceSpace = in.Body.AnchorSpaceID
	}
	actor, ctx, err := a.actorForNode(ctx, in.Authorization, resourceSpace, resourceGroup, "auth.assign_rights:manage")
	if err != nil {
		return nil, err
	}
	ctx, err = a.principalStepUpContext(ctx, in.Authorization, "assignment_rights.create", map[string]any{"space_id": in.ID, "holder_member_id": in.Body.HolderMemberID, "permissions": in.Body.Permissions, "anchor_space_id": in.Body.AnchorSpaceID, "anchor_group_id": in.Body.AnchorGroupID, "covers_subtree": in.Body.CoversSubtree, "can_redelegate": in.Body.CanRedelegate, "expires_at": in.Body.ExpiresAt})
	if err != nil {
		return nil, err
	}
	right, err := a.Authorization.CreateAssignmentRight(ctx, actor.ID, in.ID, in.Body.HolderMemberID, in.Body.Permissions, in.Body.AnchorSpaceID, in.Body.AnchorGroupID, in.Body.CoversSubtree, in.Body.CanRedelegate, in.Body.ExpiresAt)
	if err != nil {
		return nil, err
	}
	out := &authorizationDataOutput[authorization.AssignmentRight]{}
	out.Body.Data = right
	return out, nil
}

func (a *API) revokeAssignmentRight(ctx context.Context, in *assignmentRightPathInput) (*authorizationDataOutput[acceptedData], error) {
	actor, ctx, err := a.resolvePrincipalMember(ctx, in.Authorization, in.ID)
	if err != nil {
		return nil, err
	}
	ctx, err = a.principalStepUpContext(ctx, in.Authorization, "assignment_rights.revoke", map[string]any{"space_id": in.ID, "assignment_right_id": in.RightID})
	if err != nil {
		return nil, err
	}
	if err := a.Authorization.RevokeAssignmentRight(ctx, actor.ID, in.ID, in.RightID); err != nil {
		return nil, err
	}
	return acceptedResponse(), nil
}

func (a *API) createGroup(ctx context.Context, in *createGroupInput) (*authorizationDataOutput[authorization.Group], error) {
	parentGroupID := strings.TrimSpace(in.Body.ParentGroupID)
	actor, ctx, err := a.actorForNode(ctx, in.Authorization, in.ID, parentGroupID, "auth.groups:manage")
	if err != nil {
		return nil, err
	}
	group, err := a.Authorization.CreateGroup(ctx, actor.ID, in.ID, in.Body.Name, parentGroupID)
	if err != nil {
		return nil, err
	}
	out := &authorizationDataOutput[authorization.Group]{}
	out.Body.Data = group
	return out, nil
}

func (a *API) createInvitation(ctx context.Context, in *createInvitationInput) (*authorizationDataOutput[invitationResponse], error) {
	if a.Invitations == nil {
		return nil, apierr.New("UNAVAILABLE", "invitation service is unavailable")
	}
	memberID := strings.TrimSpace(in.Body.MemberID)
	var actor authorization.Member
	var err error
	inviterUserID := ""
	if memberID == "" {
		actor, ctx, err = a.actorForSpace(ctx, in.Authorization, in.ID, "auth.members:manage")
	} else {
		var claims security.Claims
		claims, err = a.authenticatePrincipal(ctx, in.Authorization)
		if err == nil && claims.Type != "user" {
			return nil, apierr.New("USER_ACCOUNT_REQUIRED", "binding invitations require a user account")
		}
		if err == nil {
			inviterUserID = claims.Subject
			actor, ctx, err = a.actorForSpaceTarget(ctx, in.Authorization, in.ID, "auth.bindings:manage", memberID)
		}
		if err == nil {
			ctx, err = a.principalStepUpContext(ctx, in.Authorization, "invitations.create", map[string]any{
				"space_id": in.ID, "email": in.Body.Email, "member_id": memberID, "expires_at": in.Body.ExpiresAt,
			})
		}
	}
	if err != nil {
		return nil, err
	}
	created, token, err := a.Invitations.CreateForActor(ctx, "member", actor.ID, invitation.CreateInput{
		SpaceID: in.ID, Email: in.Body.Email, MemberID: memberID, InviterUserID: inviterUserID, ExpiresAt: in.Body.ExpiresAt,
	})
	if err != nil {
		return nil, err
	}
	out := &authorizationDataOutput[invitationResponse]{}
	out.Body.Data = invitationResponse{ID: created.ID, SpaceID: created.SpaceID, MemberID: created.MemberID, EmailNormalized: created.EmailNormalized, ExpiresAt: created.ExpiresAt, Token: token}
	return out, nil
}

func (a *API) actorForSpace(ctx context.Context, authorizationHeader, spaceID, permission string) (authorization.Member, context.Context, error) {
	return a.actorForSpaceTarget(ctx, authorizationHeader, spaceID, permission, "")
}

func (a *API) actorForGovernanceTarget(ctx context.Context, authorizationHeader, approvalID, spaceID, targetMemberID, permission, operation string, request any) (authorization.Member, context.Context, error) {
	claims, err := a.authenticatePrincipal(ctx, authorizationHeader)
	if err != nil {
		return authorization.Member{}, ctx, err
	}
	member, err := a.resolvePrincipalMemberClaims(ctx, claims, spaceID)
	if err != nil {
		return authorization.Member{}, ctx, err
	}
	resourceGroup, err := a.Authorization.ResourceGroupForMember(ctx, targetMemberID, spaceID)
	if err != nil {
		return authorization.Member{}, ctx, err
	}
	ctx = authorization.WithTokenScopes(ctx, member.ID, claims.Scopes)
	decision, _, err := a.Authorization.Check(ctx, authorization.CheckRequest{
		MemberID: member.ID, Permission: permission, ResourceSpace: spaceID, ResourceGroup: resourceGroup,
	})
	if err != nil {
		return authorization.Member{}, ctx, err
	}
	if decision.Effect == engine.Allow {
		return member, ctx, nil
	}
	denied := &apierr.Error{Code: decision.Code, Message: "The authorization engine denied this operation.", Details: map[string]string{"permission": permission}}
	if decision.Code != "APPROVAL_REQUIRED" || claims.Type != "agent" || a.Approvals == nil {
		return authorization.Member{}, ctx, denied
	}
	digest, err := stepup.DigestValue(request)
	if err != nil {
		return authorization.Member{}, ctx, err
	}
	if approvalID != "" {
		return member, authorization.WithGovernanceApproval(ctx, approvalID, operation, targetMemberID, digest), nil
	}
	details, err := json.Marshal(request)
	if err != nil {
		return authorization.Member{}, ctx, err
	}
	created, err := a.Approvals.CreateGovernance(ctx, approval.GovernanceInput{
		AgentMemberID: member.ID, Permission: permission, Operation: operation,
		SpaceID: spaceID, TargetMemberID: targetMemberID, ResourceGroup: resourceGroup,
		RequestDigest: digest, RequestDetails: details,
	})
	if err != nil {
		return authorization.Member{}, ctx, err
	}
	return authorization.Member{}, ctx, &apierr.Error{
		Code: "APPROVAL_REQUIRED", Message: "Human approval is required before this operation can run.",
		Details: map[string]string{"permission": permission, "approval_id": created.ID},
	}
}

func (a *API) actorForSpaceSelf(ctx context.Context, authorizationHeader, spaceID, permission string) (authorization.Member, context.Context, error) {
	return a.actorForSpaceTargetWithSelf(ctx, authorizationHeader, spaceID, permission, "", true)
}

func (a *API) actorForSpaceTarget(ctx context.Context, authorizationHeader, spaceID, permission, targetMemberID string) (authorization.Member, context.Context, error) {
	return a.actorForSpaceTargetWithSelf(ctx, authorizationHeader, spaceID, permission, targetMemberID, false)
}

func (a *API) actorForNode(ctx context.Context, authorizationHeader, spaceID, groupID, permission string) (authorization.Member, context.Context, error) {
	member, ctx, err := a.resolvePrincipalMember(ctx, authorizationHeader, spaceID)
	if err != nil {
		return authorization.Member{}, ctx, err
	}
	decision, _, err := a.Authorization.Check(ctx, authorization.CheckRequest{MemberID: member.ID, Permission: permission, ResourceSpace: spaceID, ResourceGroup: groupID})
	if err != nil {
		return authorization.Member{}, ctx, err
	}
	if decision.Effect != engine.Allow {
		return authorization.Member{}, ctx, &apierr.Error{Code: decision.Code, Message: "The authorization engine denied this operation.", Details: map[string]string{"permission": permission}}
	}
	return member, ctx, nil
}

func (a *API) actorForSpaceTargetWithSelf(ctx context.Context, authorizationHeader, spaceID, permission, targetMemberID string, self bool) (authorization.Member, context.Context, error) {
	claims, err := a.authenticatePrincipal(ctx, authorizationHeader)
	if err != nil {
		return authorization.Member{}, ctx, err
	}
	member, err := a.resolvePrincipalMemberClaims(ctx, claims, spaceID)
	if err != nil {
		return authorization.Member{}, ctx, err
	}
	ctx = authorization.WithTokenScopes(ctx, member.ID, claims.Scopes)
	resourceGroup := ""
	if targetMemberID != "" {
		resourceGroup, err = a.Authorization.ResourceGroupForMember(ctx, targetMemberID, spaceID)
		if err != nil {
			return authorization.Member{}, ctx, err
		}
	}
	resourceOwner := ""
	if self {
		resourceOwner = member.ID
	}
	decision, _, err := a.Authorization.Check(ctx, authorization.CheckRequest{MemberID: member.ID, Permission: permission, ResourceSpace: spaceID, ResourceGroup: resourceGroup, ResourceOwner: resourceOwner})
	if err != nil {
		return authorization.Member{}, ctx, err
	}
	if decision.Effect != engine.Allow {
		return authorization.Member{}, ctx, &apierr.Error{Code: decision.Code, Message: "The authorization engine denied this operation.", Details: map[string]string{"permission": permission}}
	}
	return member, ctx, nil
}

func (a *API) resolvePrincipalMember(ctx context.Context, authorizationHeader, spaceID string) (authorization.Member, context.Context, error) {
	claims, err := a.authenticatePrincipal(ctx, authorizationHeader)
	if err != nil {
		return authorization.Member{}, ctx, err
	}
	member, err := a.resolvePrincipalMemberClaims(ctx, claims, spaceID)
	if err != nil {
		return authorization.Member{}, ctx, err
	}
	return member, authorization.WithTokenScopes(ctx, member.ID, claims.Scopes), nil
}

func (a *API) resolvePrincipalMemberClaims(ctx context.Context, claims security.Claims, spaceID string) (authorization.Member, error) {
	if a.Authorization == nil {
		return authorization.Member{}, apierr.New("UNAVAILABLE", "authorization is unavailable")
	}
	var member authorization.Member
	var err error
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
