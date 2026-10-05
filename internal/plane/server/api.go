package server

import (
	"context"
	"strconv"
	"strings"

	"github.com/danielgtaylor/huma/v2"
	"github.com/plystra/auth/internal/agent"
	"github.com/plystra/auth/internal/apierr"
	"github.com/plystra/auth/internal/application"
	"github.com/plystra/auth/internal/audit"
	"github.com/plystra/auth/internal/authorization"
	"github.com/plystra/auth/internal/authz/engine"
	"github.com/plystra/auth/internal/db"
	"github.com/plystra/auth/internal/ids"
	"github.com/plystra/auth/internal/member"
	"github.com/plystra/auth/internal/route"
	"github.com/plystra/auth/internal/session"
)

type API struct {
	Applications  *application.Service
	Members       *member.Service
	Authorization *authorization.Service
	Sessions      *session.Service
	Agents        *agent.Service
}

type CheckSubject struct {
	Token    string `json:"token,omitempty"`
	MemberID string `json:"member_id,omitempty"`
	UserID   string `json:"user_id,omitempty"`
	AgentID  string `json:"agent_id,omitempty"`
}

type CheckResource struct {
	Type          string `json:"type"`
	ID            string `json:"id"`
	SpaceID       string `json:"space_id,omitempty"`
	GroupID       string `json:"group_id,omitempty"`
	OwnerMemberID string `json:"owner_member_id,omitempty"`
}

type CheckBody struct {
	Subject  CheckSubject  `json:"subject"`
	Action   string        `json:"action"`
	Resource CheckResource `json:"resource"`
	// Deprecated flat fields remain accepted for one release so older SDKs can
	// migrate to the documented subject/action/resource shape without bypassing
	// the same server-side checks.
	MemberID      string `json:"member_id,omitempty"`
	Permission    string `json:"permission,omitempty"`
	ResourceSpace string `json:"resource_space,omitempty"`
	ResourceOwner string `json:"resource_owner,omitempty"`
}

type CheckInput struct {
	Authorization string `header:"Authorization"`
	Body          CheckBody
}

type CheckDecision struct {
	Decision      string `json:"decision"`
	DenyCode      string `json:"deny_code,omitempty"`
	DecisionID    string `json:"decision_id"`
	PolicyVersion string `json:"policy_version"`
}

type CheckOutput struct {
	Body struct {
		Data CheckDecision `json:"data"`
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

type resolvedSubject struct {
	ID     string
	Type   string
	Scopes []string
}

func (a *API) Register(api huma.API) {
	route.Register(api, route.Spec{Name: "authz.check", Method: "POST", Path: "/server/v1/authz/check", Plane: route.Server, Permission: "auth.authz:check", Subjects: []route.Subject{route.HumanAgent}, AuthoritativeCheck: true}, a.check)
	route.Register(api, route.Spec{Name: "tokens.introspect", Method: "POST", Path: "/server/v1/tokens/introspect", Plane: route.Server, Permission: "auth.tokens:introspect", Subjects: []route.Subject{route.HumanAgent}}, a.introspect)
}

func (a *API) check(ctx context.Context, in *CheckInput) (*CheckOutput, error) {
	if in.Body.Action == "" && in.Body.Permission != "" {
		in.Body.Action = in.Body.Permission
		if in.Body.Subject.MemberID == "" {
			in.Body.Subject.MemberID = in.Body.MemberID
		}
		if in.Body.Resource.SpaceID == "" {
			in.Body.Resource.SpaceID = in.Body.ResourceSpace
		}
		if in.Body.Resource.OwnerMemberID == "" {
			in.Body.Resource.OwnerMemberID = in.Body.ResourceOwner
		}
	}
	key, err := a.key(ctx, in.Authorization)
	if err != nil {
		return nil, err
	}
	if !contains(key.Scopes, "auth.authz:check") {
		return nil, apierr.New("PERMISSION_DENIED", "API key is not scoped for authorization checks.")
	}
	spaceID := strings.TrimSpace(in.Body.Resource.SpaceID)
	if spaceID == "" {
		spaceID = key.SpaceID
	}
	if spaceID != key.SpaceID {
		return a.writeDecision(ctx, key, in.Body, "", spaceID, engine.Decision{Effect: engine.Deny, Code: "KEY_SCOPE_EXCLUDED"})
	}
	resolved, err := a.resolveSubject(ctx, key, in.Body.Subject, spaceID)
	if err != nil {
		return nil, err
	}
	memberID := resolved.ID
	var assignments []engine.Assignment
	var policyVersion int64
	if a.Authorization != nil {
		assignments, policyVersion, err = a.Authorization.Assignments(ctx, memberID)
		if err != nil {
			return nil, err
		}
	} else if a.Members != nil {
		permissions, err := a.Members.Permissions(ctx, memberID)
		if err != nil {
			return nil, err
		}
		keys := make([]string, 0, len(permissions))
		for _, permission := range permissions {
			keys = append(keys, permission.Key)
		}
		assignments = []engine.Assignment{{MemberID: memberID, Role: "legacy", Permissions: keys, Scope: engine.Scope{Kind: "space", Anchor: spaceID}}}
	} else {
		return nil, apierr.New("UNAVAILABLE", "authorization is unavailable")
	}
	if policyVersion == 0 && a.Authorization != nil {
		policyVersion, err = a.Authorization.PolicyVersion(ctx, spaceID)
		if err != nil {
			return nil, err
		}
	}
	request := engine.Request{MemberID: memberID, PrincipalType: resolved.Type, Permission: strings.TrimSpace(in.Body.Action), ResourceSpace: spaceID,
		ResourceGroup: in.Body.Resource.GroupID, ResourceOwner: in.Body.Resource.OwnerMemberID, Assignments: assignments}
	if len(resolved.Scopes) > 0 && !contains(resolved.Scopes, request.Permission) {
		return a.writeDecisionWithVersion(ctx, key, in.Body, memberID, spaceID, engine.Decision{Effect: engine.Deny, Code: "TOKEN_SCOPE_EXCLUDED", Trace: []string{"delegated token scope excludes permission"}}, policyVersion)
	}
	if in.Body.Resource.OwnerMemberID != "" && in.Body.Resource.OwnerMemberID != memberID && a.Agents != nil {
		owned, ownerErr := a.Agents.CanManage(ctx, memberID, in.Body.Resource.OwnerMemberID)
		if ownerErr != nil {
			return nil, ownerErr
		}
		if owned {
			request.SelfOwners = []string{in.Body.Resource.OwnerMemberID}
		}
	}
	if resolved.Type == "agent" {
		request.Owner, err = a.ownerRequest(ctx, memberID, request.Permission, request.ResourceSpace, request.ResourceGroup, request.ResourceOwner, 0)
		if err != nil {
			return nil, err
		}
	}
	decision := engine.Check(request)
	return a.writeDecisionWithVersion(ctx, key, in.Body, memberID, spaceID, decision, policyVersion)
}

func (a *API) resolveSubject(ctx context.Context, key application.Key, subject CheckSubject, spaceID string) (resolvedSubject, error) {
	if subject.AgentID != "" {
		if !key.AllowSubjectAssertion || a.Agents == nil {
			return resolvedSubject{}, apierr.New("VALIDATION_FAILED", "agent subject assertions are not enabled for this API key")
		}
		if _, err := a.Agents.Owner(ctx, subject.AgentID); err != nil {
			return resolvedSubject{}, err
		}
		return resolvedSubject{ID: subject.AgentID, Type: "agent"}, nil
	}
	if subject.Token != "" {
		if strings.HasPrefix(subject.Token, "ply_ag_") && a.Agents != nil {
			credential, err := a.Agents.AuthenticateKey(ctx, subject.Token)
			if err != nil {
				return resolvedSubject{}, err
			}
			return resolvedSubject{ID: credential.MemberID, Type: "agent"}, nil
		}
		if a.Sessions == nil {
			return resolvedSubject{}, apierr.New("UNAVAILABLE", "authentication is unavailable")
		}
		claims, active, err := a.Sessions.Introspect(ctx, subject.Token, key.ClientID)
		if err != nil {
			return resolvedSubject{}, err
		}
		if !active {
			return resolvedSubject{}, apierr.New("UNAUTHENTICATED", "the subject token is invalid")
		}
		if claims.Type == "agent" {
			return resolvedSubject{ID: claims.Subject, Type: "agent", Scopes: claims.Scopes}, nil
		}
		if a.Authorization == nil {
			return resolvedSubject{}, apierr.New("UNAVAILABLE", "authorization is unavailable")
		}
		member, err := a.Authorization.GetMemberForUser(ctx, claims.Subject, spaceID)
		if err != nil {
			return resolvedSubject{}, err
		}
		if subject.MemberID != "" && subject.MemberID != member.ID {
			return resolvedSubject{}, apierr.New("SUBJECT_NOT_FOUND", "the subject token and member do not match")
		}
		return resolvedSubject{ID: member.ID, Type: member.Kind}, nil
	}
	if subject.MemberID == "" {
		return resolvedSubject{}, apierr.New("VALIDATION_FAILED", "subject.token is required")
	}
	if !key.AllowSubjectAssertion {
		return resolvedSubject{}, apierr.New("VALIDATION_FAILED", "member_id subject assertions are not enabled for this API key")
	}
	if a.Authorization == nil {
		return resolvedSubject{ID: subject.MemberID, Type: "human"}, nil
	}
	member, err := a.Authorization.GetMember(ctx, subject.MemberID, spaceID)
	if err != nil {
		return resolvedSubject{}, err
	}
	if subject.UserID != "" {
		bound, err := a.Authorization.GetMemberForUser(ctx, subject.UserID, spaceID)
		if err != nil || bound.ID != member.ID {
			return resolvedSubject{}, apierr.New("SUBJECT_NOT_FOUND", "the asserted user is not bound to this member")
		}
	}
	return resolvedSubject{ID: member.ID, Type: member.Kind}, nil
}

func (a *API) ownerRequest(ctx context.Context, memberID, permission, spaceID, groupID, resourceOwner string, depth int) (*engine.Request, error) {
	if depth >= 8 || a.Agents == nil || a.Authorization == nil {
		return nil, apierr.New("OWNER_INACTIVE", "agent owner chain is invalid")
	}
	ownerID, err := a.Agents.Owner(ctx, memberID)
	if err != nil {
		return nil, err
	}
	assignments, _, err := a.Authorization.Assignments(ctx, ownerID)
	if err != nil {
		return nil, err
	}
	owner, err := a.Authorization.GetMember(ctx, ownerID, spaceID)
	if err != nil {
		return nil, err
	}
	// Owner-envelope evaluation answers whether the owner could perform the
	// same action. Approval is a property of the acting Agent request; it must
	// not be required recursively just to establish the owner's upper bound.
	req := &engine.Request{MemberID: ownerID, PrincipalType: owner.Kind, Permission: permission, ResourceSpace: spaceID, ResourceGroup: groupID, ResourceOwner: resourceOwner, Assignments: assignments, SkipApproval: true}
	if owner.Kind == "agent" {
		req.Owner, err = a.ownerRequest(ctx, ownerID, permission, spaceID, groupID, resourceOwner, depth+1)
		if err != nil {
			return nil, err
		}
	}
	return req, nil
}

func (a *API) writeDecision(ctx context.Context, key application.Key, body CheckBody, memberID, spaceID string, decision engine.Decision) (*CheckOutput, error) {
	version := int64(0)
	if a.Authorization != nil && spaceID != "" {
		var err error
		version, err = a.Authorization.PolicyVersion(ctx, spaceID)
		if err != nil {
			return nil, err
		}
	}
	return a.writeDecisionWithVersion(ctx, key, body, memberID, spaceID, decision, version)
}

func (a *API) writeDecisionWithVersion(ctx context.Context, key application.Key, body CheckBody, memberID, spaceID string, decision engine.Decision, policyVersion int64) (*CheckOutput, error) {
	out := &CheckOutput{}
	out.Body.Data.Decision = string(decision.Effect)
	out.Body.Data.DecisionID = string(ids.New[ids.ID]("dec"))
	out.Body.Data.PolicyVersion = strconv.FormatInt(policyVersion, 10)
	if decision.Effect == engine.Deny {
		out.Body.Data.DenyCode = decision.Code
		if a.Applications != nil && a.Applications.Store != nil {
			err := a.Applications.Store.InTx(ctx, func(q *db.Queries) error {
				return audit.Write(ctx, q, "application", key.ID, "authz.check", body.Resource.ID, "deny")
			})
			if err != nil {
				return nil, err
			}
		}
	}
	return out, nil
}

func (a *API) introspect(ctx context.Context, in *IntrospectInput) (*IntrospectOutput, error) {
	key, err := a.key(ctx, in.Authorization)
	if err != nil {
		return nil, err
	}
	if !contains(key.Scopes, "auth.tokens:introspect") {
		return nil, apierr.New("PERMISSION_DENIED", "API key is not scoped for token introspection.")
	}
	if strings.TrimSpace(in.Body.Token) == "" {
		return nil, apierr.New("VALIDATION_FAILED", "token is required")
	}
	if a.Sessions == nil {
		return nil, apierr.New("UNAVAILABLE", "token introspection is unavailable")
	}
	claims, active, err := a.Sessions.Introspect(ctx, in.Body.Token, key.ClientID)
	if err != nil {
		return nil, err
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
		return application.Key{}, apierr.New("CREDENTIAL_PLANE_MISMATCH", "an application API key is required")
	}
	if a.Applications == nil {
		return application.Key{}, apierr.New("UNAVAILABLE", "application credentials are unavailable")
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
