package principal

import (
	"context"
	"strings"
	"time"

	"github.com/danielgtaylor/huma/v2"
	"github.com/plystra/auth/internal/account"
	"github.com/plystra/auth/internal/agent"
	"github.com/plystra/auth/internal/apierr"
	"github.com/plystra/auth/internal/audit"
	"github.com/plystra/auth/internal/authorization"
	"github.com/plystra/auth/internal/authz/engine"
	"github.com/plystra/auth/internal/route"
	"github.com/plystra/auth/internal/security"
)

type agentsInput struct {
	Authorization string `header:"Authorization"`
	Body          struct {
		Name      string     `json:"name"`
		ExpiresAt *time.Time `json:"expires_at,omitempty"`
		Source    string     `json:"source,omitempty"`
	}
}

type agentPathInput struct {
	Authorization string `header:"Authorization"`
	ID            string `path:"id"`
}

type agentGrantInput struct {
	Authorization string `header:"Authorization"`
	ID            string `path:"id"`
	Body          struct {
		Permissions   []string `json:"permissions"`
		Scope         string   `json:"scope,omitempty"`
		AnchorSpaceID string   `json:"anchor_space_id,omitempty"`
		AnchorGroupID string   `json:"anchor_group_id,omitempty"`
	}
}

type agentsListInput struct {
	Authorization string `header:"Authorization"`
}

type agentsListOutput struct {
	Body struct {
		Data []agent.Agent `json:"data"`
	}
}

type agentCreated struct {
	Agent      agent.Agent `json:"agent"`
	AgentKey   string      `json:"agent_key"`
	Credential string      `json:"credential_type"`
}

type agentCreatedOutput struct {
	Body struct {
		Data agentCreated `json:"data"`
	}
}

type agentSecretOutput struct {
	Body struct {
		Data struct {
			AgentKey string `json:"agent_key"`
		} `json:"data"`
	}
}

type agentAcceptedOutput struct {
	Body struct {
		Data struct {
			Accepted bool `json:"accepted"`
		} `json:"data"`
	}
}

func (a *API) registerAgentRoutes(api huma.API) {
	route.Register(api, route.NewSpec("me.agents.list", "GET", "/v1/me/agents", route.Principal, "self:read", []route.Subject{route.HumanAgent}), a.listAgents)
	route.Register(api, route.NewSpec("me.agents.create", "POST", "/v1/me/agents", route.Principal, "auth.agents:create", []route.Subject{route.HumanAgent}, route.WithStepUp(), route.WithAuthoritativeCheck()), a.createAgent)
	route.Register(api, route.NewSpec("me.agents.rotate", "POST", "/v1/me/agents/{id}/rotate", route.Principal, "auth.agents:create", []route.Subject{route.HumanAgent}, route.WithStepUp(), route.WithAuthoritativeCheck()), a.rotateAgent)
	route.Register(api, route.NewSpec("me.agents.grants.replace", "PUT", "/v1/me/agents/{id}/grants", route.Principal, "", []route.Subject{route.HumanAgent}, route.WithSystemAssignmentRight(), route.WithConditionalPermission("auth.grants:assign"), route.WithAuthoritativeCheck()), a.replaceAgentGrants)
	route.Register(api, route.NewSpec("me.agents.stop", "POST", "/v1/me/agents/{id}/stop", route.Principal, "auth.agents:create", []route.Subject{route.HumanAgent}, route.WithAuthoritativeCheck()), a.stopAgent)
	route.Register(api, route.NewSpec("me.agents.delete", "DELETE", "/v1/me/agents/{id}", route.Principal, "auth.agents:create", []route.Subject{route.HumanAgent}, route.WithAuthoritativeCheck()), a.deleteAgent)
}

func (a *API) listAgents(ctx context.Context, in *agentsListInput) (*agentsListOutput, error) {
	member, _, ctx, err := a.authorizeCurrentMember(ctx, in.Authorization, "self:read")
	if err != nil {
		return nil, err
	}
	if a.Agents == nil {
		return nil, apierr.New("UNAVAILABLE", "agent service is unavailable")
	}
	items, err := a.Agents.List(ctx, member.ID)
	if err != nil {
		return nil, err
	}
	out := &agentsListOutput{}
	out.Body.Data = items
	return out, nil
}

func (a *API) createAgent(ctx context.Context, in *agentsInput) (*agentCreatedOutput, error) {
	memberID, userID, ctx, err := a.currentMember(ctx, in.Authorization)
	if err != nil {
		return nil, err
	}
	if a.Authorization == nil || a.Agents == nil {
		return nil, apierr.New("UNAVAILABLE", "agent service is unavailable")
	}
	ctx, err = a.principalStepUpContext(ctx, in.Authorization, "me.agents.create", map[string]any{"name": in.Body.Name, "expires_at": in.Body.ExpiresAt, "source": in.Body.Source})
	if err != nil {
		return nil, err
	}
	var expires time.Time
	if in.Body.ExpiresAt != nil {
		expires = in.Body.ExpiresAt.UTC()
	}
	created, key, err := a.Agents.CreateManaged(ctx, agent.CreateInput{OwnerMemberID: memberID, CreatedByUser: userID, Name: in.Body.Name, ExpiresAt: expires, Source: in.Body.Source}, a.Authorization)
	if err != nil {
		return nil, err
	}
	out := &agentCreatedOutput{}
	out.Body.Data.Agent = created
	out.Body.Data.AgentKey = key
	out.Body.Data.Credential = "agent_key"
	return out, nil
}

func (a *API) rotateAgent(ctx context.Context, in *agentPathInput) (*agentSecretOutput, error) {
	memberID, userID, ctx, err := a.currentMember(ctx, in.Authorization)
	if err != nil {
		return nil, err
	}
	if a.Agents == nil {
		return nil, apierr.New("UNAVAILABLE", "agent service is unavailable")
	}
	ctx, err = a.principalStepUpContext(ctx, in.Authorization, "me.agents.rotate", map[string]any{"agent_id": in.ID})
	if err != nil {
		return nil, err
	}
	key, err := a.Agents.RotateManaged(ctx, memberID, userID, in.ID, a.Authorization)
	if err != nil {
		return nil, err
	}
	out := &agentSecretOutput{}
	out.Body.Data.AgentKey = key
	return out, nil
}

func (a *API) replaceAgentGrants(ctx context.Context, in *agentGrantInput) (*authorizationDataOutput[authorization.Grant], error) {
	actorID, userID, ctx, err := a.currentMember(ctx, in.Authorization)
	if err != nil {
		return nil, err
	}
	if a.Agents == nil || a.Authorization == nil {
		return nil, apierr.New("UNAVAILABLE", "agent service is unavailable")
	}
	target, err := a.Agents.Get(ctx, in.ID)
	if err != nil {
		return nil, err
	}
	ctx = authorization.WithHumanActor(ctx, actorID, userID)
	var grant authorization.Grant
	if in.Body.AnchorGroupID != "" || in.Body.Scope == "group" || in.Body.Scope == "group_tree" {
		if in.Body.AnchorSpaceID != "" {
			return nil, apierr.New("VALIDATION_FAILED", "a group grant cannot also specify anchor_space_id")
		}
		grant, err = a.Authorization.ReplaceAgentGroupGrants(ctx, actorID, target.SpaceID, target.ID, in.Body.Permissions, in.Body.Scope, in.Body.AnchorGroupID)
	} else {
		grant, err = a.Authorization.ReplaceAgentGrants(ctx, actorID, target.SpaceID, target.ID, in.Body.Permissions, in.Body.Scope, in.Body.AnchorSpaceID)
	}
	if err != nil {
		return nil, err
	}
	out := &authorizationDataOutput[authorization.Grant]{}
	out.Body.Data = grant
	return out, nil
}

func (a *API) stopAgent(ctx context.Context, in *agentPathInput) (*agentAcceptedOutput, error) {
	memberID, _, ctx, err := a.currentMember(ctx, in.Authorization)
	if err != nil {
		return nil, err
	}
	if a.Agents == nil {
		return nil, apierr.New("UNAVAILABLE", "agent service is unavailable")
	}
	if err := a.Agents.StopManaged(ctx, memberID, in.ID, a.Authorization); err != nil {
		return nil, err
	}
	return acceptedAgent(), nil
}

func (a *API) deleteAgent(ctx context.Context, in *agentPathInput) (*agentAcceptedOutput, error) {
	memberID, _, ctx, err := a.currentMember(ctx, in.Authorization)
	if err != nil {
		return nil, err
	}
	if a.Agents == nil {
		return nil, apierr.New("UNAVAILABLE", "agent service is unavailable")
	}
	if err := a.Agents.DeleteManaged(ctx, memberID, in.ID, a.Authorization); err != nil {
		return nil, err
	}
	return acceptedAgent(), nil
}

func acceptedAgent() *agentAcceptedOutput {
	out := &agentAcceptedOutput{}
	out.Body.Data.Accepted = true
	return out
}

func (a *API) currentMember(ctx context.Context, authorizationHeader string) (string, string, context.Context, error) {
	parts := strings.Fields(authorizationHeader)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
		return "", "", ctx, apierr.New("UNAUTHENTICATED", "a bearer access token is required")
	}
	claims, active, err := a.Sessions.Introspect(ctx, parts[1], security.DefaultApplicationAudience)
	if err != nil {
		return "", "", ctx, err
	}
	if !active {
		return "", "", ctx, apierr.New("UNAUTHENTICATED", "the access token is invalid")
	}
	ctx = principalAuditContext(ctx, claims)
	if claims.Type == "agent" {
		return claims.Subject, "", authorization.WithTokenScopes(ctx, claims.Subject, claims.Scopes), nil
	}
	if a.Authorization == nil {
		return "", "", ctx, apierr.New("UNAVAILABLE", "authorization is unavailable")
	}
	spaceID := claims.SpaceID
	if spaceID == "" {
		spaceID = account.DefaultSpaceID
	}
	if claims.MemberID != "" {
		member, err := a.Authorization.GetMember(ctx, claims.MemberID, spaceID)
		if err != nil {
			return "", "", ctx, err
		}
		bound, bindErr := a.Authorization.UserBoundToMember(ctx, claims.Subject, member.ID)
		if bindErr != nil {
			return "", "", ctx, bindErr
		}
		if !bound {
			return "", "", ctx, apierr.New("BINDING_REVOKED", "the current member binding is no longer active")
		}
		ctx = authorization.WithHumanActor(ctx, member.ID, claims.Subject)
		return member.ID, claims.Subject, authorization.WithTokenScopes(ctx, member.ID, claims.Scopes), nil
	}
	member, err := a.Authorization.GetMemberForUser(ctx, claims.Subject, spaceID)
	if err != nil {
		return "", "", ctx, err
	}
	ctx = authorization.WithHumanActor(ctx, member.ID, claims.Subject)
	return member.ID, claims.Subject, authorization.WithTokenScopes(ctx, member.ID, claims.Scopes), nil
}

func principalAuditContext(ctx context.Context, claims security.Claims) context.Context {
	caller := audit.Caller{CredentialType: "agent_access_token"}
	if claims.Type != "agent" {
		caller.UserID, caller.CredentialType = claims.Subject, "user_access_token"
	}
	return audit.WithCaller(ctx, caller)
}

func (a *API) authorizeCurrentMember(ctx context.Context, authorizationHeader, permission string) (authorization.Member, string, context.Context, error) {
	memberID, userID, ctx, err := a.currentMember(ctx, authorizationHeader)
	if err != nil {
		return authorization.Member{}, "", ctx, err
	}
	if a.Authorization == nil {
		return authorization.Member{}, "", ctx, apierr.New("UNAVAILABLE", "authorization is unavailable")
	}
	member, err := a.Authorization.GetMemberAnySpace(ctx, memberID)
	if err != nil {
		return authorization.Member{}, "", ctx, err
	}
	decision, _, err := a.Authorization.Check(ctx, authorization.CheckRequest{
		MemberID: member.ID, Permission: permission, ResourceSpace: member.SpaceID, ResourceOwner: member.ID,
	})
	if err != nil {
		return authorization.Member{}, "", ctx, err
	}
	if decision.Effect != engine.Allow {
		return authorization.Member{}, "", ctx, &apierr.Error{Code: decision.Code, Message: "The authorization engine denied this operation.", Details: map[string]string{"permission": permission}}
	}
	return member, userID, ctx, nil
}
