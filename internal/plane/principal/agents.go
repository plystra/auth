package principal

import (
	"context"
	"strings"
	"time"

	"github.com/danielgtaylor/huma/v2"
	"github.com/plystra/auth/internal/account"
	"github.com/plystra/auth/internal/agent"
	"github.com/plystra/auth/internal/apierr"
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
	}
}

type agentsListInput struct {
	Authorization string `header:"Authorization"`
}

type agentDataOutput struct {
	Body struct {
		Data agent.Agent `json:"data"`
	}
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
	route.Register(api, route.Spec{Name: "me.agents.list", Method: "GET", Path: "/v1/me/agents", Plane: route.Principal, Permission: "self:read", Subjects: []route.Subject{route.HumanAgent}}, a.listAgents)
	route.Register(api, route.Spec{Name: "me.agents.create", Method: "POST", Path: "/v1/me/agents", Plane: route.Principal, Permission: "auth.agents:create", Subjects: []route.Subject{route.HumanAgent}, StepUp: true, AuthoritativeCheck: true}, a.createAgent)
	route.Register(api, route.Spec{Name: "me.agents.rotate", Method: "POST", Path: "/v1/me/agents/{id}/rotate", Plane: route.Principal, Permission: "auth.agents:create", Subjects: []route.Subject{route.HumanAgent}, StepUp: true}, a.rotateAgent)
	route.Register(api, route.Spec{Name: "me.agents.grants.replace", Method: "PUT", Path: "/v1/me/agents/{id}/grants", Plane: route.Principal, Permission: "auth.grants:assign", Subjects: []route.Subject{route.HumanAgent}, AuthoritativeCheck: true}, a.replaceAgentGrants)
	route.Register(api, route.Spec{Name: "me.agents.stop", Method: "POST", Path: "/v1/me/agents/{id}/stop", Plane: route.Principal, Permission: "auth.agents:create", Subjects: []route.Subject{route.HumanAgent}}, a.stopAgent)
	route.Register(api, route.Spec{Name: "me.agents.delete", Method: "DELETE", Path: "/v1/me/agents/{id}", Plane: route.Principal, Permission: "auth.agents:create", Subjects: []route.Subject{route.HumanAgent}}, a.deleteAgent)
}

func (a *API) listAgents(ctx context.Context, in *agentsListInput) (*agentsListOutput, error) {
	memberID, _, err := a.currentMember(ctx, in.Authorization)
	if err != nil {
		return nil, err
	}
	if a.Agents == nil {
		return nil, apierr.New("UNAVAILABLE", "agent service is unavailable")
	}
	items, err := a.Agents.List(ctx, memberID)
	if err != nil {
		return nil, err
	}
	out := &agentsListOutput{}
	out.Body.Data = items
	return out, nil
}

func (a *API) createAgent(ctx context.Context, in *agentsInput) (*agentCreatedOutput, error) {
	memberID, userID, err := a.currentMember(ctx, in.Authorization)
	if err != nil {
		return nil, err
	}
	if a.Authorization == nil || a.Agents == nil {
		return nil, apierr.New("UNAVAILABLE", "agent service is unavailable")
	}
	member, err := a.Authorization.GetMemberAnySpace(ctx, memberID)
	if err != nil {
		return nil, err
	}
	decision, _, err := a.Authorization.Check(ctx, authorization.CheckRequest{MemberID: memberID, Permission: "auth.agents:create", ResourceSpace: member.SpaceID, ResourceOwner: memberID})
	if err != nil {
		return nil, err
	}
	if decision.Effect != engine.Allow {
		return nil, &apierr.Error{Code: decision.Code, Message: "The authorization engine denied this operation."}
	}
	var expires time.Time
	if in.Body.ExpiresAt != nil {
		expires = in.Body.ExpiresAt.UTC()
	}
	created, key, err := a.Agents.Create(ctx, agent.CreateInput{OwnerMemberID: memberID, CreatedByUser: userID, Name: in.Body.Name, ExpiresAt: expires, Source: in.Body.Source})
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
	memberID, _, err := a.currentMember(ctx, in.Authorization)
	if err != nil {
		return nil, err
	}
	if a.Agents == nil {
		return nil, apierr.New("UNAVAILABLE", "agent service is unavailable")
	}
	if err := a.authorizeAgentAction(ctx, memberID, in.ID, "auth.agents:create"); err != nil {
		return nil, err
	}
	key, err := a.Agents.Rotate(ctx, memberID, in.ID)
	if err != nil {
		return nil, err
	}
	out := &agentSecretOutput{}
	out.Body.Data.AgentKey = key
	return out, nil
}

func (a *API) replaceAgentGrants(ctx context.Context, in *agentGrantInput) (*authorizationDataOutput[authorization.Grant], error) {
	actorID, _, err := a.currentMember(ctx, in.Authorization)
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
	canManage, err := a.Agents.CanManage(ctx, actorID, target.ID)
	if err != nil {
		return nil, err
	}
	if !canManage {
		return nil, apierr.New("PERMISSION_DENIED", "agent is outside the current member's agent tree")
	}
	grant, err := a.Authorization.CreateInlineGrant(ctx, actorID, target.SpaceID, target.ID, in.Body.Permissions, in.Body.Scope, in.Body.AnchorSpaceID)
	if err != nil {
		return nil, err
	}
	out := &authorizationDataOutput[authorization.Grant]{}
	out.Body.Data = grant
	return out, nil
}

func (a *API) stopAgent(ctx context.Context, in *agentPathInput) (*agentAcceptedOutput, error) {
	memberID, _, err := a.currentMember(ctx, in.Authorization)
	if err != nil {
		return nil, err
	}
	if a.Agents == nil {
		return nil, apierr.New("UNAVAILABLE", "agent service is unavailable")
	}
	if err := a.authorizeAgentAction(ctx, memberID, in.ID, "auth.agents:create"); err != nil {
		return nil, err
	}
	if err := a.Agents.Stop(ctx, memberID, in.ID); err != nil {
		return nil, err
	}
	return acceptedAgent(), nil
}

func (a *API) deleteAgent(ctx context.Context, in *agentPathInput) (*agentAcceptedOutput, error) {
	memberID, _, err := a.currentMember(ctx, in.Authorization)
	if err != nil {
		return nil, err
	}
	if a.Agents == nil {
		return nil, apierr.New("UNAVAILABLE", "agent service is unavailable")
	}
	if err := a.authorizeAgentAction(ctx, memberID, in.ID, "auth.agents:create"); err != nil {
		return nil, err
	}
	if err := a.Agents.Delete(ctx, memberID, in.ID); err != nil {
		return nil, err
	}
	return acceptedAgent(), nil
}

func acceptedAgent() *agentAcceptedOutput {
	out := &agentAcceptedOutput{}
	out.Body.Data.Accepted = true
	return out
}

func (a *API) authorizeAgentAction(ctx context.Context, actorID, targetID, permission string) error {
	if a.Authorization == nil || a.Agents == nil {
		return apierr.New("UNAVAILABLE", "authorization is unavailable")
	}
	member, err := a.Authorization.GetMemberAnySpace(ctx, actorID)
	if err != nil {
		return err
	}
	target, err := a.Agents.Get(ctx, targetID)
	if err != nil {
		return err
	}
	decision, _, err := a.Authorization.Check(ctx, authorization.CheckRequest{MemberID: actorID, Permission: permission, ResourceSpace: target.SpaceID, ResourceOwner: target.ID})
	if err != nil {
		return err
	}
	if decision.Effect != engine.Allow {
		return &apierr.Error{Code: decision.Code, Message: "The authorization engine denied this operation."}
	}
	canManage, err := a.Agents.CanManage(ctx, member.ID, target.ID)
	if err != nil {
		return err
	}
	if !canManage {
		return apierr.New("PERMISSION_DENIED", "agent is outside the current member's agent tree")
	}
	return nil
}

func (a *API) currentMember(ctx context.Context, authorization string) (string, string, error) {
	parts := strings.Fields(authorization)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
		return "", "", apierr.New("UNAUTHENTICATED", "a bearer access token is required")
	}
	claims, active, err := a.Sessions.Introspect(ctx, parts[1], security.DefaultApplicationAudience)
	if err != nil {
		return "", "", err
	}
	if !active {
		return "", "", apierr.New("UNAUTHENTICATED", "the access token is invalid")
	}
	if claims.Type == "agent" {
		return claims.Subject, "", nil
	}
	if a.Authorization == nil {
		return "", "", apierr.New("UNAVAILABLE", "authorization is unavailable")
	}
	spaceID := claims.SpaceID
	if spaceID == "" {
		spaceID = account.DefaultSpaceID
	}
	if claims.MemberID != "" {
		member, err := a.Authorization.GetMember(ctx, claims.MemberID, spaceID)
		if err != nil {
			return "", "", err
		}
		binding, bindErr := a.Authorization.GetMemberForUser(ctx, claims.Subject, spaceID)
		if bindErr != nil || binding.ID != member.ID {
			return "", "", apierr.New("BINDING_REVOKED", "the current member binding is no longer active")
		}
		return member.ID, claims.Subject, nil
	}
	member, err := a.Authorization.GetMemberForUser(ctx, claims.Subject, spaceID)
	if err != nil {
		return "", "", err
	}
	return member.ID, claims.Subject, nil
}
