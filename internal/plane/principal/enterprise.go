package principal

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"strings"

	"github.com/danielgtaylor/huma/v2"

	"github.com/plystra/auth/internal/apierr"
	"github.com/plystra/auth/internal/enterprise"
	"github.com/plystra/auth/internal/route"
	"github.com/plystra/auth/internal/secret"
)

type ssoConnectionsInput struct {
	Authorization string `header:"Authorization"`
	ApprovalID    string `header:"Approval-Id"`
	ID            string `path:"id"`
}

type createSSOConnectionInput struct {
	Authorization string `header:"Authorization"`
	ApprovalID    string `header:"Approval-Id"`
	ID            string `path:"id"`
	Body          struct {
		Name         string            `json:"name"`
		Provider     string            `json:"provider"`
		Issuer       string            `json:"issuer"`
		ClientID     string            `json:"client_id"`
		ClientSecret secret.String     `json:"client_secret"`
		RedirectURI  string            `json:"redirect_uri"`
		GroupsClaim  string            `json:"groups_claim,omitempty"`
		RoleMappings map[string]string `json:"role_mappings,omitempty"`
	}
}

type ssoConnectionPathInput struct {
	Authorization string `header:"Authorization"`
	ApprovalID    string `header:"Approval-Id"`
	ID            string `path:"id"`
	ConnectionID  string `path:"conn_id"`
}

type ssoConnectionOutput struct {
	Body struct {
		Data enterprise.Connection `json:"data"`
	}
}

type ssoConnectionsOutput struct {
	Body struct {
		Data []enterprise.Connection `json:"data"`
	}
}

func (a *API) registerEnterpriseRoutes(api huma.API) {
	route.Register(api, route.NewSpec("sso_connections.list", "GET", "/v1/spaces/{id}/sso-connections", route.Principal, "auth.connections:manage", []route.Subject{route.HumanAgent}), a.listSSOConnections)
	route.Register(api, route.NewSpec("sso_connections.create", "POST", "/v1/spaces/{id}/sso-connections", route.Principal, "auth.connections:manage", []route.Subject{route.HumanAgent}, route.WithStepUp(), route.WithAuthoritativeCheck()), a.createSSOConnection)
	route.Register(api, route.NewSpec("sso_connections.delete", "DELETE", "/v1/spaces/{id}/sso-connections/{conn_id}", route.Principal, "auth.connections:manage", []route.Subject{route.HumanAgent}, route.WithStepUp(), route.WithAuthoritativeCheck()), a.deleteSSOConnection)
}

func (a *API) deleteSSOConnection(ctx context.Context, in *ssoConnectionPathInput) (*authorizationDataOutput[acceptedData], error) {
	if a.Enterprise == nil {
		return nil, apierr.New("unavailable", "enterprise connection service is unavailable")
	}
	request := map[string]any{"operation": "sso_connections.delete", "space_id": in.ID, "connection_id": in.ConnectionID}
	actor, ctx, err := a.actorForGovernanceTarget(ctx, in.Authorization, in.ApprovalID, in.ID, "", "auth.connections:manage", "sso_connections.delete", request)
	if err != nil {
		return nil, err
	}
	ctx, err = a.principalStepUpContext(ctx, in.Authorization, "sso_connections.delete", request)
	if err != nil {
		return nil, err
	}
	if err := a.Enterprise.DisableConnection(ctx, actor.ID, in.ID, in.ConnectionID); err != nil {
		return nil, err
	}
	return acceptedResponse(), nil
}

func (a *API) listSSOConnections(ctx context.Context, in *ssoConnectionsInput) (*ssoConnectionsOutput, error) {
	if a.Enterprise == nil {
		return nil, apierr.New("unavailable", "enterprise connection service is unavailable")
	}
	request := map[string]any{"operation": "sso_connections.list", "space_id": in.ID}
	actor, ctx, err := a.actorForGovernanceTarget(ctx, in.Authorization, in.ApprovalID, in.ID, "", "auth.connections:manage", "sso_connections.list", request)
	if err != nil {
		return nil, err
	}
	connections, err := a.Enterprise.ListConnections(ctx, actor.ID, in.ID)
	if err != nil {
		return nil, err
	}
	out := &ssoConnectionsOutput{}
	out.Body.Data = connections
	return out, nil
}

func (a *API) createSSOConnection(ctx context.Context, in *createSSOConnectionInput) (*ssoConnectionOutput, error) {
	if a.Enterprise == nil {
		return nil, apierr.New("unavailable", "enterprise connection service is unavailable")
	}
	if strings.TrimSpace(in.Body.ClientSecret.Value()) == "" {
		return nil, apierr.New("validation_failed", "client_secret is required")
	}
	secretDigest := sha256.Sum256([]byte(in.Body.ClientSecret.Value()))
	request := map[string]any{
		"operation": "sso_connections.create", "space_id": in.ID, "name": strings.TrimSpace(in.Body.Name),
		"provider": strings.TrimSpace(in.Body.Provider), "issuer": strings.TrimSpace(in.Body.Issuer),
		"client_id": strings.TrimSpace(in.Body.ClientID), "redirect_uri": strings.TrimSpace(in.Body.RedirectURI),
		"groups_claim": strings.TrimSpace(in.Body.GroupsClaim), "role_mappings": in.Body.RoleMappings,
		"client_secret_digest": hex.EncodeToString(secretDigest[:]),
	}
	actor, ctx, err := a.actorForGovernanceTarget(ctx, in.Authorization, in.ApprovalID, in.ID, "", "auth.connections:manage", "sso_connections.create", request)
	if err != nil {
		return nil, err
	}
	ctx, err = a.principalStepUpContext(ctx, in.Authorization, "sso_connections.create", request)
	if err != nil {
		return nil, err
	}
	connection, err := a.Enterprise.CreateConnection(ctx, actor.ID, in.ID, enterprise.ConnectionInput{
		Name: in.Body.Name, Provider: in.Body.Provider, Issuer: in.Body.Issuer, ClientID: in.Body.ClientID,
		ClientSecret: in.Body.ClientSecret.Value(), RedirectURI: in.Body.RedirectURI,
		GroupsClaim: in.Body.GroupsClaim, RoleMappings: in.Body.RoleMappings,
	})
	if err != nil {
		return nil, err
	}
	out := &ssoConnectionOutput{}
	out.Body.Data = connection
	return out, nil
}
