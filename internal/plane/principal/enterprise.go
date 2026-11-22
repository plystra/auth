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
		Name          string            `json:"name"`
		Provider      string            `json:"provider"`
		Issuer        string            `json:"issuer"`
		ClientID      string            `json:"client_id"`
		ClientSecret  secret.String     `json:"client_secret"`
		RedirectURI   string            `json:"redirect_uri"`
		GroupsClaim   string            `json:"groups_claim,omitempty"`
		RoleMappings  map[string]string `json:"role_mappings,omitempty"`
		SAMLMetadata  string            `json:"saml_metadata,omitempty"`
		CoversSubtree bool              `json:"covers_subtree,omitempty"`
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

type domainsInput struct {
	Authorization string `header:"Authorization"`
	ApprovalID    string `header:"Approval-Id"`
	ID            string `path:"id"`
}

type createDomainInput struct {
	Authorization string `header:"Authorization"`
	ApprovalID    string `header:"Approval-Id"`
	ID            string `path:"id"`
	Body          struct {
		Domain        string `json:"domain"`
		ConnectionID  string `json:"connection_id,omitempty"`
		ForceSSO      bool   `json:"force_sso"`
		CoversSubtree bool   `json:"covers_subtree,omitempty"`
	}
}

type domainPathInput struct {
	Authorization string `header:"Authorization"`
	ApprovalID    string `header:"Approval-Id"`
	ID            string `path:"id"`
	DomainID      string `path:"domain_id"`
}

type domainOutput struct {
	Body struct {
		Data enterprise.Domain `json:"data"`
	}
}

type domainsOutput struct {
	Body struct {
		Data []enterprise.Domain `json:"data"`
	}
}

func (a *API) registerEnterpriseRoutes(api huma.API) {
	route.Register(api, route.NewSpec("domains.list", "GET", "/v1/spaces/{id}/domains", route.Principal, "auth.connections:manage", []route.Subject{route.HumanAgent}), a.listDomains)
	route.Register(api, route.NewSpec("domains.create", "POST", "/v1/spaces/{id}/domains", route.Principal, "auth.connections:manage", []route.Subject{route.HumanAgent}, route.WithStepUp(), route.WithAuthoritativeCheck()), a.createDomain)
	route.Register(api, route.NewSpec("domains.verify", "POST", "/v1/spaces/{id}/domains/{domain_id}/verify", route.Principal, "auth.connections:manage", []route.Subject{route.HumanAgent}, route.WithStepUp(), route.WithAuthoritativeCheck()), a.verifyDomain)
	route.Register(api, route.NewSpec("domains.delete", "DELETE", "/v1/spaces/{id}/domains/{domain_id}", route.Principal, "auth.connections:manage", []route.Subject{route.HumanAgent}, route.WithStepUp(), route.WithAuthoritativeCheck()), a.deleteDomain)
	route.Register(api, route.NewSpec("sso_connections.list", "GET", "/v1/spaces/{id}/sso-connections", route.Principal, "auth.connections:manage", []route.Subject{route.HumanAgent}), a.listSSOConnections)
	route.Register(api, route.NewSpec("sso_connections.create", "POST", "/v1/spaces/{id}/sso-connections", route.Principal, "auth.connections:manage", []route.Subject{route.HumanAgent}, route.WithStepUp(), route.WithAuthoritativeCheck()), a.createSSOConnection)
	route.Register(api, route.NewSpec("sso_connections.delete", "DELETE", "/v1/spaces/{id}/sso-connections/{conn_id}", route.Principal, "auth.connections:manage", []route.Subject{route.HumanAgent}, route.WithStepUp(), route.WithAuthoritativeCheck()), a.deleteSSOConnection)
}

func (a *API) listDomains(ctx context.Context, in *domainsInput) (*domainsOutput, error) {
	if a.Enterprise == nil {
		return nil, apierr.New("unavailable", "enterprise connection service is unavailable")
	}
	request := map[string]any{"operation": "domains.list", "space_id": in.ID}
	actor, ctx, err := a.actorForGovernanceTarget(ctx, in.Authorization, in.ApprovalID, in.ID, "", "auth.connections:manage", "domains.list", request)
	if err != nil {
		return nil, err
	}
	domains, err := a.Enterprise.ListDomains(ctx, actor.ID, in.ID)
	if err != nil {
		return nil, err
	}
	out := &domainsOutput{}
	out.Body.Data = domains
	return out, nil
}

func (a *API) createDomain(ctx context.Context, in *createDomainInput) (*domainOutput, error) {
	if a.Enterprise == nil {
		return nil, apierr.New("unavailable", "enterprise connection service is unavailable")
	}
	request := map[string]any{
		"operation": "domains.create", "space_id": in.ID, "domain": strings.TrimSpace(in.Body.Domain),
		"connection_id": strings.TrimSpace(in.Body.ConnectionID), "force_sso": in.Body.ForceSSO,
		"covers_subtree": in.Body.CoversSubtree,
	}
	actor, ctx, err := a.actorForGovernanceTarget(ctx, in.Authorization, in.ApprovalID, in.ID, "", "auth.connections:manage", "domains.create", request)
	if err != nil {
		return nil, err
	}
	ctx, err = a.principalStepUpContext(ctx, in.Authorization, "domains.create", request)
	if err != nil {
		return nil, err
	}
	domain, err := a.Enterprise.CreateDomain(ctx, actor.ID, in.ID, enterprise.DomainInput{Domain: in.Body.Domain, ConnectionID: in.Body.ConnectionID, ForceSSO: in.Body.ForceSSO, CoversSubtree: in.Body.CoversSubtree})
	if err != nil {
		return nil, err
	}
	out := &domainOutput{}
	out.Body.Data = domain
	return out, nil
}

func (a *API) verifyDomain(ctx context.Context, in *domainPathInput) (*authorizationDataOutput[acceptedData], error) {
	if a.Enterprise == nil {
		return nil, apierr.New("unavailable", "enterprise connection service is unavailable")
	}
	request := map[string]any{"operation": "domains.verify", "space_id": in.ID, "domain_id": in.DomainID}
	actor, ctx, err := a.actorForGovernanceTarget(ctx, in.Authorization, in.ApprovalID, in.ID, "", "auth.connections:manage", "domains.verify", request)
	if err != nil {
		return nil, err
	}
	ctx, err = a.principalStepUpContext(ctx, in.Authorization, "domains.verify", request)
	if err != nil {
		return nil, err
	}
	if err := a.Enterprise.VerifyDomain(ctx, actor.ID, in.ID, in.DomainID); err != nil {
		return nil, err
	}
	return acceptedResponse(), nil
}

func (a *API) deleteDomain(ctx context.Context, in *domainPathInput) (*authorizationDataOutput[acceptedData], error) {
	if a.Enterprise == nil {
		return nil, apierr.New("unavailable", "enterprise connection service is unavailable")
	}
	request := map[string]any{"operation": "domains.delete", "space_id": in.ID, "domain_id": in.DomainID}
	actor, ctx, err := a.actorForGovernanceTarget(ctx, in.Authorization, in.ApprovalID, in.ID, "", "auth.connections:manage", "domains.delete", request)
	if err != nil {
		return nil, err
	}
	ctx, err = a.principalStepUpContext(ctx, in.Authorization, "domains.delete", request)
	if err != nil {
		return nil, err
	}
	if err := a.Enterprise.DisableDomain(ctx, actor.ID, in.ID, in.DomainID); err != nil {
		return nil, err
	}
	return acceptedResponse(), nil
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
	if strings.EqualFold(strings.TrimSpace(in.Body.Provider), "oidc") && strings.TrimSpace(in.Body.ClientSecret.Value()) == "" {
		return nil, apierr.New("validation_failed", "client_secret is required")
	}
	secretDigest := sha256.Sum256([]byte(in.Body.ClientSecret.Value()))
	metadataDigest := sha256.Sum256([]byte(in.Body.SAMLMetadata))
	request := map[string]any{
		"operation": "sso_connections.create", "space_id": in.ID, "name": strings.TrimSpace(in.Body.Name),
		"provider": strings.TrimSpace(in.Body.Provider), "issuer": strings.TrimSpace(in.Body.Issuer),
		"client_id": strings.TrimSpace(in.Body.ClientID), "redirect_uri": strings.TrimSpace(in.Body.RedirectURI),
		"groups_claim": strings.TrimSpace(in.Body.GroupsClaim), "role_mappings": in.Body.RoleMappings,
		"client_secret_digest": hex.EncodeToString(secretDigest[:]), "saml_metadata_digest": hex.EncodeToString(metadataDigest[:]),
		"covers_subtree": in.Body.CoversSubtree,
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
		GroupsClaim: in.Body.GroupsClaim, RoleMappings: in.Body.RoleMappings, SAMLMetadata: in.Body.SAMLMetadata, CoversSubtree: in.Body.CoversSubtree,
	})
	if err != nil {
		return nil, err
	}
	out := &ssoConnectionOutput{}
	out.Body.Data = connection
	return out, nil
}
