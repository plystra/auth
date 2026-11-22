package principal

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"strconv"
	"strings"

	"github.com/danielgtaylor/huma/v2"

	"github.com/plystra/auth/internal/apierr"
	"github.com/plystra/auth/internal/enterprise"
	"github.com/plystra/auth/internal/route"
	"github.com/plystra/auth/internal/secret"
)

type enterpriseSettingsListInput struct {
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

type createDirectoryInput struct {
	Authorization string `header:"Authorization"`
	ApprovalID    string `header:"Approval-Id"`
	ID            string `path:"id"`
	Body          struct {
		Name             string  `json:"name"`
		SSOConnectionID  *string `json:"sso_connection_id,omitempty"`
		SSOIdentityClaim *string `json:"sso_identity_claim,omitempty"`
	}
}

type directoryPathInput struct {
	Authorization string `header:"Authorization"`
	ApprovalID    string `header:"Approval-Id"`
	IfMatch       string `header:"If-Match"`
	ID            string `path:"id"`
	DirectoryID   string `path:"dir_id"`
	Body          struct {
		Name             string  `json:"name,omitempty"`
		RotateToken      bool    `json:"rotate_token,omitempty"`
		SSOConnectionID  *string `json:"sso_connection_id,omitempty"`
		SSOIdentityClaim *string `json:"sso_identity_claim,omitempty"`
	}
}

type deleteDirectoryInput struct {
	Authorization string `header:"Authorization"`
	ApprovalID    string `header:"Approval-Id"`
	IfMatch       string `header:"If-Match"`
	ID            string `path:"id"`
	DirectoryID   string `path:"dir_id"`
}

type directoryOutput struct {
	Body struct {
		Data enterprise.Directory `json:"data"`
	}
}

type directoriesOutput struct {
	Body struct {
		Data []enterprise.Directory `json:"data"`
	}
}

func (a *API) registerEnterpriseRoutes(api huma.API) {
	route.Register(api, route.NewSpec("directories.list", "GET", "/v1/spaces/{id}/directories", route.Principal, "auth.connections:manage", []route.Subject{route.HumanAgent}, route.WithStepUp(), route.WithAuthoritativeCheck()), a.listDirectories)
	route.Register(api, route.NewSpec("directories.create", "POST", "/v1/spaces/{id}/directories", route.Principal, "auth.connections:manage", []route.Subject{route.HumanAgent}, route.WithStepUp(), route.WithAuthoritativeCheck()), a.createDirectory)
	route.Register(api, route.NewSpec("directories.update", "PATCH", "/v1/spaces/{id}/directories/{dir_id}", route.Principal, "auth.connections:manage", []route.Subject{route.HumanAgent}, route.WithStepUp(), route.WithAuthoritativeCheck()), a.updateDirectory)
	route.Register(api, route.NewSpec("directories.delete", "DELETE", "/v1/spaces/{id}/directories/{dir_id}", route.Principal, "auth.connections:manage", []route.Subject{route.HumanAgent}, route.WithStepUp(), route.WithAuthoritativeCheck()), a.deleteDirectory)
	route.Register(api, route.NewSpec("domains.list", "GET", "/v1/spaces/{id}/domains", route.Principal, "auth.connections:manage", []route.Subject{route.HumanAgent}, route.WithStepUp(), route.WithAuthoritativeCheck()), a.listDomains)
	route.Register(api, route.NewSpec("domains.create", "POST", "/v1/spaces/{id}/domains", route.Principal, "auth.connections:manage", []route.Subject{route.HumanAgent}, route.WithStepUp(), route.WithAuthoritativeCheck()), a.createDomain)
	route.Register(api, route.NewSpec("domains.verify", "POST", "/v1/spaces/{id}/domains/{domain_id}/verify", route.Principal, "auth.connections:manage", []route.Subject{route.HumanAgent}, route.WithStepUp(), route.WithAuthoritativeCheck()), a.verifyDomain)
	route.Register(api, route.NewSpec("domains.delete", "DELETE", "/v1/spaces/{id}/domains/{domain_id}", route.Principal, "auth.connections:manage", []route.Subject{route.HumanAgent}, route.WithStepUp(), route.WithAuthoritativeCheck()), a.deleteDomain)
	route.Register(api, route.NewSpec("sso_connections.list", "GET", "/v1/spaces/{id}/sso-connections", route.Principal, "auth.connections:manage", []route.Subject{route.HumanAgent}, route.WithStepUp(), route.WithAuthoritativeCheck()), a.listSSOConnections)
	route.Register(api, route.NewSpec("sso_connections.get", "GET", "/v1/spaces/{id}/sso-connections/{conn_id}", route.Principal, "auth.connections:manage", []route.Subject{route.HumanAgent}, route.WithStepUp(), route.WithAuthoritativeCheck()), a.getSSOConnection)
	route.Register(api, route.NewSpec("sso_connections.create", "POST", "/v1/spaces/{id}/sso-connections", route.Principal, "auth.connections:manage", []route.Subject{route.HumanAgent}, route.WithStepUp(), route.WithAuthoritativeCheck()), a.createSSOConnection)
	route.Register(api, route.NewSpec("sso_connections.delete", "DELETE", "/v1/spaces/{id}/sso-connections/{conn_id}", route.Principal, "auth.connections:manage", []route.Subject{route.HumanAgent}, route.WithStepUp(), route.WithAuthoritativeCheck()), a.deleteSSOConnection)
}

func (a *API) enterpriseSettingsListActor(ctx context.Context, in *enterpriseSettingsListInput, operation string) (string, context.Context, error) {
	request := enterprise.SettingsListRequest(operation, in.ID)
	actor, ctx, err := a.actorForGovernanceTarget(ctx, in.Authorization, in.ApprovalID, in.ID, "", "auth.connections:manage", operation, request)
	if err != nil {
		return "", ctx, err
	}
	ctx, err = a.principalStepUpContext(ctx, in.Authorization, operation, request)
	return actor.ID, ctx, err
}

func (a *API) listDirectories(ctx context.Context, in *enterpriseSettingsListInput) (*directoriesOutput, error) {
	if a.Enterprise == nil {
		return nil, apierr.New("unavailable", "enterprise directory service is unavailable")
	}
	actorID, ctx, err := a.enterpriseSettingsListActor(ctx, in, "directories.list")
	if err != nil {
		return nil, err
	}
	directories, err := a.Enterprise.ListDirectories(ctx, actorID, in.ID)
	if err != nil {
		return nil, err
	}
	out := &directoriesOutput{}
	out.Body.Data = directories
	return out, nil
}

func (a *API) createDirectory(ctx context.Context, in *createDirectoryInput) (*directoryOutput, error) {
	if a.Enterprise == nil {
		return nil, apierr.New("unavailable", "enterprise directory service is unavailable")
	}
	if (in.Body.SSOConnectionID == nil) != (in.Body.SSOIdentityClaim == nil) {
		return nil, apierr.New("validation_failed", "sso_connection_id and sso_identity_claim must be provided together")
	}
	request := map[string]any{"operation": "directories.create", "space_id": in.ID, "name": strings.TrimSpace(in.Body.Name),
		"sso_connection_id": in.Body.SSOConnectionID, "sso_identity_claim": in.Body.SSOIdentityClaim}
	actor, ctx, err := a.actorForGovernanceTarget(ctx, in.Authorization, in.ApprovalID, in.ID, "", "auth.connections:manage", "directories.create", request)
	if err != nil {
		return nil, err
	}
	ctx, err = a.principalStepUpContext(ctx, in.Authorization, "directories.create", request)
	if err != nil {
		return nil, err
	}
	input := enterprise.DirectoryInput{Name: in.Body.Name}
	if in.Body.SSOConnectionID != nil {
		input.SSOConnectionID, input.SSOIdentityClaim = *in.Body.SSOConnectionID, *in.Body.SSOIdentityClaim
		if input.SSOConnectionID == "" || input.SSOIdentityClaim == "" {
			return nil, apierr.New("validation_failed", "directory creation requires nonempty SSO configuration when provided")
		}
	}
	directory, err := a.Enterprise.CreateDirectory(ctx, actor.ID, in.ID, input)
	if err != nil {
		return nil, err
	}
	out := &directoryOutput{}
	out.Body.Data = directory
	return out, nil
}

func (a *API) updateDirectory(ctx context.Context, in *directoryPathInput) (*directoryOutput, error) {
	if a.Enterprise == nil {
		return nil, apierr.New("unavailable", "enterprise directory service is unavailable")
	}
	version, err := parseDirectoryIfMatch(in.IfMatch)
	if err != nil {
		return nil, err
	}
	if in.Body.RotateToken && (in.Body.Name != "" || in.Body.SSOConnectionID != nil || in.Body.SSOIdentityClaim != nil) {
		return nil, apierr.New("validation_failed", "token rotation cannot be combined with configuration changes")
	}
	request := map[string]any{"operation": "directories.update", "space_id": in.ID, "directory_id": in.DirectoryID, "version": version, "name": strings.TrimSpace(in.Body.Name), "rotate_token": in.Body.RotateToken,
		"sso_connection_id": in.Body.SSOConnectionID, "sso_identity_claim": in.Body.SSOIdentityClaim}
	actor, ctx, err := a.actorForGovernanceTarget(ctx, in.Authorization, in.ApprovalID, in.ID, "", "auth.connections:manage", "directories.update", request)
	if err != nil {
		return nil, err
	}
	ctx, err = a.principalStepUpContext(ctx, in.Authorization, "directories.update", request)
	if err != nil {
		return nil, err
	}
	var directory enterprise.Directory
	if in.Body.RotateToken {
		directory, err = a.Enterprise.RotateDirectoryToken(ctx, actor.ID, in.ID, in.DirectoryID, version)
	} else {
		directory, err = a.Enterprise.UpdateDirectory(ctx, actor.ID, in.ID, in.DirectoryID, enterprise.DirectoryUpdate{Name: in.Body.Name,
			SSOConnectionID: in.Body.SSOConnectionID, SSOIdentityClaim: in.Body.SSOIdentityClaim}, version)
	}
	if err != nil {
		return nil, err
	}
	out := &directoryOutput{}
	out.Body.Data = directory
	return out, nil
}

func (a *API) deleteDirectory(ctx context.Context, in *deleteDirectoryInput) (*authorizationDataOutput[acceptedData], error) {
	if a.Enterprise == nil {
		return nil, apierr.New("unavailable", "enterprise directory service is unavailable")
	}
	version, err := parseDirectoryIfMatch(in.IfMatch)
	if err != nil {
		return nil, err
	}
	request := map[string]any{"operation": "directories.delete", "space_id": in.ID, "directory_id": in.DirectoryID, "version": version}
	actor, ctx, err := a.actorForGovernanceTarget(ctx, in.Authorization, in.ApprovalID, in.ID, "", "auth.connections:manage", "directories.delete", request)
	if err != nil {
		return nil, err
	}
	ctx, err = a.principalStepUpContext(ctx, in.Authorization, "directories.delete", request)
	if err != nil {
		return nil, err
	}
	if err := a.Enterprise.DisableDirectory(ctx, actor.ID, in.ID, in.DirectoryID, version); err != nil {
		return nil, err
	}
	return acceptedResponse(), nil
}

func parseDirectoryIfMatch(raw string) (int64, error) {
	raw = strings.TrimSpace(raw)
	if !strings.HasPrefix(raw, `W/"`) || !strings.HasSuffix(raw, `"`) {
		return 0, apierr.New("precondition_failed", "If-Match must contain the directory version")
	}
	value := strings.TrimSuffix(strings.TrimPrefix(raw, `W/"`), `"`)
	version, err := strconv.ParseInt(value, 10, 64)
	if err != nil || version < 1 {
		return 0, apierr.New("precondition_failed", "If-Match must contain the directory version")
	}
	return version, nil
}

func (a *API) listDomains(ctx context.Context, in *enterpriseSettingsListInput) (*domainsOutput, error) {
	if a.Enterprise == nil {
		return nil, apierr.New("unavailable", "enterprise connection service is unavailable")
	}
	actorID, ctx, err := a.enterpriseSettingsListActor(ctx, in, "domains.list")
	if err != nil {
		return nil, err
	}
	domains, err := a.Enterprise.ListDomains(ctx, actorID, in.ID)
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

func (a *API) getSSOConnection(ctx context.Context, in *ssoConnectionPathInput) (*ssoConnectionOutput, error) {
	if a.Enterprise == nil {
		return nil, apierr.New("unavailable", "enterprise connection service is unavailable")
	}
	request := enterprise.ConnectionDetailRequest(in.ID, in.ConnectionID)
	actor, ctx, err := a.actorForGovernanceTarget(ctx, in.Authorization, in.ApprovalID, in.ID, "", "auth.connections:manage", "sso_connections.get", request)
	if err != nil {
		return nil, err
	}
	ctx, err = a.principalStepUpContext(ctx, in.Authorization, "sso_connections.get", request)
	if err != nil {
		return nil, err
	}
	connection, err := a.Enterprise.GetConnection(ctx, actor.ID, in.ID, in.ConnectionID)
	if err != nil {
		return nil, err
	}
	out := &ssoConnectionOutput{}
	out.Body.Data = connection
	return out, nil
}

func (a *API) listSSOConnections(ctx context.Context, in *enterpriseSettingsListInput) (*ssoConnectionsOutput, error) {
	if a.Enterprise == nil {
		return nil, apierr.New("unavailable", "enterprise connection service is unavailable")
	}
	actorID, ctx, err := a.enterpriseSettingsListActor(ctx, in, "sso_connections.list")
	if err != nil {
		return nil, err
	}
	connections, err := a.Enterprise.ListConnections(ctx, actorID, in.ID)
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
