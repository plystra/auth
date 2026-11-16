package principal

import (
	"context"
	"time"

	"github.com/danielgtaylor/huma/v2"
	"github.com/plystra/auth/internal/apierr"
	"github.com/plystra/auth/internal/application"
	"github.com/plystra/auth/internal/route"
	"github.com/plystra/auth/internal/secret"
)

type applicationsPathInput struct {
	Authorization string `header:"Authorization"`
	ID            string `path:"id"`
}

type registerApplicationInput struct {
	Authorization string `header:"Authorization"`
	ID            string `path:"id"`
	Body          struct {
		Name                string   `json:"name" minLength:"1" maxLength:"120"`
		RedirectURIs        []string `json:"redirect_uris,omitempty" maxItems:"20"`
		ManifestPermissions []string `json:"manifest_permissions" minItems:"1" maxItems:"100"`
		Visibility          string   `json:"visibility,omitempty" enum:"private,public"`
	}
}

type updateApplicationInput struct {
	Authorization string `header:"Authorization"`
	ApplicationID string `path:"app_id"`
	Body          struct {
		Name                *string   `json:"name,omitempty" maxLength:"120"`
		RedirectURIs        *[]string `json:"redirect_uris,omitempty" maxItems:"20"`
		ManifestPermissions *[]string `json:"manifest_permissions,omitempty" maxItems:"100"`
	}
}

type installApplicationInput struct {
	Authorization string `header:"Authorization"`
	ID            string `path:"id"`
	Body          struct {
		ApplicationID string `json:"application_id"`
		Scope         string `json:"scope,omitempty" enum:"space,space_tree"`
	}
}

type installationLifecycleInput struct {
	Authorization  string `header:"Authorization"`
	ID             string `path:"id"`
	InstallationID string `path:"ins_id"`
}

type applicationKeyPathInput struct {
	Authorization string `header:"Authorization"`
	ApplicationID string `path:"app_id"`
}

type createApplicationKeyInput struct {
	Authorization string `header:"Authorization"`
	ApplicationID string `path:"app_id"`
	Body          struct {
		Name                  string                       `json:"name" minLength:"1" maxLength:"120"`
		Grants                []string                     `json:"grants" minItems:"1" maxItems:"100"`
		RestrictTo            []application.KeyRestriction `json:"restrict_to,omitempty" maxItems:"50"`
		AllowedIPCIDRs        []string                     `json:"allowed_ip_cidrs,omitempty" maxItems:"50"`
		ExpiresAt             time.Time                    `json:"expires_at"`
		AllowSubjectAssertion bool                         `json:"allow_subject_assertion,omitempty"`
	}
}

type revokeApplicationKeyInput struct {
	Authorization string `header:"Authorization"`
	ApplicationID string `path:"app_id"`
	KeyID         string `path:"key_id"`
}

type rotateApplicationKeyInput struct {
	Authorization string `header:"Authorization"`
	ApplicationID string `path:"app_id"`
	KeyID         string `path:"key_id"`
}

type applicationKeyCreation struct {
	Key    application.ManagedKey `json:"key"`
	Secret secret.String          `json:"secret"`
}

func (a *API) registerApplicationRoutes(api huma.API) {
	route.Register(api, route.NewSpec("applications.list", "GET", "/v1/spaces/{id}/applications", route.Principal, "auth.applications:manage", []route.Subject{route.HumanAgent}), a.listApplications)
	route.Register(api, route.NewSpec("applications.register", "POST", "/v1/spaces/{id}/applications", route.Principal, "auth.applications:manage", []route.Subject{route.HumanAgent}, route.WithStepUp()), a.registerApplication)
	route.Register(api, route.NewSpec("applications.update", "PATCH", "/v1/applications/{app_id}", route.Principal, "auth.applications:manage", []route.Subject{route.HumanAgent}), a.updateApplication)
	route.Register(api, route.NewSpec("installations.list", "GET", "/v1/spaces/{id}/installations", route.Principal, "auth.members:read", []route.Subject{route.HumanAgent}), a.listInstallations)
	route.Register(api, route.NewSpec("installations.create", "POST", "/v1/spaces/{id}/installations", route.Principal, "auth.applications:manage", []route.Subject{route.HumanAgent}, route.WithStepUp(), route.WithAuthoritativeCheck()), a.installApplication)
	route.Register(api, route.NewSpec("installations.approve", "PUT", "/v1/spaces/{id}/installations/{ins_id}/approvals", route.Principal, "auth.applications:manage", []route.Subject{route.HumanAgent}, route.WithAuthoritativeCheck()), a.approveInstallation)
	route.Register(api, route.NewSpec("installations.suspend", "POST", "/v1/spaces/{id}/installations/{ins_id}/suspend", route.Principal, "auth.applications:manage", []route.Subject{route.HumanAgent}), a.suspendInstallation)
	route.Register(api, route.NewSpec("installations.resume", "POST", "/v1/spaces/{id}/installations/{ins_id}/resume", route.Principal, "auth.applications:manage", []route.Subject{route.HumanAgent}, route.WithAuthoritativeCheck()), a.resumeInstallation)
	route.Register(api, route.NewSpec("installations.uninstall", "POST", "/v1/spaces/{id}/installations/{ins_id}/uninstall", route.Principal, "auth.applications:manage", []route.Subject{route.HumanAgent}), a.uninstallInstallation)
	route.Register(api, route.NewSpec("applications.keys.list", "GET", "/v1/applications/{app_id}/api-keys", route.Principal, "auth.applications:manage", []route.Subject{route.HumanAgent}), a.listApplicationKeys)
	route.Register(api, route.NewSpec("applications.keys.create", "POST", "/v1/applications/{app_id}/api-keys", route.Principal, "auth.applications:manage", []route.Subject{route.HumanAgent}, route.WithStepUp()), a.createApplicationKey)
	route.Register(api, route.NewSpec("applications.keys.rotate", "POST", "/v1/applications/{app_id}/api-keys/{key_id}/rotate", route.Principal, "auth.applications:manage", []route.Subject{route.HumanAgent}, route.WithStepUp()), a.rotateApplicationKey)
	route.Register(api, route.NewSpec("applications.keys.revoke", "POST", "/v1/applications/{app_id}/api-keys/{key_id}/revoke", route.Principal, "auth.applications:manage", []route.Subject{route.HumanAgent}), a.revokeApplicationKey)
}

func (a *API) applicationKeyActor(ctx context.Context, authorizationHeader, applicationID string) (string, context.Context, error) {
	if a.Applications == nil {
		return "", ctx, apierr.New("UNAVAILABLE", "application key management is unavailable")
	}
	if _, err := a.authenticatePrincipal(ctx, authorizationHeader); err != nil {
		return "", ctx, err
	}
	spaceID, err := a.Applications.ApplicationSpace(ctx, applicationID)
	if err != nil {
		return "", ctx, err
	}
	actor, ctx, err := a.actorForSpace(ctx, authorizationHeader, spaceID, "auth.applications:manage")
	if err != nil {
		return "", ctx, err
	}
	return actor.ID, ctx, nil
}

func (a *API) listApplicationKeys(ctx context.Context, in *applicationKeyPathInput) (*authorizationDataOutput[[]application.ManagedKey], error) {
	actorID, ctx, err := a.applicationKeyActor(ctx, in.Authorization, in.ApplicationID)
	if err != nil {
		return nil, err
	}
	keys, err := a.Applications.ListManagedKeys(ctx, actorID, in.ApplicationID)
	if err != nil {
		return nil, err
	}
	out := &authorizationDataOutput[[]application.ManagedKey]{}
	out.Body.Data = keys
	return out, nil
}

func (a *API) createApplicationKey(ctx context.Context, in *createApplicationKeyInput) (*authorizationDataOutput[applicationKeyCreation], error) {
	actorID, ctx, err := a.applicationKeyActor(ctx, in.Authorization, in.ApplicationID)
	if err != nil {
		return nil, err
	}
	request := map[string]any{
		"application_id": in.ApplicationID, "name": in.Body.Name, "grants": in.Body.Grants,
		"restrict_to": in.Body.RestrictTo, "expires_at": in.Body.ExpiresAt,
		"allow_subject_assertion": in.Body.AllowSubjectAssertion,
	}
	if len(in.Body.AllowedIPCIDRs) > 0 {
		request["allowed_ip_cidrs"] = in.Body.AllowedIPCIDRs
	}
	ctx, err = a.principalStepUpContext(ctx, in.Authorization, "applications.keys.create", request)
	if err != nil {
		return nil, err
	}
	key, raw, err := a.Applications.CreateManagedKey(ctx, actorID, in.ApplicationID, application.CreateManagedKeyInput{
		Name: in.Body.Name, Grants: in.Body.Grants, RestrictTo: in.Body.RestrictTo, AllowedIPCIDRs: in.Body.AllowedIPCIDRs,
		ExpiresAt: in.Body.ExpiresAt, AllowSubjectAssertion: in.Body.AllowSubjectAssertion,
	})
	if err != nil {
		return nil, err
	}
	out := &authorizationDataOutput[applicationKeyCreation]{}
	out.Body.Data = applicationKeyCreation{Key: key, Secret: raw}
	return out, nil
}

func (a *API) rotateApplicationKey(ctx context.Context, in *rotateApplicationKeyInput) (*authorizationDataOutput[applicationKeyCreation], error) {
	actorID, ctx, err := a.applicationKeyActor(ctx, in.Authorization, in.ApplicationID)
	if err != nil {
		return nil, err
	}
	ctx, err = a.principalStepUpContext(ctx, in.Authorization, "applications.keys.rotate", map[string]any{
		"application_id": in.ApplicationID, "key_id": in.KeyID,
	})
	if err != nil {
		return nil, err
	}
	key, raw, err := a.Applications.RotateManagedKey(ctx, actorID, in.ApplicationID, in.KeyID)
	if err != nil {
		return nil, err
	}
	out := &authorizationDataOutput[applicationKeyCreation]{}
	out.Body.Data = applicationKeyCreation{Key: key, Secret: raw}
	return out, nil
}

func (a *API) revokeApplicationKey(ctx context.Context, in *revokeApplicationKeyInput) (*authorizationDataOutput[application.ManagedKey], error) {
	actorID, ctx, err := a.applicationKeyActor(ctx, in.Authorization, in.ApplicationID)
	if err != nil {
		return nil, err
	}
	key, err := a.Applications.RevokeManagedKey(ctx, actorID, in.ApplicationID, in.KeyID)
	if err != nil {
		return nil, err
	}
	out := &authorizationDataOutput[application.ManagedKey]{}
	out.Body.Data = key
	return out, nil
}

func (a *API) listInstallations(ctx context.Context, in *applicationsPathInput) (*authorizationDataOutput[[]application.Installation], error) {
	if a.Applications == nil {
		return nil, apierr.New("UNAVAILABLE", "application installations are unavailable")
	}
	if _, _, err := a.actorForSpace(ctx, in.Authorization, in.ID, "auth.members:read"); err != nil {
		return nil, err
	}
	items, err := a.Applications.ListInstallations(ctx, in.ID)
	if err != nil {
		return nil, err
	}
	out := &authorizationDataOutput[[]application.Installation]{}
	out.Body.Data = items
	return out, nil
}

func (a *API) installApplication(ctx context.Context, in *installApplicationInput) (*authorizationDataOutput[application.Installation], error) {
	if a.Applications == nil {
		return nil, apierr.New("UNAVAILABLE", "application installation is unavailable")
	}
	scope := in.Body.Scope
	if scope == "" {
		scope = "space"
	}
	if scope != "space" && scope != "space_tree" {
		return nil, apierr.New("VALIDATION_FAILED", "installation scope is invalid")
	}
	actor, ctx, err := a.actorForSpace(ctx, in.Authorization, in.ID, "auth.applications:manage")
	if err != nil {
		return nil, err
	}
	ctx, err = a.principalStepUpContext(ctx, in.Authorization, "installations.create", map[string]any{
		"space_id": in.ID, "application_id": in.Body.ApplicationID, "scope": scope,
	})
	if err != nil {
		return nil, err
	}
	installed, err := a.Applications.Install(ctx, actor.ID, in.Body.ApplicationID, in.ID, scope)
	if err != nil {
		return nil, err
	}
	out := &authorizationDataOutput[application.Installation]{}
	out.Body.Data = installed
	return out, nil
}

func (a *API) approveInstallation(ctx context.Context, in *installationLifecycleInput) (*authorizationDataOutput[application.Installation], error) {
	if a.Applications == nil {
		return nil, apierr.New("UNAVAILABLE", "application installations are unavailable")
	}
	if _, err := a.authenticatePrincipal(ctx, in.Authorization); err != nil {
		return nil, err
	}
	spaceID, err := a.Applications.InstallationSpace(ctx, in.InstallationID)
	if err != nil {
		return nil, err
	}
	if spaceID != in.ID {
		return nil, apierr.New("NOT_FOUND", "installation was not found in this Space")
	}
	actor, ctx, err := a.actorForSpace(ctx, in.Authorization, spaceID, "auth.applications:manage")
	if err != nil {
		return nil, err
	}
	installation, err := a.Applications.ApproveInstallationManifest(ctx, actor.ID, spaceID, in.InstallationID)
	if err != nil {
		return nil, err
	}
	out := &authorizationDataOutput[application.Installation]{}
	out.Body.Data = installation
	return out, nil
}

func (a *API) suspendInstallation(ctx context.Context, in *installationLifecycleInput) (*authorizationDataOutput[application.Installation], error) {
	return a.changeInstallationStatus(ctx, in, "suspend")
}

func (a *API) resumeInstallation(ctx context.Context, in *installationLifecycleInput) (*authorizationDataOutput[application.Installation], error) {
	return a.changeInstallationStatus(ctx, in, "resume")
}

func (a *API) uninstallInstallation(ctx context.Context, in *installationLifecycleInput) (*authorizationDataOutput[application.Installation], error) {
	return a.changeInstallationStatus(ctx, in, "uninstall")
}

func (a *API) changeInstallationStatus(ctx context.Context, in *installationLifecycleInput, action string) (*authorizationDataOutput[application.Installation], error) {
	if a.Applications == nil {
		return nil, apierr.New("UNAVAILABLE", "application installations are unavailable")
	}
	if _, err := a.authenticatePrincipal(ctx, in.Authorization); err != nil {
		return nil, err
	}
	spaceID, err := a.Applications.InstallationSpace(ctx, in.InstallationID)
	if err != nil {
		return nil, err
	}
	if spaceID != in.ID {
		return nil, apierr.New("NOT_FOUND", "installation was not found in this Space")
	}
	actor, ctx, err := a.actorForSpace(ctx, in.Authorization, spaceID, "auth.applications:manage")
	if err != nil {
		return nil, err
	}
	installation, err := a.Applications.ChangeInstallationStatus(ctx, actor.ID, spaceID, in.InstallationID, action)
	if err != nil {
		return nil, err
	}
	out := &authorizationDataOutput[application.Installation]{}
	out.Body.Data = installation
	return out, nil
}

func (a *API) listApplications(ctx context.Context, in *applicationsPathInput) (*authorizationDataOutput[[]application.PublishedApplication], error) {
	if a.Applications == nil {
		return nil, apierr.New("UNAVAILABLE", "application listing is unavailable")
	}
	if _, _, err := a.actorForSpace(ctx, in.Authorization, in.ID, "auth.applications:manage"); err != nil {
		return nil, err
	}
	items, err := a.Applications.ListPublished(ctx, in.ID)
	if err != nil {
		return nil, err
	}
	out := &authorizationDataOutput[[]application.PublishedApplication]{}
	out.Body.Data = items
	return out, nil
}

func (a *API) registerApplication(ctx context.Context, in *registerApplicationInput) (*authorizationDataOutput[application.PublishedApplication], error) {
	if a.Applications == nil {
		return nil, apierr.New("UNAVAILABLE", "application registration is unavailable")
	}
	actor, ctx, err := a.actorForSpace(ctx, in.Authorization, in.ID, "auth.applications:manage")
	if err != nil {
		return nil, err
	}
	stepUpRequest := map[string]any{
		"space_id": in.ID, "name": in.Body.Name,
		"redirect_uris": in.Body.RedirectURIs, "manifest_permissions": in.Body.ManifestPermissions,
	}
	if in.Body.Visibility != "" {
		stepUpRequest["visibility"] = in.Body.Visibility
	}
	ctx, err = a.principalStepUpContext(ctx, in.Authorization, "applications.register", stepUpRequest)
	if err != nil {
		return nil, err
	}
	registered, err := a.Applications.Register(ctx, actor.ID, application.RegisterInput{
		SpaceID: in.ID, Name: in.Body.Name, RedirectURIs: in.Body.RedirectURIs,
		ManifestPermissions: in.Body.ManifestPermissions, Visibility: in.Body.Visibility,
	})
	if err != nil {
		return nil, err
	}
	out := &authorizationDataOutput[application.PublishedApplication]{}
	out.Body.Data = registered
	return out, nil
}

func (a *API) updateApplication(ctx context.Context, in *updateApplicationInput) (*authorizationDataOutput[application.PublishedApplication], error) {
	actorID, ctx, err := a.applicationKeyActor(ctx, in.Authorization, in.ApplicationID)
	if err != nil {
		return nil, err
	}
	updated, err := a.Applications.UpdatePrivate(ctx, actorID, in.ApplicationID, application.UpdateInput{
		Name: in.Body.Name, RedirectURIs: in.Body.RedirectURIs, ManifestPermissions: in.Body.ManifestPermissions,
	})
	if err != nil {
		return nil, err
	}
	out := &authorizationDataOutput[application.PublishedApplication]{}
	out.Body.Data = updated
	return out, nil
}
