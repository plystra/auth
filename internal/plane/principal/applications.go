package principal

import (
	"context"

	"github.com/danielgtaylor/huma/v2"
	"github.com/plystra/auth/internal/apierr"
	"github.com/plystra/auth/internal/application"
	"github.com/plystra/auth/internal/route"
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
	}
}

type installApplicationInput struct {
	Authorization string `header:"Authorization"`
	ID            string `path:"id"`
	Body          struct {
		ApplicationID string `json:"application_id"`
		Scope         string `json:"scope,omitempty" enum:"space"`
	}
}

func (a *API) registerApplicationRoutes(api huma.API) {
	route.Register(api, route.NewSpec("applications.list", "GET", "/v1/spaces/{id}/applications", route.Principal, "auth.applications:manage", []route.Subject{route.HumanAgent}), a.listApplications)
	route.Register(api, route.NewSpec("applications.register", "POST", "/v1/spaces/{id}/applications", route.Principal, "auth.applications:manage", []route.Subject{route.HumanAgent}, route.WithStepUp()), a.registerApplication)
	route.Register(api, route.NewSpec("installations.list", "GET", "/v1/spaces/{id}/installations", route.Principal, "auth.members:read", []route.Subject{route.HumanAgent}), a.listInstallations)
	route.Register(api, route.NewSpec("installations.create", "POST", "/v1/spaces/{id}/installations", route.Principal, "auth.applications:manage", []route.Subject{route.HumanAgent}, route.WithStepUp(), route.WithAuthoritativeCheck()), a.installApplication)
}

func (a *API) listInstallations(ctx context.Context, in *applicationsPathInput) (*authorizationDataOutput[[]application.Installation], error) {
	if a.Applications == nil {
		return nil, apierr.New("UNAVAILABLE", "application installations are unavailable")
	}
	if _, err := a.actorForSpace(ctx, in.Authorization, in.ID, "auth.members:read"); err != nil {
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
	if in.Body.Scope != "" && in.Body.Scope != "space" {
		return nil, apierr.New("VALIDATION_FAILED", "only space installations are available")
	}
	actor, err := a.actorForSpace(ctx, in.Authorization, in.ID, "auth.applications:manage")
	if err != nil {
		return nil, err
	}
	ctx, err = a.principalStepUpContext(ctx, in.Authorization, "installations.create", map[string]any{
		"space_id": in.ID, "application_id": in.Body.ApplicationID, "scope": "space",
	})
	if err != nil {
		return nil, err
	}
	installed, err := a.Applications.InstallPrivateSpace(ctx, actor.ID, in.Body.ApplicationID, in.ID)
	if err != nil {
		return nil, err
	}
	out := &authorizationDataOutput[application.Installation]{}
	out.Body.Data = installed
	return out, nil
}

func (a *API) listApplications(ctx context.Context, in *applicationsPathInput) (*authorizationDataOutput[[]application.PublishedApplication], error) {
	if a.Applications == nil {
		return nil, apierr.New("UNAVAILABLE", "application listing is unavailable")
	}
	if _, err := a.actorForSpace(ctx, in.Authorization, in.ID, "auth.applications:manage"); err != nil {
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
	actor, err := a.actorForSpace(ctx, in.Authorization, in.ID, "auth.applications:manage")
	if err != nil {
		return nil, err
	}
	ctx, err = a.principalStepUpContext(ctx, in.Authorization, "applications.register", map[string]any{
		"space_id": in.ID, "name": in.Body.Name,
		"redirect_uris": in.Body.RedirectURIs, "manifest_permissions": in.Body.ManifestPermissions,
	})
	if err != nil {
		return nil, err
	}
	registered, err := a.Applications.RegisterPrivate(ctx, actor.ID, application.RegisterInput{
		SpaceID: in.ID, Name: in.Body.Name, RedirectURIs: in.Body.RedirectURIs,
		ManifestPermissions: in.Body.ManifestPermissions,
	})
	if err != nil {
		return nil, err
	}
	out := &authorizationDataOutput[application.PublishedApplication]{}
	out.Body.Data = registered
	return out, nil
}
