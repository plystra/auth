package server

import (
	"context"
	"time"

	"github.com/plystra/auth/internal/application"
)

type keyIdentityInput struct {
	Authorization string `header:"Authorization"`
}

type keyIdentity struct {
	ID                    string                       `json:"id"`
	ApplicationID         string                       `json:"application_id"`
	ClientID              string                       `json:"client_id"`
	SpaceID               string                       `json:"space_id"`
	Name                  string                       `json:"name"`
	Prefix                string                       `json:"prefix"`
	Grants                []string                     `json:"grants"`
	RestrictTo            []application.KeyRestriction `json:"restrict_to"`
	AllowedIPCIDRs        []string                     `json:"allowed_ip_cidrs"`
	AllowSubjectAssertion bool                         `json:"allow_subject_assertion"`
	ExpiresAt             time.Time                    `json:"expires_at"`
	CreatedAt             time.Time                    `json:"created_at"`
}

type keyIdentityOutput struct {
	CacheControl string `header:"Cache-Control"`
	Body         struct {
		Data keyIdentity `json:"data"`
	}
}

type keyInstallationsInput struct {
	Authorization string `header:"Authorization"`
	Cursor        string `query:"cursor" maxLength:"512"`
	Limit         int    `query:"limit" default:"50" minimum:"1" maximum:"100"`
}

type keyInstallationsOutput struct {
	CacheControl string `header:"Cache-Control"`
	Body         struct {
		Data       []application.Installation `json:"data"`
		NextCursor string                     `json:"next_cursor,omitempty"`
	}
}

func (a *API) whoami(ctx context.Context, in *keyIdentityInput) (*keyIdentityOutput, error) {
	key, err := a.key(ctx, in.Authorization)
	if err != nil {
		return nil, err
	}
	out := &keyIdentityOutput{CacheControl: "no-store"}
	out.Body.Data = keyIdentity{
		ID: key.ID, ApplicationID: key.ApplicationID, ClientID: key.ClientID, SpaceID: key.SpaceID,
		Name: key.Name, Prefix: key.Prefix, Grants: key.Scopes, RestrictTo: key.RestrictTo,
		AllowedIPCIDRs: key.AllowedIPCIDRs, AllowSubjectAssertion: key.AllowSubjectAssertion,
		ExpiresAt: key.ExpiresAt, CreatedAt: key.CreatedAt,
	}
	return out, nil
}

func (a *API) listKeyInstallations(ctx context.Context, in *keyInstallationsInput) (*keyInstallationsOutput, error) {
	key, err := a.key(ctx, in.Authorization)
	if err != nil {
		return nil, err
	}
	page, err := a.Applications.ListKeyInstallations(ctx, key, in.Cursor, in.Limit)
	if err != nil {
		return nil, err
	}
	out := &keyInstallationsOutput{CacheControl: "no-store"}
	out.Body.Data, out.Body.NextCursor = page.Installations, page.NextCursor
	return out, nil
}
