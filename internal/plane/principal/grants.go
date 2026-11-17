package principal

import (
	"context"

	"github.com/plystra/auth/internal/authorization"
)

type grantListInput struct {
	Authorization string `header:"Authorization"`
	ID            string `path:"id"`
	Cursor        string `query:"cursor" maxLength:"512"`
	Limit         int    `query:"limit" default:"50" minimum:"1" maximum:"100"`
}

type grantListOutput struct {
	Body struct {
		Data       []authorization.Grant `json:"data"`
		NextCursor string                `json:"next_cursor,omitempty"`
	}
}

func (a *API) listGrants(ctx context.Context, in *grantListInput) (*grantListOutput, error) {
	actor, ctx, err := a.resolvePrincipalMember(ctx, in.Authorization, in.ID)
	if err != nil {
		return nil, err
	}
	page, err := a.Authorization.ListGrants(ctx, actor.ID, authorization.GrantQuery{SpaceID: in.ID, Cursor: in.Cursor, Limit: in.Limit})
	if err != nil {
		return nil, err
	}
	out := &grantListOutput{}
	out.Body.Data, out.Body.NextCursor = page.Grants, page.NextCursor
	return out, nil
}
