package principal

import (
	"context"

	"github.com/plystra/auth/internal/authorization"
)

type membersListInput struct {
	Authorization string `header:"Authorization"`
	ID            string `path:"id"`
	Type          string `query:"type" enum:"human,agent,application"`
}

type groupMembersListInput struct {
	Authorization string `header:"Authorization"`
	ID            string `path:"id"`
	GroupID       string `path:"group_id"`
}

func (a *API) listMembers(ctx context.Context, in *membersListInput) (*authorizationDataOutput[[]authorization.Member], error) {
	actor, ctx, err := a.resolvePrincipalMember(ctx, in.Authorization, in.ID)
	if err != nil {
		return nil, err
	}
	members, err := a.Authorization.ListMembers(ctx, actor.ID, in.ID, in.Type)
	if err != nil {
		return nil, err
	}
	out := &authorizationDataOutput[[]authorization.Member]{}
	out.Body.Data = members
	return out, nil
}

func (a *API) listGroupMembers(ctx context.Context, in *groupMembersListInput) (*authorizationDataOutput[[]authorization.Member], error) {
	actor, ctx, err := a.resolvePrincipalMember(ctx, in.Authorization, in.ID)
	if err != nil {
		return nil, err
	}
	members, err := a.Authorization.ListGroupMembers(ctx, actor.ID, in.ID, in.GroupID)
	if err != nil {
		return nil, err
	}
	out := &authorizationDataOutput[[]authorization.Member]{}
	out.Body.Data = members
	return out, nil
}
