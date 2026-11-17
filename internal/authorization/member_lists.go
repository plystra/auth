package authorization

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/plystra/auth/internal/apierr"
	"github.com/plystra/auth/internal/db"
)

func (s *Service) ListMembers(ctx context.Context, actorMemberID, spaceID, memberType string) ([]Member, error) {
	if memberType != "" && memberType != "human" && memberType != "agent" && memberType != "application" {
		return nil, apierr.New("VALIDATION_FAILED", "type must be human, agent or application")
	}
	out := make([]Member, 0)
	err := s.Store.InTx(ctx, func(q *db.Queries) error {
		if err := lockAuthorizationActorTx(ctx, q, actorMemberID); err != nil {
			return err
		}
		if err := s.authorizeTx(ctx, q, actorMemberID, "auth.members:read", spaceID); err != nil {
			return err
		}
		rows, err := q.ListMembersInSpace(ctx, db.ListMembersInSpaceParams{SpaceID: spaceID, MemberType: pgtype.Text{String: memberType, Valid: memberType != ""}})
		if err != nil {
			return err
		}
		for _, row := range rows {
			out = append(out, Member{ID: row.ID, SpaceID: row.SpaceID, Name: row.Name, Kind: row.Type, BindingPolicy: row.BindingPolicy, Status: row.Status})
		}
		return nil
	})
	return out, err
}

func (s *Service) ListGroupMembers(ctx context.Context, actorMemberID, spaceID, groupID string) ([]Member, error) {
	out := make([]Member, 0)
	err := s.Store.InTx(ctx, func(q *db.Queries) error {
		if err := lockAuthorizationActorTx(ctx, q, actorMemberID); err != nil {
			return err
		}
		if err := lockAuthorizationNodesTx(ctx, q, spaceID, groupID); err != nil {
			return err
		}
		if _, err := q.GetGroupInSpace(ctx, db.GetGroupInSpaceParams{ID: groupID, SpaceID: spaceID}); errors.Is(err, pgx.ErrNoRows) {
			return apierr.New("NOT_FOUND", "group was not found in this Space")
		} else if err != nil {
			return err
		}
		if err := s.authorizeGroupTx(ctx, q, actorMemberID, "auth.groups:manage", spaceID, groupID); err != nil {
			return err
		}
		rows, err := q.ListGroupMembers(ctx, db.ListGroupMembersParams{SpaceID: spaceID, GroupID: groupID})
		if err != nil {
			return err
		}
		for _, row := range rows {
			out = append(out, Member{ID: row.ID, SpaceID: row.SpaceID, Name: row.Name, Kind: row.Type, BindingPolicy: row.BindingPolicy, Status: row.Status})
		}
		return nil
	})
	return out, err
}
