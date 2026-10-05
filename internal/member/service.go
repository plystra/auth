package member

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"
	"github.com/plystra/auth/internal/db"
	"github.com/plystra/auth/internal/ids"
	"github.com/plystra/auth/internal/store"
)

type Service struct{ Store *store.Store }
type Member struct {
	ID      string `json:"id"`
	SpaceID string `json:"space_id"`
	Name    string `json:"name"`
	Kind    string `json:"kind"`
}

func (s *Service) Create(ctx context.Context, spaceID, name, kind string) (Member, error) {
	typeName := kind
	if typeName == "user" {
		typeName = "human"
	}
	if typeName == "service" {
		typeName = "application"
	}
	row, e := s.Store.Queries().CreateMember(ctx, db.CreateMemberParams{ID: string(ids.New[ids.MemberID]("mem")), SpaceID: spaceID, Name: name, Kind: kind, Type: typeName})
	if e != nil {
		return Member{}, e
	}
	return Member{ID: row.ID, SpaceID: row.SpaceID, Name: row.Name, Kind: row.Type}, nil
}
func (s *Service) LinkUser(ctx context.Context, userID, memberID string) error {
	return s.Store.InTx(ctx, func(q *db.Queries) error {
		return q.LinkUserMember(ctx, db.LinkUserMemberParams{UserID: userID, MemberID: memberID})
	})
}
func (s *Service) ForUser(ctx context.Context, userID, spaceID string) (Member, error) {
	row, e := s.Store.Queries().GetMemberForUser(ctx, db.GetMemberForUserParams{UserID: userID, SpaceID: spaceID})
	if errors.Is(e, pgx.ErrNoRows) {
		return Member{}, errors.New("member not found")
	}
	if e != nil {
		return Member{}, e
	}
	return Member{ID: row.ID, SpaceID: row.SpaceID, Name: row.Name, Kind: row.Type}, nil
}
