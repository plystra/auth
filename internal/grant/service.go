package grant

import (
	"context"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/plystra/auth/internal/db"
	"github.com/plystra/auth/internal/ids"
	"github.com/plystra/auth/internal/store"
)

type Service struct{ Store *store.Store }

func (s *Service) EnsurePermission(ctx context.Context, key, description string) (string, error) {
	row, e := s.Store.Queries().CreatePermission(ctx, db.CreatePermissionParams{ID: string(ids.New[ids.PermissionID]("prm")), Key: key, Description: description})
	return row.ID, e
}
func (s *Service) CreateRole(ctx context.Context, spaceID, name, description string, managed bool) (string, error) {
	row, e := s.Store.Queries().CreateRole(ctx, db.CreateRoleParams{ID: string(ids.New[ids.RoleID]("rol")), SpaceID: spaceID, Name: name, Description: description, Managed: managed})
	return row.ID, e
}
func (s *Service) Grant(ctx context.Context, roleID, permissionID string) error {
	return s.Store.InTx(ctx, func(q *db.Queries) error {
		return q.GrantRolePermission(ctx, db.GrantRolePermissionParams{RoleID: roleID, PermissionID: permissionID})
	})
}
func (s *Service) Assign(ctx context.Context, memberID, roleID, grantedBy string) error {
	return s.Store.InTx(ctx, func(q *db.Queries) error {
		return q.AssignRole(ctx, db.AssignRoleParams{MemberID: memberID, RoleID: roleID, GrantedBy: pgtype.Text{String: grantedBy, Valid: grantedBy != ""}})
	})
}
