package authorization

import (
	"context"
	"encoding/json"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/plystra/auth/internal/db"
	"github.com/plystra/auth/internal/ids"
)

// A new top-level Space has the default envelope: active delegable permissions
// may be assigned and delegated. Creating the Space and this right share a
// transaction, so the creator never observes a Space without its right.
func createTopLevelCreatorRightTx(ctx context.Context, q *db.Queries, memberID, spaceID string) (string, error) {
	permissions, err := q.ListDefaultAssignablePermissionKeys(ctx)
	if err != nil {
		return "", err
	}
	if len(permissions) == 0 {
		return "", nil
	}
	encoded, err := json.Marshal(permissions)
	if err != nil {
		return "", err
	}
	id := string(ids.New[ids.AssignRightID]("ar"))
	_, err = q.CreateAssignRight(ctx, db.CreateAssignRightParams{
		ID: id, HolderMemberID: memberID, PermissionKeys: encoded,
		AnchorSpaceID: pgtype.Text{String: spaceID, Valid: true},
		CoversSubtree: true, CanRedelegate: true, Source: "system",
	})
	if err != nil {
		return "", err
	}
	return id, nil
}
