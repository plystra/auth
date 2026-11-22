package enterprise

import (
	"context"
	"crypto/subtle"
	"errors"
	"slices"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/plystra/auth/internal/apierr"
	"github.com/plystra/auth/internal/authorization"
	"github.com/plystra/auth/internal/db"
	"github.com/plystra/auth/internal/secret"
)

// Provisioning locks identities before nodes and the directory. The initial
// lookup is only a hint: token, status, configurator, and target lock set are
// revalidated after all waits. A changed lock set requires a new request.
func (s *Service) withDirectoryTx(ctx context.Context, hint db.Directory, token secret.String, write bool, run func(context.Context, *db.Queries, db.Directory) error) error {
	var users []db.ListDirectoryUsersForLockRow
	if write {
		var err error
		users, err = s.Store.Queries().ListDirectoryUsersForLock(ctx, db.ListDirectoryUsersForLockParams{DirectoryID: hint.ID})
		if err != nil {
			return err
		}
	}
	return s.Store.InTx(ctx, func(q *db.Queries) error {
		if write {
			userIDs := []string{hint.ConfiguredByUserID.String}
			memberIDs := []string{hint.ConfiguredByMemberID.String}
			for _, user := range users {
				userIDs = append(userIDs, user.UserID)
				memberIDs = append(memberIDs, user.MemberID)
			}
			if err := authorization.LockProvisioningTx(ctx, q, hint.SpaceID, userIDs, memberIDs); err != nil {
				return err
			}
		}
		var row db.Directory
		var err error
		if write {
			row, err = q.LockDirectory(ctx, db.LockDirectoryParams{ID: hint.ID})
		} else {
			row, err = q.LockDirectoryForRead(ctx, db.LockDirectoryForReadParams{ID: hint.ID})
		}
		if errors.Is(err, pgx.ErrNoRows) {
			return apierr.New("unauthenticated", "SCIM directory is unavailable")
		}
		if err != nil {
			return err
		}
		if row.Status != "active" || subtle.ConstantTimeCompare(row.TokenHash, digest(strings.TrimSpace(token.Value()))) != 1 {
			return apierr.New("unauthenticated", "SCIM bearer token is invalid or revoked")
		}
		if write {
			if row.ConfiguredByMemberID != hint.ConfiguredByMemberID || row.ConfiguredByUserID != hint.ConfiguredByUserID {
				return apierr.New("conflict", "directory configurator changed; retry the request")
			}
			current, err := q.ListDirectoryUsersForLock(ctx, db.ListDirectoryUsersForLockParams{DirectoryID: row.ID})
			if err != nil {
				return err
			}
			if !slices.Equal(users, current) {
				return apierr.New("conflict", "directory identities changed; retry the request")
			}
		}
		if row.ConfiguredByUserID.Valid {
			ctx = authorization.WithHumanActor(ctx, row.ConfiguredByMemberID.String, row.ConfiguredByUserID.String)
		}
		return run(ctx, q, row)
	})
}
