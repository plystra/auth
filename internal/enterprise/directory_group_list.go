package enterprise

import (
	"context"
	"errors"
	"strconv"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/oklog/ulid/v2"
	"github.com/plystra/auth/internal/apierr"
	"github.com/plystra/auth/internal/db"
)

const DirectoryGroupListOperation = "directory_groups.list"

type DirectoryGroupMapping struct {
	ID          string `json:"id"`
	GroupID     string `json:"group_id"`
	DisplayName string `json:"display_name"`
}

type DirectoryGroupPage struct {
	Data       []DirectoryGroupMapping `json:"data"`
	NextCursor string                  `json:"next_cursor,omitempty"`
}

type DirectoryGroupList struct {
	SpaceID     string
	DirectoryID string
	Cursor      string
	Limit       int
}

func (in DirectoryGroupList) Request() map[string]string {
	return map[string]string{
		"operation": DirectoryGroupListOperation, "space_id": in.SpaceID, "directory_id": in.DirectoryID,
		"cursor": in.Cursor, "limit": strconv.Itoa(in.pageLimit()),
	}
}

func (in DirectoryGroupList) pageLimit() int {
	if in.Limit == 0 {
		return 50
	}
	return in.Limit
}

func (s *Service) ListDirectoryGroups(ctx context.Context, actorID string, in DirectoryGroupList) (DirectoryGroupPage, error) {
	limit := in.pageLimit()
	if limit < 1 || limit > 100 {
		return DirectoryGroupPage{}, apierr.New("VALIDATION_FAILED", "limit must be between 1 and 100")
	}
	if in.Cursor != "" {
		suffix, prefixed := strings.CutPrefix(in.Cursor, "dgrp_")
		id, err := ulid.ParseStrict(suffix)
		if !prefixed || err != nil || suffix != id.String() {
			return DirectoryGroupPage{}, apierr.New("VALIDATION_FAILED", "cursor must be a directory group ID")
		}
	}
	page := DirectoryGroupPage{Data: []DirectoryGroupMapping{}}
	err := s.Store.InTx(ctx, func(q *db.Queries) error {
		if err := s.authorizeSettingsTx(ctx, q, actorID, in.Request()); err != nil {
			return err
		}
		directory, err := q.LockDirectoryForRead(ctx, db.LockDirectoryForReadParams{ID: in.DirectoryID})
		if errors.Is(err, pgx.ErrNoRows) || err == nil && (directory.Status != "active" || directory.SpaceID != in.SpaceID) {
			return apierr.New("NOT_FOUND", "the active directory was not found")
		}
		if err != nil {
			return err
		}
		rows, err := q.ListDirectoryGroupMappings(ctx, db.ListDirectoryGroupMappingsParams{
			SpaceID: in.SpaceID, DirectoryID: in.DirectoryID, AfterID: in.Cursor, LimitCount: int32(limit + 1),
		})
		if err != nil {
			return err
		}
		if len(rows) > limit {
			rows = rows[:limit]
			page.NextCursor = rows[limit-1].ID
		}
		for _, row := range rows {
			page.Data = append(page.Data, DirectoryGroupMapping{ID: row.ID, GroupID: row.GroupID, DisplayName: row.DisplayName})
		}
		return nil
	})
	if err != nil {
		return DirectoryGroupPage{}, normalizeConnectionError(err)
	}
	return page, nil
}
