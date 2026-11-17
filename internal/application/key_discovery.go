package application

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"strings"

	"github.com/plystra/auth/internal/apierr"
	"github.com/plystra/auth/internal/db"
	"github.com/plystra/auth/internal/ids"
)

type KeyInstallationPage struct {
	Installations []Installation
	NextCursor    string
}

// ListKeyInstallations lists installation roots, not every Space covered by a
// space_tree installation. Filtering happens before pagination, using the same
// active-Space and descendant restriction rules as ResolveKeyInstallation.
func (s *Service) ListKeyInstallations(ctx context.Context, key Key, cursor string, limit int) (KeyInstallationPage, error) {
	if s == nil || s.Store == nil {
		return KeyInstallationPage{}, apierr.New("UNAVAILABLE", "application installations are unavailable")
	}
	if limit == 0 {
		limit = 50
	}
	if limit < 1 || limit > 100 || len(cursor) > 512 {
		return KeyInstallationPage{}, apierr.New("VALIDATION_FAILED", "limit must be between 1 and 100 and cursor must be valid")
	}
	afterID := ""
	if cursor != "" {
		raw, err := base64.RawURLEncoding.Strict().DecodeString(cursor)
		parts := strings.Split(string(raw), "\n")
		if err != nil || len(parts) != 3 || parts[0] != key.ID || parts[1] != key.ApplicationID || !ids.InstallationID(parts[2]).Valid() {
			return KeyInstallationPage{}, apierr.New("VALIDATION_FAILED", "installation cursor is invalid for this key")
		}
		afterID = parts[2]
	}
	restrictions := key.RestrictTo
	if restrictions == nil {
		restrictions = []KeyRestriction{}
	}
	restrictJSON, err := json.Marshal(restrictions)
	if err != nil {
		return KeyInstallationPage{}, err
	}
	rows, err := s.Store.Queries().ListKeyInstallations(ctx, db.ListKeyInstallationsParams{
		ApplicationID: key.ApplicationID, RestrictTo: restrictJSON, AfterID: afterID, LimitCount: int32(limit + 1),
	})
	if err != nil {
		return KeyInstallationPage{}, err
	}
	page := KeyInstallationPage{Installations: make([]Installation, 0, min(len(rows), limit))}
	if len(rows) > limit {
		rows = rows[:limit]
		page.NextCursor = base64.RawURLEncoding.EncodeToString([]byte(key.ID + "\n" + key.ApplicationID + "\n" + rows[len(rows)-1].ID))
	}
	for _, row := range rows {
		var permissions []string
		if err := json.Unmarshal(row.ApprovedPermissions, &permissions); err != nil {
			return KeyInstallationPage{}, err
		}
		page.Installations = append(page.Installations, Installation{
			ID: row.ID, ApplicationID: row.ApplicationID, ApplicationName: row.ApplicationName,
			SpaceID: row.SpaceID, MemberID: row.MemberID, Scope: row.Scope, AnchorGroupID: row.AnchorGroupID.String,
			ApprovedPermissions: permissions, Status: row.Status, CreatedAt: row.CreatedAt.Time,
		})
	}
	return page, nil
}
