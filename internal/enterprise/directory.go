package enterprise

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/plystra/auth/internal/apierr"
	"github.com/plystra/auth/internal/audit"
	"github.com/plystra/auth/internal/authorization"
	"github.com/plystra/auth/internal/db"
	"github.com/plystra/auth/internal/ids"
	"github.com/plystra/auth/internal/secret"
)

type DirectoryInput struct {
	Name             string
	SSOConnectionID  string
	SSOIdentityClaim string
}

type DirectoryUpdate struct {
	Name             string
	SSOConnectionID  *string
	SSOIdentityClaim *string
}

type Directory struct {
	ID               string        `json:"id"`
	SpaceID          string        `json:"space_id"`
	Name             string        `json:"name"`
	Token            secret.String `json:"token,omitempty"`
	Status           string        `json:"status"`
	Version          int64         `json:"version"`
	CreatedAt        time.Time     `json:"created_at"`
	UpdatedAt        time.Time     `json:"updated_at"`
	SSOConnectionID  string        `json:"sso_connection_id,omitempty"`
	SSOIdentityClaim string        `json:"sso_identity_claim,omitempty"`
}

func (s *Service) CreateDirectory(ctx context.Context, actorMemberID, spaceID string, in DirectoryInput) (Directory, error) {
	name := strings.TrimSpace(in.Name)
	if name == "" || len(name) > 128 {
		return Directory{}, apierr.New("validation_failed", "directory name is invalid")
	}
	token, err := randomOpaque("dir_tok")
	if err != nil {
		return Directory{}, err
	}
	var out Directory
	err = s.Store.InTx(ctx, func(q *db.Queries) error {
		if err := s.checkConnectionManagement(ctx, q, actorMemberID, spaceID); err != nil {
			return err
		}
		if _, err := q.GetSpace(ctx, db.GetSpaceParams{ID: spaceID}); err != nil {
			return err
		}
		if err := validateDirectorySSOTx(ctx, q, spaceID, in.SSOConnectionID, in.SSOIdentityClaim); err != nil {
			return err
		}
		if err := s.consumeStepUp(ctx, q); err != nil {
			return err
		}
		row, err := q.CreateDirectory(ctx, db.CreateDirectoryParams{
			ID: string(ids.New[ids.ID]("dir")), SpaceID: spaceID, Name: name,
			TokenPrefix: directoryTokenPrefix(token), TokenHash: digest(token),
			ConfiguredByMemberID: pgtype.Text{String: actorMemberID, Valid: true}, ConfiguredByUserID: actorUserID(ctx, actorMemberID),
			SsoConnectionID: optionalDirectoryText(in.SSOConnectionID), SsoIdentityClaim: optionalDirectoryText(in.SSOIdentityClaim),
		})
		if err != nil {
			return err
		}
		out = directoryFromRow(row)
		out.Token = secret.New(token)
		return audit.WriteSecurityEvent(ctx, q, audit.SecurityEvent{
			ActorType: "member", ActorID: actorMemberID, MemberID: actorMemberID,
			Action: "directory.create", Outcome: "success", Permission: "auth.connections:manage",
			Resource: audit.Resource{Type: "directory", ID: out.ID, SpaceID: spaceID},
			Metadata: map[string]string{"token_prefix": directoryTokenPrefix(token)},
		})
	})
	if err != nil {
		return Directory{}, normalizeConnectionError(err)
	}
	return out, nil
}

func (s *Service) ListDirectories(ctx context.Context, actorMemberID, spaceID string) ([]Directory, error) {
	var rows []db.ListDirectoriesRow
	err := s.Store.InTx(ctx, func(q *db.Queries) error {
		if err := s.authorizeSettingsTx(ctx, q, actorMemberID, SettingsListRequest("directories.list", spaceID)); err != nil {
			return err
		}
		var err error
		rows, err = q.ListDirectories(ctx, db.ListDirectoriesParams{SpaceID: spaceID})
		return err
	})
	if err != nil {
		return nil, normalizeConnectionError(err)
	}
	out := make([]Directory, 0, len(rows))
	for _, row := range rows {
		out = append(out, directoryFromListRow(row))
	}
	return out, nil
}

func (s *Service) RotateDirectoryToken(ctx context.Context, actorMemberID, spaceID, directoryID string, version int64) (Directory, error) {
	token, err := randomOpaque("dir_tok")
	if err != nil {
		return Directory{}, err
	}
	var out Directory
	err = s.Store.InTx(ctx, func(q *db.Queries) error {
		if err := s.checkConnectionManagement(ctx, q, actorMemberID, spaceID); err != nil {
			return err
		}
		row, err := q.LockDirectory(ctx, db.LockDirectoryParams{ID: strings.TrimSpace(directoryID)})
		if errors.Is(err, pgx.ErrNoRows) || err == nil && row.SpaceID != spaceID {
			return apierr.New("not_found", "directory was not found")
		}
		if err != nil {
			return err
		}
		if row.Status != "active" {
			return apierr.New("forbidden", "directory is disabled")
		}
		if row.Version != version {
			return apierr.New("precondition_failed", "directory version does not match")
		}
		if err := s.consumeStepUp(ctx, q); err != nil {
			return err
		}
		updated, err := q.RotateDirectoryToken(ctx, db.RotateDirectoryTokenParams{
			ID: row.ID, Version: row.Version, TokenPrefix: directoryTokenPrefix(token), TokenHash: digest(token),
			ConfiguredByMemberID: pgtype.Text{String: actorMemberID, Valid: true}, ConfiguredByUserID: actorUserID(ctx, actorMemberID),
		})
		if err != nil {
			return err
		}
		out = directoryFromRow(updated)
		out.Token = secret.New(token)
		return audit.WriteSecurityEvent(ctx, q, audit.SecurityEvent{
			ActorType: "member", ActorID: actorMemberID, MemberID: actorMemberID,
			Action: "directory.token.rotate", Outcome: "success", Permission: "auth.connections:manage",
			Resource: audit.Resource{Type: "directory", ID: row.ID, SpaceID: spaceID},
			Metadata: map[string]string{"token_prefix": directoryTokenPrefix(token)},
		})
	})
	if err != nil {
		return Directory{}, normalizeConnectionError(err)
	}
	return out, nil
}

func (s *Service) UpdateDirectory(ctx context.Context, actorMemberID, spaceID, directoryID string, in DirectoryUpdate, version int64) (Directory, error) {
	name := strings.TrimSpace(in.Name)
	if len(name) > 128 || name == "" && in.SSOConnectionID == nil && in.SSOIdentityClaim == nil {
		return Directory{}, apierr.New("validation_failed", "directory name is invalid")
	}
	if (in.SSOConnectionID == nil) != (in.SSOIdentityClaim == nil) {
		return Directory{}, apierr.New("validation_failed", "sso_connection_id and sso_identity_claim must be provided together")
	}
	var out Directory
	err := s.Store.InTx(ctx, func(q *db.Queries) error {
		if err := s.checkConnectionManagement(ctx, q, actorMemberID, spaceID); err != nil {
			return err
		}
		row, err := q.LockDirectory(ctx, db.LockDirectoryParams{ID: strings.TrimSpace(directoryID)})
		if errors.Is(err, pgx.ErrNoRows) || err == nil && row.SpaceID != spaceID {
			return apierr.New("not_found", "directory was not found")
		}
		if err != nil {
			return err
		}
		if row.Status != "active" {
			return apierr.New("forbidden", "directory is disabled")
		}
		if row.Version != version {
			return apierr.New("precondition_failed", "directory version does not match")
		}
		connectionID, claim := row.SsoConnectionID.String, row.SsoIdentityClaim.String
		if in.SSOConnectionID != nil {
			connectionID, claim = *in.SSOConnectionID, *in.SSOIdentityClaim
			if err := validateDirectorySSOTx(ctx, q, spaceID, connectionID, claim); err != nil {
				return err
			}
		}
		if name == "" {
			name = row.Name
		}
		if err := s.consumeStepUp(ctx, q); err != nil {
			return err
		}
		updated, err := q.UpdateDirectoryConfiguration(ctx, db.UpdateDirectoryConfigurationParams{
			ID: row.ID, Name: name, Version: row.Version,
			SsoConnectionID: optionalDirectoryText(connectionID), SsoIdentityClaim: optionalDirectoryText(claim),
		})
		if err != nil {
			return err
		}
		out = directoryFromRow(updated)
		return audit.WriteSecurityEvent(ctx, q, audit.SecurityEvent{
			ActorType: "member", ActorID: actorMemberID, MemberID: actorMemberID,
			Action: "directory.update", Outcome: "success", Permission: "auth.connections:manage",
			Resource: audit.Resource{Type: "directory", ID: row.ID, SpaceID: spaceID},
		})
	})
	if err != nil {
		return Directory{}, normalizeConnectionError(err)
	}
	return out, nil
}

func (s *Service) DisableDirectory(ctx context.Context, actorMemberID, spaceID, directoryID string, version int64) error {
	return normalizeConnectionError(s.Store.InTx(ctx, func(q *db.Queries) error {
		if err := s.checkConnectionManagement(ctx, q, actorMemberID, spaceID); err != nil {
			return err
		}
		row, err := q.LockDirectory(ctx, db.LockDirectoryParams{ID: strings.TrimSpace(directoryID)})
		if errors.Is(err, pgx.ErrNoRows) || err == nil && row.SpaceID != spaceID {
			return apierr.New("not_found", "directory was not found")
		}
		if err != nil {
			return err
		}
		if row.Version != version {
			return apierr.New("precondition_failed", "directory version does not match")
		}
		if err := s.consumeStepUp(ctx, q); err != nil {
			return err
		}
		if err := q.DisableDirectory(ctx, db.DisableDirectoryParams{ID: row.ID}); err != nil {
			return err
		}
		return audit.WriteSecurityEvent(ctx, q, audit.SecurityEvent{
			ActorType: "member", ActorID: actorMemberID, MemberID: actorMemberID,
			Action: "directory.disable", Outcome: "success", Permission: "auth.connections:manage",
			Resource: audit.Resource{Type: "directory", ID: row.ID, SpaceID: spaceID},
		})
	}))
}

// ValidateDirectoryToken checks current directory scope before any idempotency replay.
func (s *Service) ValidateDirectoryToken(ctx context.Context, directoryID string, token secret.String) error {
	_, err := s.authenticateDirectory(ctx, directoryID, token)
	return err
}

func (s *Service) authenticateDirectory(ctx context.Context, directoryID string, token secret.String) (db.Directory, error) {
	if strings.TrimSpace(token.Value()) == "" {
		return db.Directory{}, apierr.New("unauthenticated", "SCIM bearer token required")
	}
	row, err := s.Store.Queries().GetDirectoryByTokenHash(ctx, db.GetDirectoryByTokenHashParams{TokenHash: digest(strings.TrimSpace(token.Value()))})
	if errors.Is(err, pgx.ErrNoRows) || err == nil && row.ID != strings.TrimSpace(directoryID) {
		return db.Directory{}, apierr.New("unauthenticated", "SCIM bearer token is invalid")
	}
	if err != nil {
		return db.Directory{}, err
	}
	if row.Status != "active" {
		return db.Directory{}, apierr.New("unauthenticated", "SCIM directory is disabled")
	}
	return row, nil
}

func directoryTokenPrefix(token string) string {
	if len(token) <= 16 {
		return token
	}
	return token[:16]
}

func directoryFromRow(row db.Directory) Directory {
	return Directory{ID: row.ID, SpaceID: row.SpaceID, Name: row.Name, Status: row.Status, Version: row.Version, CreatedAt: row.CreatedAt.Time, UpdatedAt: row.UpdatedAt.Time, SSOConnectionID: row.SsoConnectionID.String, SSOIdentityClaim: row.SsoIdentityClaim.String}
}

func directoryFromListRow(row db.ListDirectoriesRow) Directory {
	return Directory{ID: row.ID, SpaceID: row.SpaceID, Name: row.Name, Status: row.Status, Version: row.Version, CreatedAt: row.CreatedAt.Time, UpdatedAt: row.UpdatedAt.Time, SSOConnectionID: row.SsoConnectionID.String, SSOIdentityClaim: row.SsoIdentityClaim.String}
}

func actorUserID(ctx context.Context, memberID string) pgtype.Text {
	id := authorization.HumanActorUserID(ctx, memberID)
	return pgtype.Text{String: id, Valid: id != ""}
}
