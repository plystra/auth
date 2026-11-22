package enterprise

import (
	"context"
	"encoding/json"
	"errors"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/plystra/auth/internal/apierr"
	"github.com/plystra/auth/internal/authorization"
	"github.com/plystra/auth/internal/db"
	"github.com/plystra/auth/internal/ids"
)

func optionalDirectoryText(value string) pgtype.Text {
	return pgtype.Text{String: value, Valid: value != ""}
}

func validateDirectorySSOTx(ctx context.Context, q *db.Queries, spaceID, connectionID, claim string) error {
	if connectionID == "" && claim == "" {
		return nil
	}
	if connectionID == "" || !validDirectoryIdentityClaim(claim) {
		return apierr.New("validation_failed", "provide an SSO connection and a stable identity claim together")
	}
	connection, err := q.LockSSOConnection(ctx, db.LockSSOConnectionParams{ID: connectionID})
	if errors.Is(err, pgx.ErrNoRows) || err == nil && (connection.SpaceID != spaceID || connection.Status != "active") {
		return apierr.New("validation_failed", "directory SSO connection must be active and belong to this Space")
	}
	if err != nil {
		return err
	}
	if connection.Provider == "oidc" && claim == "NameID" || connection.Provider == "saml" && claim == "sub" {
		return apierr.New("validation_failed", "identity claim does not match the connection protocol")
	}
	return nil
}

func validDirectoryIdentityClaim(claim string) bool {
	if claim == "" || len(claim) > maxExternalSubjectLen || strings.ContainsAny(claim, " \t\r\n[]\x00") {
		return false
	}
	// URI attribute names are allowed, but JSON paths and reassignable login
	// identifiers cannot be used as stable directory identity keys.
	if !strings.Contains(claim, "://") && strings.ContainsAny(claim, "./\\") {
		return false
	}
	name := strings.ToLower(claim)
	if i := strings.LastIndex(name, "/"); i >= 0 {
		name = name[i+1:]
	}
	switch name {
	case "email", "emails", "emailaddress", "email_address", "mail", "upn", "username", "user_name", "preferred_username", "name", "displayname", "display_name", "unique_name":
		return false
	}
	return true
}

func directoryIdentityValue(connection db.SsoConnection, claim string, claims idTokenClaims) (string, error) {
	var value string
	if connection.Provider == "saml" {
		if claim == "NameID" {
			value = claims.Subject
		} else if values := claims.SAMLAttributes[claim]; len(values) == 1 {
			value = values[0]
		}
	} else if claim == "sub" {
		value = claims.Subject
	} else if raw := claims.VerifiedClaims[claim]; raw != nil {
		if err := json.Unmarshal(raw, &value); err != nil {
			return "", directoryIdentityUnavailable()
		}
	}
	if strings.TrimSpace(value) == "" || len(value) > maxExternalSubjectLen || strings.ContainsAny(value, "\r\n\x00") {
		return "", directoryIdentityUnavailable()
	}
	return value, nil
}

func directoryIdentityUnavailable() error {
	return apierr.New("invalid_grant", "the SSO identity has no active trusted directory binding")
}

type directorySSOHint struct {
	directory db.Directory
	user      db.DirectoryUser
}

func (s *Service) directorySSOHint(ctx context.Context, connection db.SsoConnection, claims idTokenClaims) (*directorySSOHint, error) {
	directory, err := s.Store.Queries().GetDirectoryForSSOConnection(ctx, db.GetDirectoryForSSOConnectionParams{ConnectionID: optionalDirectoryText(connection.ID)})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if directory.Status != "active" {
		return nil, directoryIdentityUnavailable()
	}
	value, err := directoryIdentityValue(connection, directory.SsoIdentityClaim.String, claims)
	if err != nil {
		return nil, err
	}
	user, err := s.Store.Queries().GetDirectoryUserByExternalID(ctx, db.GetDirectoryUserByExternalIDParams{DirectoryID: directory.ID, ExternalID: value})
	if errors.Is(err, pgx.ErrNoRows) || err == nil && (!user.Active || user.DeletedAt.Valid) {
		return nil, directoryIdentityUnavailable()
	}
	if err != nil {
		return nil, err
	}
	return &directorySSOHint{directory: directory, user: user}, nil
}

func lockDirectorySSOTx(ctx context.Context, q *db.Queries, connection db.SsoConnection, hint *directorySSOHint) error {
	var users, members []string
	if hint != nil {
		users, members = []string{hint.user.UserID}, []string{hint.user.MemberID}
	}
	// Match governance and SCIM account -> member -> node -> directory locks.
	// The Space lock also serializes connection associations, including absence.
	if err := authorization.LockProvisioningTx(ctx, q, connection.SpaceID, users, members); err != nil {
		return err
	}
	current, err := q.GetDirectoryForSSOConnection(ctx, db.GetDirectoryForSSOConnectionParams{ConnectionID: optionalDirectoryText(connection.ID)})
	if hint == nil && errors.Is(err, pgx.ErrNoRows) {
		return nil
	}
	if errors.Is(err, pgx.ErrNoRows) || err == nil && (hint == nil || current.ID != hint.directory.ID || current.Version != hint.directory.Version || current.Status != "active") {
		return directoryIdentityUnavailable()
	}
	if err != nil {
		return err
	}
	_, err = q.LockDirectory(ctx, db.LockDirectoryParams{ID: current.ID})
	return err
}

func linkDirectoryIdentityTx(ctx context.Context, q *db.Queries, connection db.SsoConnection, hint *directorySSOHint, claims idTokenClaims) (db.GetDirectoryLoginIdentityRow, error) {
	row, err := q.GetDirectoryLoginIdentity(ctx, db.GetDirectoryLoginIdentityParams{DirectoryID: hint.directory.ID, ID: hint.user.ID, SpaceID: connection.SpaceID})
	if errors.Is(err, pgx.ErrNoRows) {
		return row, directoryIdentityUnavailable()
	}
	if err != nil {
		return row, err
	}
	external, err := q.GetExternalIdentity(ctx, db.GetExternalIdentityParams{Issuer: connection.Issuer, Subject: claims.Subject})
	if errors.Is(err, pgx.ErrNoRows) {
		_, err = q.CreateExternalIdentity(ctx, db.CreateExternalIdentityParams{
			ID: string(ids.New[ids.ID]("ext")), UserID: row.UserID, Issuer: connection.Issuer, Subject: claims.Subject,
			DirectoryUserID: optionalDirectoryText(row.DirectoryUserID),
		})
	} else if err == nil {
		if external.UserID != row.UserID || external.DirectoryUserID.Valid && external.DirectoryUserID.String != row.DirectoryUserID {
			return row, directoryIdentityUnavailable()
		}
		if !external.DirectoryUserID.Valid {
			_, err = q.AssociateExternalDirectoryUser(ctx, db.AssociateExternalDirectoryUserParams{ID: external.ID, DirectoryUserID: optionalDirectoryText(row.DirectoryUserID)})
			if errors.Is(err, pgx.ErrNoRows) {
				return row, directoryIdentityUnavailable()
			}
		}
	}
	return row, err
}
