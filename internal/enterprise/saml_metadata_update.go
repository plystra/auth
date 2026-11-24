package enterprise

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/plystra/auth/internal/apierr"
	"github.com/plystra/auth/internal/audit"
	"github.com/plystra/auth/internal/db"
)

const SSOConnectionUpdateOperation = "sso_connections.update"

func (c Connection) ETag() string { return connectionETag(c.ID, c.UpdatedAt) }

func connectionETag(id string, updatedAt time.Time) string {
	return `"` + sha256Hex(id+":"+strconv.FormatInt(updatedAt.UnixMicro(), 10)) + `"`
}

func SAMLMetadataUpdateRequest(spaceID, connectionID, ifMatch, metadata string) map[string]string {
	return map[string]string{
		"operation": SSOConnectionUpdateOperation, "space_id": spaceID, "connection_id": connectionID,
		"if_match": ifMatch, "saml_metadata_digest": sha256Hex(metadata),
	}
}

func (s *Service) ReplaceSAMLSigningCertificates(ctx context.Context, actorMemberID, spaceID, connectionID, ifMatch, metadata string) (Connection, error) {
	if len(metadata) == 0 || len(metadata) > 1024*1024 {
		return Connection{}, apierr.New("validation_failed", "SAML metadata must be between 1 byte and 1 MiB")
	}
	details, err := parseSAMLMetadata(strings.TrimSpace(metadata))
	if err != nil {
		return Connection{}, err
	}
	request := SAMLMetadataUpdateRequest(spaceID, connectionID, ifMatch, metadata)
	var out Connection
	err = s.Store.InTx(ctx, func(q *db.Queries) error {
		current, err := s.lockConnectionUpdateTx(ctx, q, actorMemberID, request)
		if err != nil {
			return err
		}
		if current.Provider != "saml" {
			return apierr.New("validation_failed", "signing metadata updates require a SAML connection")
		}
		if details.EntityID != current.SamlEntityID.String || details.SSOURL != current.SamlSsoUrl.String || details.Binding != current.SamlSsoBinding.String {
			return apierr.New("validation_failed", "metadata must preserve the configured IdP entity, SSO endpoint and binding")
		}
		row, err := q.ReplaceSAMLSigningCertificates(ctx, db.ReplaceSAMLSigningCertificatesParams{
			ID: connectionID, SpaceID: spaceID, SamlIdpCertificate: pgtype.Text{String: details.Certificate, Valid: true},
		})
		if err != nil {
			return err
		}
		out, err = connectionFromPublicRow(db.ListSSOConnectionsRow(row))
		if err != nil {
			return err
		}
		if err := audit.WriteSecurityEvent(ctx, q, audit.SecurityEvent{
			ActorType: "member", ActorID: actorMemberID, MemberID: actorMemberID,
			Action: "sso.connection.saml_metadata.update", Outcome: "success", Permission: "auth.connections:manage",
			Resource: audit.Resource{Type: "sso_connection", ID: connectionID, SpaceID: spaceID},
			Metadata: map[string]string{
				"previous_trust_sha256": sha256Hex(current.SamlIdpCertificate.String), "new_trust_sha256": sha256Hex(details.Certificate),
			},
		}); err != nil {
			return err
		}
		if _, err := currentSAMLSigningCertificates(details.Certificate, time.Now()); err != nil {
			return apierr.New("validation_failed", "SAML metadata must contain a currently valid signing certificate")
		}
		return nil
	})
	if err != nil {
		return Connection{}, normalizeConnectionError(err)
	}
	return out, nil
}

func (s *Service) lockConnectionUpdateTx(ctx context.Context, q *db.Queries, actorMemberID string, request map[string]string) (db.LockSSOConnectionInSpaceRow, error) {
	if err := s.authorizeSettingsTx(ctx, q, actorMemberID, request); err != nil {
		return db.LockSSOConnectionInSpaceRow{}, err
	}
	current, err := q.LockSSOConnectionInSpace(ctx, db.LockSSOConnectionInSpaceParams{ID: request["connection_id"], SpaceID: request["space_id"]})
	if errors.Is(err, pgx.ErrNoRows) || err == nil && current.Status != "active" {
		return db.LockSSOConnectionInSpaceRow{}, apierr.New("not_found", "active SSO connection was not found")
	}
	if err != nil {
		return db.LockSSOConnectionInSpaceRow{}, err
	}
	if request["if_match"] != connectionETag(current.ID, current.UpdatedAt.Time) {
		return db.LockSSOConnectionInSpaceRow{}, apierr.New("precondition_failed", "If-Match must contain the current SSO connection ETag")
	}
	return current, nil
}

func sha256Hex(value string) string {
	digest := sha256.Sum256([]byte(value))
	return hex.EncodeToString(digest[:])
}
