package enterprise

import (
	"context"

	"github.com/plystra/auth/internal/apierr"
	"github.com/plystra/auth/internal/audit"
	"github.com/plystra/auth/internal/db"
	"github.com/plystra/auth/internal/secret"
)

func OIDCClientSecretUpdateRequest(spaceID, connectionID, ifMatch string, clientSecret secret.String) map[string]string {
	return map[string]string{
		"operation": SSOConnectionUpdateOperation, "space_id": spaceID, "connection_id": connectionID,
		"if_match": ifMatch, "client_secret_digest": sha256Hex(clientSecret.Value()),
	}
}

func (s *Service) ReplaceOIDCClientSecret(ctx context.Context, actorMemberID, spaceID, connectionID, ifMatch string, clientSecret secret.String) (Connection, error) {
	if len(clientSecret.Value()) == 0 || len(clientSecret.Value()) > 4096 {
		return Connection{}, apierr.New("validation_failed", "client_secret must be between 1 and 4096 bytes")
	}
	request := OIDCClientSecretUpdateRequest(spaceID, connectionID, ifMatch, clientSecret)
	ciphertext, err := s.seal([]byte(clientSecret.Value()), clientSecretAAD)
	if err != nil {
		return Connection{}, err
	}
	var out Connection
	err = s.Store.InTx(ctx, func(q *db.Queries) error {
		current, err := s.lockConnectionUpdateTx(ctx, q, actorMemberID, request)
		if err != nil {
			return err
		}
		if current.Provider != "oidc" {
			return apierr.New("validation_failed", "client secret updates require an OIDC connection")
		}
		row, err := q.ReplaceOIDCClientSecret(ctx, db.ReplaceOIDCClientSecretParams{
			ID: connectionID, SpaceID: spaceID, ClientSecretCiphertext: ciphertext,
		})
		if err != nil {
			return err
		}
		out, err = connectionFromPublicRow(db.ListSSOConnectionsRow(row))
		if err != nil {
			return err
		}
		return audit.WriteSecurityEvent(ctx, q, audit.SecurityEvent{
			ActorType: "member", ActorID: actorMemberID, MemberID: actorMemberID,
			Action: "sso.connection.oidc_client_secret.update", Outcome: "success", Permission: "auth.connections:manage",
			Resource: audit.Resource{Type: "sso_connection", ID: connectionID, SpaceID: spaceID},
		})
	})
	if err != nil {
		return Connection{}, normalizeConnectionError(err)
	}
	return out, nil
}
