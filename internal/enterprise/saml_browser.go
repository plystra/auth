package enterprise

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/plystra/auth/internal/account"
	"github.com/plystra/auth/internal/apierr"
	"github.com/plystra/auth/internal/db"
	"github.com/plystra/auth/internal/secret"
)

const samlBrowserResponseAAD = "plystra-auth-saml-browser-response-v1:"

// StageSAMLBrowserResponse accepts the IdP's front-channel response without
// a browser credential. Only the cookie-bound interaction can complete it.
func (s *Service) StageSAMLBrowserResponse(ctx context.Context, connectionID, redirectURI string, relay, response secret.String) (string, error) {
	receivedAt := time.Now().UTC()
	q := s.Store.Queries()
	state, err := q.GetSAMLBrowserRelay(ctx, db.GetSAMLBrowserRelayParams{
		StateHash: digest(relay.Value()), ConnectionID: connectionID, RedirectUri: redirectURI,
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return "", invalidSAMLBrowserResponse()
	}
	if err != nil {
		return "", err
	}
	connection, err := s.hostedSAMLConnection(ctx, connectionID, redirectURI)
	if err != nil {
		return "", err
	}
	if _, err := s.verifyBrowserSAML(ctx, connection, state.RequestID.String, response.Value(), receivedAt); err != nil {
		return "", err
	}
	ciphertext, err := s.seal([]byte(response.Value()), samlBrowserResponseAAD+state.ID)
	if err != nil {
		return "", err
	}
	changed, err := q.InsertSAMLBrowserResponse(ctx, db.InsertSAMLBrowserResponseParams{
		StateID: state.ID, Ciphertext: ciphertext, ReceivedAt: pgtype.Timestamptz{Time: receivedAt, Valid: true},
	})
	if err != nil {
		return "", err
	}
	if changed != 1 {
		return "", invalidSAMLBrowserResponse()
	}
	return state.InteractionID, nil
}

// CompleteSAMLBrowser creates and binds the session after proof of the original cookie.
func (s *Service) CompleteSAMLBrowser(ctx context.Context, connectionID, redirectURI string, browser OIDCBrowserBinding) (account.User, error) {
	state, err := s.Store.Queries().GetSAMLBrowserResponse(ctx, db.GetSAMLBrowserResponseParams{
		InteractionID: browser.ID, RequestHash: browser.RequestHash[:], ConnectionID: connectionID, RedirectUri: redirectURI,
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return account.User{}, invalidSAMLBrowserResponse()
	}
	if err != nil {
		return account.User{}, err
	}
	connection, err := s.hostedSAMLConnection(ctx, connectionID, redirectURI)
	if err != nil {
		return account.User{}, err
	}
	response, err := s.open(state.Ciphertext, samlBrowserResponseAAD+state.ID)
	if err != nil {
		return account.User{}, apierr.New("temporarily_unavailable", "the pending SAML response is unavailable")
	}
	defer clear(response)
	claims, err := s.verifyBrowserSAML(ctx, connection, state.RequestID.String, string(response), state.ReceivedAt.Time)
	if err != nil {
		return account.User{}, err
	}
	result, err := s.finishCallback(ctx, connection, db.SsoState{ID: state.ID, StateHash: state.StateHash}, claims, &browser)
	return result.User, err
}

func (s *Service) verifyBrowserSAML(ctx context.Context, connection db.SsoConnection, requestID, response string, receivedAt time.Time) (idTokenClaims, error) {
	inResponseTo, keyHintMissing, err := parseSAMLResponseHints(response)
	if err != nil {
		return idTokenClaims{}, err
	}
	if requestID == "" || inResponseTo != requestID {
		return idTokenClaims{}, invalidSAMLBrowserResponse()
	}
	return s.verifiedSAMLLogin(ctx, connection, response, keyHintMissing, requestID, receivedAt)
}

func (s *Service) hostedSAMLConnection(ctx context.Context, connectionID, redirectURI string) (db.SsoConnection, error) {
	row, err := s.Store.Queries().GetSSOConnection(ctx, db.GetSSOConnectionParams{ID: connectionID})
	if errors.Is(err, pgx.ErrNoRows) || err == nil && (row.Provider != "saml" || row.Status != "active" || row.RedirectUri != redirectURI) {
		return db.SsoConnection{}, invalidSAMLBrowserResponse()
	}
	return row, err
}

func invalidSAMLBrowserResponse() error {
	return apierr.New("invalid_grant", "the SAML browser response is invalid or expired")
}

func (s *Service) ExpireSAMLArtifacts(ctx context.Context) error {
	queries := s.Store.Queries()
	if _, err := queries.DeleteExpiredSAMLBrowserResponses(ctx); err != nil {
		return err
	}
	_, err := queries.DeleteExpiredSAMLAssertionUses(ctx)
	return err
}
