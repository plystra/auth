package enterprise

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/plystra/auth/internal/apierr"
	"github.com/plystra/auth/internal/audit"
	"github.com/plystra/auth/internal/authorization"
	"github.com/plystra/auth/internal/db"
	"github.com/plystra/auth/internal/ids"
	"github.com/plystra/auth/internal/session"
	"github.com/plystra/auth/internal/stepup"
)

const CompleteIdentityLinkOperation = "me.sso_links.complete"

func IdentityLinkProofRequest(connectionID, state, code string) map[string]string {
	return map[string]string{"connection_id": connectionID, "state_sha256": hexDigest(state), "code_sha256": hexDigest(code)}
}

func (s *Service) StartIdentityLink(ctx context.Context, connectionID, userID, sessionID string) (StartResult, error) {
	connection, err := s.identityLinkConnection(ctx, connectionID)
	if err != nil {
		return StartResult{}, err
	}
	member, err := s.Store.Queries().GetSSOMembershipForUser(ctx, db.GetSSOMembershipForUserParams{UserID: userID, SpaceID: connection.SpaceID})
	if errors.Is(err, pgx.ErrNoRows) || err == nil && !member.Active {
		return StartResult{}, unavailableIdentityLink()
	}
	if err != nil {
		return StartResult{}, err
	}
	if err := s.Store.InTx(ctx, func(q *db.Queries) error {
		_, err := lockIdentityLinkTarget(ctx, q, connection, userID, member.ID)
		if err != nil {
			return err
		}
		return lockIdentityLinkSession(ctx, q, userID, sessionID, nil)
	}); err != nil {
		return StartResult{}, err
	}
	result, state, err := s.prepareOIDCRequest(ctx, connection, connection.RedirectUri, nil)
	if err != nil {
		return StartResult{}, err
	}
	state.LinkSessionID = optionalDirectoryText(sessionID)
	state.LinkMemberID = optionalDirectoryText(member.ID)
	state.LinkConnectionUpdatedAt = connection.UpdatedAt
	err = s.Store.InTx(ctx, func(q *db.Queries) error {
		if _, err := lockIdentityLinkTarget(ctx, q, connection, userID, member.ID); err != nil {
			return err
		}
		if err := lockIdentityLinkSession(ctx, q, userID, sessionID, nil); err != nil {
			return err
		}
		_, err := q.CreateSSOState(ctx, state)
		return err
	})
	if err != nil {
		return StartResult{}, err
	}
	return result, nil
}

func (s *Service) CompleteIdentityLink(ctx context.Context, connectionID, userID, sessionID, rawState, code string) error {
	if rawState == "" || code == "" || strings.TrimSpace(rawState) != rawState || strings.TrimSpace(code) != code {
		return apierr.New("invalid_request", "state and code are required")
	}
	connection, err := s.identityLinkConnection(ctx, connectionID)
	if err != nil {
		return err
	}
	proof, err := stepup.DigestValue(IdentityLinkProofRequest(connectionID, rawState, code))
	if err != nil {
		return err
	}
	stateHash := digest(rawState)
	var state db.SsoState
	err = s.Store.InTx(ctx, func(q *db.Queries) error {
		if err := lockIdentityLinkSession(ctx, q, userID, sessionID, proof); err != nil {
			return err
		}
		var err error
		state, err = lockIdentityLinkState(ctx, q, connection, sessionID, stateHash)
		return err
	})
	if err != nil {
		return err
	}
	claims, err := s.exchangeOIDCCode(ctx, connection, state, code)
	if err != nil {
		return err
	}
	ctx = session.WithStepUpRequirement(ctx, session.StepUpRequirement{SessionID: sessionID, Operation: CompleteIdentityLinkOperation, Digest: proof})
	return s.Store.InTx(ctx, func(q *db.Queries) error {
		email, err := lockIdentityLinkTarget(ctx, q, connection, userID, state.LinkMemberID.String)
		if err != nil {
			return err
		}
		if email != strings.ToLower(strings.TrimSpace(claims.Email)) {
			return unavailableIdentityLink()
		}
		if err := lockIdentityLinkSession(ctx, q, userID, sessionID, proof); err != nil {
			return err
		}
		current, err := lockIdentityLinkState(ctx, q, connection, sessionID, stateHash)
		if err != nil {
			return err
		}
		if current.LinkMemberID != state.LinkMemberID {
			return unavailableIdentityLink()
		}
		if err := s.Sessions.ConsumeStepUpTx(ctx, q); err != nil {
			return err
		}
		if err := linkExternalIdentity(ctx, q, connection.Issuer, claims.Subject, userID); err != nil {
			return err
		}
		if err := q.ConsumeSSOState(ctx, db.ConsumeSSOStateParams{ID: current.ID}); err != nil {
			return err
		}
		space, err := q.GetSpace(ctx, db.GetSpaceParams{ID: connection.SpaceID})
		if err != nil {
			return err
		}
		return audit.WriteSecurityEvent(ctx, q, audit.SecurityEvent{
			ActorType: "user", ActorID: userID, UserID: userID, MemberID: current.LinkMemberID.String,
			Action: "auth.sso.identity.link", Outcome: "success", CredentialType: "oidc",
			Resource:      audit.Resource{Type: "sso_connection", ID: connection.ID, SpaceID: connection.SpaceID},
			PolicyVersion: space.PolicyVersion, Metadata: map[string]string{"subject_hash": hexDigest(claims.Subject)},
		})
	})
}

func (s *Service) identityLinkConnection(ctx context.Context, connectionID string) (db.SsoConnection, error) {
	connection, err := s.Store.Queries().GetSSOConnection(ctx, db.GetSSOConnectionParams{ID: connectionID})
	if errors.Is(err, pgx.ErrNoRows) || err == nil && (connection.Provider != "oidc" || connection.Status != "active") {
		return db.SsoConnection{}, unavailableIdentityLink()
	}
	return connection, err
}

func lockIdentityLinkTarget(ctx context.Context, q *db.Queries, connection db.SsoConnection, userID, memberID string) (string, error) {
	if err := authorization.LockProvisioningTx(ctx, q, connection.SpaceID, []string{userID}, []string{memberID}); err != nil {
		return "", err
	}
	current, err := q.LockSSOConnection(ctx, db.LockSSOConnectionParams{ID: connection.ID})
	if err != nil {
		return "", err
	}
	if current.Status != "active" || !current.UpdatedAt.Time.Equal(connection.UpdatedAt.Time) {
		return "", unavailableIdentityLink()
	}
	if err := lockDirectorySSOTx(ctx, q, connection, nil); err != nil {
		return "", err
	}
	active, err := q.AreSpaceAncestorsActive(ctx, db.AreSpaceAncestorsActiveParams{SpaceID: connection.SpaceID})
	if err != nil {
		return "", err
	}
	if !active {
		return "", unavailableIdentityLink()
	}
	member, err := q.GetSSOMembershipForUser(ctx, db.GetSSOMembershipForUserParams{UserID: userID, SpaceID: connection.SpaceID})
	if errors.Is(err, pgx.ErrNoRows) || err == nil && (!member.Active || member.ID != memberID) {
		return "", unavailableIdentityLink()
	}
	if err != nil {
		return "", err
	}
	user, err := q.GetUserByID(ctx, db.GetUserByIDParams{ID: userID})
	if err == nil && (user.Status != "active" || user.DisabledAt.Valid || !user.EmailVerifiedAt.Valid) {
		return "", unavailableIdentityLink()
	}
	return user.EmailNormalized, err
}

func lockIdentityLinkSession(ctx context.Context, q *db.Queries, userID, sessionID string, proof []byte) error {
	current, err := q.LockSessionForStepUp(ctx, db.LockSessionForStepUpParams{ID: sessionID})
	now := time.Now().UTC()
	if errors.Is(err, pgx.ErrNoRows) || err == nil && (current.UserID != userID || current.RevokedAt.Valid || !current.ExpiresAt.Time.After(now)) {
		return apierr.New("UNAUTHENTICATED", "the account session is no longer active")
	}
	if err != nil {
		return err
	}
	if proof != nil && (current.StepUpOperation.String != CompleteIdentityLinkOperation || !bytes.Equal(current.StepUpDigest, proof) || !current.StepUpExpiresAt.Time.After(now)) {
		return apierr.New("STEP_UP_REQUIRED", "complete step-up for this operation and request")
	}
	return nil
}

func lockIdentityLinkState(ctx context.Context, q *db.Queries, connection db.SsoConnection, sessionID string, hash []byte) (db.SsoState, error) {
	state, err := q.LockSSOStateByHash(ctx, db.LockSSOStateByHashParams{StateHash: hash})
	if errors.Is(err, pgx.ErrNoRows) || err == nil && (state.ConnectionID != connection.ID || state.ConsumedAt.Valid ||
		!state.ExpiresAt.Time.After(time.Now().UTC()) || !state.LinkSessionID.Valid || state.LinkSessionID.String != sessionID ||
		!state.LinkConnectionUpdatedAt.Time.Equal(connection.UpdatedAt.Time)) {
		return db.SsoState{}, unavailableIdentityLink()
	}
	return state, err
}

func linkExternalIdentity(ctx context.Context, q *db.Queries, issuer, subject, userID string) error {
	_, err := q.LinkUnclaimedExternalIdentity(ctx, db.LinkUnclaimedExternalIdentityParams{
		ID: string(ids.New[ids.ID]("ext")), UserID: userID, Issuer: issuer, Subject: subject,
	})
	if !errors.Is(err, pgx.ErrNoRows) {
		return err
	}
	existing, err := q.GetExternalIdentity(ctx, db.GetExternalIdentityParams{Issuer: issuer, Subject: subject})
	if err != nil {
		return err
	}
	if existing.UserID != userID || existing.DirectoryUserID.Valid {
		return unavailableIdentityLink()
	}
	return nil
}

func unavailableIdentityLink() error {
	return apierr.New("invalid_grant", "the enterprise identity cannot be linked")
}
