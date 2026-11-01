package factor

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/plystra/auth/internal/apierr"
	"github.com/plystra/auth/internal/audit"
	"github.com/plystra/auth/internal/db"
	"github.com/plystra/auth/internal/ids"
	"github.com/plystra/auth/internal/stepup"
)

type PasskeyChallenge struct {
	ID        string                       `json:"challenge_id"`
	Options   *protocol.CredentialCreation `json:"options"`
	ExpiresAt time.Time                    `json:"expires_at"`
}

const passkeyChallengeLifetime = 5 * time.Minute

var ErrInvalidPasskey = errors.New("invalid passkey assertion")
var ErrClonedPasskey = errors.New("passkey authenticator counter did not advance")

type passkeyUser struct {
	id          string
	email       string
	credentials []webauthn.Credential
}

func (u passkeyUser) WebAuthnID() []byte                         { return []byte(u.id) }
func (u passkeyUser) WebAuthnName() string                       { return u.email }
func (u passkeyUser) WebAuthnDisplayName() string                { return u.email }
func (u passkeyUser) WebAuthnCredentials() []webauthn.Credential { return u.credentials }

func (s *Service) passkeyUserTx(ctx context.Context, q *db.Queries, userID string) (passkeyUser, error) {
	row, err := q.LockUserForStatus(ctx, db.LockUserForStatusParams{ID: userID})
	if errors.Is(err, pgx.ErrNoRows) || err == nil && (row.Status != "active" || row.DisabledAt.Valid) {
		return passkeyUser{}, apierr.New("UNAUTHENTICATED", "the user account is unavailable")
	}
	if err != nil {
		return passkeyUser{}, err
	}
	rows, err := q.ListPasskeysForUser(ctx, db.ListPasskeysForUserParams{UserID: userID})
	if err != nil {
		return passkeyUser{}, err
	}
	aead, err := s.cipher()
	if err != nil {
		return passkeyUser{}, err
	}
	user := passkeyUser{id: userID, email: row.Email}
	for _, row := range rows {
		plain, err := open(aead, row.SecretCiphertext)
		if err != nil {
			return passkeyUser{}, err
		}
		var credential webauthn.Credential
		err = json.Unmarshal(plain, &credential)
		clear(plain)
		if err != nil || len(credential.ID) == 0 || !bytes.Equal(row.CredentialID, credential.ID) ||
			(row.PublicKey != nil && !bytes.Equal(row.PublicKey, credential.PublicKey)) ||
			!strings.EqualFold(row.Kind, "webauthn") || int64(credential.Authenticator.SignCount) != row.Counter {
			return passkeyUser{}, apierr.New("UNAVAILABLE", "stored passkey is invalid")
		}
		user.credentials = append(user.credentials, credential)
	}
	return user, nil
}

func (s *Service) BeginPasskeyLogin() (*protocol.CredentialAssertion, []byte, time.Time, error) {
	if s == nil || s.WebAuthn == nil {
		return nil, nil, time.Time{}, apierr.New("UNAVAILABLE", "passkey sign-in is unavailable")
	}
	assertion, session, err := s.WebAuthn.BeginDiscoverableLogin(webauthn.WithUserVerification(protocol.VerificationRequired))
	if err != nil {
		return nil, nil, time.Time{}, err
	}
	session.Expires = time.Now().UTC().Add(passkeyChallengeLifetime)
	encoded, err := json.Marshal(session)
	return assertion, encoded, session.Expires, err
}

func (s *Service) VerifyPasskeyTx(ctx context.Context, q *db.Queries, userID string, sessionData, rawResponse []byte) error {
	if s == nil || s.WebAuthn == nil || len(rawResponse) == 0 || len(rawResponse) > 64*1024 {
		return ErrInvalidPasskey
	}
	user, err := s.passkeyUserTx(ctx, q, userID)
	if err != nil {
		return err
	}
	var session webauthn.SessionData
	if err := json.Unmarshal(sessionData, &session); err != nil || session.Challenge == "" {
		return apierr.New("UNAVAILABLE", "stored passkey sign-in challenge is invalid")
	}
	parsed, err := protocol.ParseCredentialRequestResponseBytes(rawResponse)
	if err != nil {
		return ErrInvalidPasskey
	}
	credential, err := s.WebAuthn.ValidateDiscoverableLogin(func(rawID, userHandle []byte) (webauthn.User, error) {
		if !bytes.Equal(userHandle, []byte(userID)) {
			return nil, ErrInvalidPasskey
		}
		for _, owned := range user.credentials {
			if bytes.Equal(rawID, owned.ID) {
				return user, nil
			}
		}
		return nil, ErrInvalidPasskey
	}, session, parsed)
	if err != nil || !credential.Flags.UserVerified {
		return ErrInvalidPasskey
	}
	if credential.Authenticator.CloneWarning {
		return ErrClonedPasskey
	}
	plain, err := json.Marshal(credential)
	if err != nil {
		return err
	}
	aead, err := s.cipher()
	if err != nil {
		return err
	}
	ciphertext, err := seal(aead, plain)
	clear(plain)
	if err != nil {
		return err
	}
	updated, err := q.UpdatePasskeyAfterLogin(ctx, db.UpdatePasskeyAfterLoginParams{
		CredentialID: credential.ID, UserID: userID, SecretCiphertext: ciphertext,
		Counter: int64(credential.Authenticator.SignCount),
	})
	if err != nil {
		return err
	}
	if updated != 1 {
		return apierr.New("UNAVAILABLE", "stored passkey is unavailable")
	}
	return nil
}

func (s *Service) BeginPasskeyEnrollment(ctx context.Context, userID, sessionID, name string) (PasskeyChallenge, error) {
	name = strings.TrimSpace(name)
	if name == "" || len(name) > 100 {
		return PasskeyChallenge{}, apierr.New("VALIDATION_FAILED", "passkey name must be between 1 and 100 characters")
	}
	if s == nil || s.Store == nil || s.WebAuthn == nil || s.StepUp == nil {
		return PasskeyChallenge{}, apierr.New("UNAVAILABLE", "passkey enrollment is unavailable")
	}
	if _, ok := stepup.RequirementFromContext(ctx); !ok {
		return PasskeyChallenge{}, apierr.New("STEP_UP_REQUIRED", "passkey enrollment requires step-up")
	}
	var result PasskeyChallenge
	err := s.Store.InTx(ctx, func(q *db.Queries) error {
		if err := s.StepUp.ConsumeStepUpTx(ctx, q); err != nil {
			return err
		}
		user, err := s.passkeyUserTx(ctx, q, userID)
		if err != nil {
			return err
		}
		creation, session, err := s.WebAuthn.BeginRegistration(user,
			webauthn.WithAuthenticatorSelection(protocol.AuthenticatorSelection{
				ResidentKey:        protocol.ResidentKeyRequirementRequired,
				RequireResidentKey: protocol.ResidentKeyRequired(),
				UserVerification:   protocol.VerificationRequired,
			}),
			webauthn.WithExclusions(webauthn.Credentials(user.credentials).CredentialDescriptors()),
		)
		if err != nil {
			return err
		}
		session.Expires = time.Now().UTC().Add(passkeyChallengeLifetime)
		encoded, err := json.Marshal(session)
		if err != nil {
			return err
		}
		id := string(ids.New[ids.PasskeyChallengeID]("pch"))
		if err := q.CreatePasskeyChallenge(ctx, db.CreatePasskeyChallengeParams{
			ID: id, UserID: userID, SessionID: sessionID, Name: name,
			SessionData: encoded, ExpiresAt: pgtype.Timestamptz{Time: session.Expires, Valid: true},
		}); err != nil {
			return err
		}
		if err := audit.Write(ctx, q, "user", userID, "factor.passkey.begin", userID, "success"); err != nil {
			return err
		}
		result = PasskeyChallenge{ID: id, Options: creation, ExpiresAt: session.Expires}
		return nil
	})
	return result, err
}

func (s *Service) FinishPasskeyEnrollment(ctx context.Context, userID, sessionID, challengeID string, rawResponse []byte) (string, error) {
	if s == nil || s.Store == nil || s.WebAuthn == nil || !ids.PasskeyChallengeID(challengeID).Valid() || len(rawResponse) > 64*1024 {
		return "", apierr.New("invalid_grant", "passkey challenge is invalid or expired")
	}
	var factorID string
	var validationErr error
	err := s.Store.InTx(ctx, func(q *db.Queries) error {
		challenge, err := q.LockPasskeyChallenge(ctx, db.LockPasskeyChallengeParams{ID: challengeID})
		if errors.Is(err, pgx.ErrNoRows) || err == nil && (challenge.UserID != userID || challenge.SessionID != sessionID || challenge.ConsumedAt.Valid || !challenge.ExpiresAt.Time.After(time.Now().UTC())) {
			return apierr.New("invalid_grant", "passkey challenge is invalid or expired")
		}
		if err != nil {
			return err
		}
		currentSession, err := q.LockSessionForStepUp(ctx, db.LockSessionForStepUpParams{ID: sessionID})
		if errors.Is(err, pgx.ErrNoRows) || err == nil && (currentSession.UserID != userID || currentSession.RevokedAt.Valid || !currentSession.ExpiresAt.Time.After(time.Now().UTC())) {
			return apierr.New("UNAUTHENTICATED", "the session is unavailable")
		}
		if err != nil {
			return err
		}
		user, err := s.passkeyUserTx(ctx, q, userID)
		if err != nil {
			return err
		}
		var session webauthn.SessionData
		if err := json.Unmarshal(challenge.SessionData, &session); err != nil {
			return apierr.New("UNAVAILABLE", "stored passkey challenge is invalid")
		}
		parsed, parseErr := protocol.ParseCredentialCreationResponseBytes(rawResponse)
		var credential *webauthn.Credential
		if parseErr != nil {
			validationErr = apierr.New("invalid_grant", "passkey response is invalid")
		} else {
			credential, err = s.WebAuthn.CreateCredential(user, session, parsed)
			if err != nil {
				validationErr = apierr.New("invalid_grant", "passkey response is invalid")
			} else if !credential.Flags.UserVerified {
				validationErr = apierr.New("invalid_grant", "passkey user verification is required")
			}
		}
		if err := q.ConsumePasskeyChallenge(ctx, db.ConsumePasskeyChallengeParams{ID: challengeID}); err != nil {
			return err
		}
		if validationErr != nil {
			return audit.Write(ctx, q, "user", userID, "factor.passkey.finish", userID, "failure")
		}
		plain, err := json.Marshal(credential)
		if err != nil {
			return err
		}
		aead, err := s.cipher()
		if err != nil {
			return err
		}
		ciphertext, err := seal(aead, plain)
		clear(plain)
		if err != nil {
			return err
		}
		factorID = string(ids.New[ids.FactorID]("fac"))
		if _, err := q.CreateFactor(ctx, db.CreateFactorParams{
			ID: factorID, UserID: userID, Kind: "webauthn", Name: challenge.Name,
			SecretCiphertext: ciphertext, CredentialID: credential.ID, PublicKey: credential.PublicKey,
			Counter: pgtype.Int8{Int64: int64(credential.Authenticator.SignCount), Valid: true},
		}); err != nil {
			return err
		}
		return audit.Write(ctx, q, "user", userID, "factor.passkey.create", factorID, "success")
	})
	var constraint *pgconn.PgError
	if errors.As(err, &constraint) && constraint.Code == "23505" {
		return "", apierr.New("conflict", "passkey is already registered")
	}
	if err != nil {
		return "", err
	}
	if validationErr != nil {
		return "", validationErr
	}
	return factorID, nil
}
