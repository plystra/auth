package invitation

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"net/mail"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/plystra/auth/internal/account"
	"github.com/plystra/auth/internal/apierr"
	"github.com/plystra/auth/internal/audit"
	"github.com/plystra/auth/internal/authorization"
	"github.com/plystra/auth/internal/db"
	"github.com/plystra/auth/internal/ids"
	"github.com/plystra/auth/internal/security"
	"github.com/plystra/auth/internal/store"
)

const tokenLifetime = 7 * 24 * time.Hour

type Service struct {
	Store         *store.Store
	Accounts      *account.Service
	Authorization *authorization.Service
}

type CreateInput struct {
	SpaceID       string
	Email         string
	MemberID      string
	InviterUserID string
	ExpiresAt     time.Time
}

type Invitation struct {
	ID              string
	SpaceID         string
	EmailNormalized string
	MemberID        string
	ExpiresAt       time.Time
	ConsumedAt      *time.Time
	CreatedAt       time.Time
}

type Acceptance struct {
	SpaceID             string `json:"space_id,omitempty"`
	MemberID            string `json:"member_id,omitempty"`
	PendingVerification bool   `json:"pending_verification,omitempty"`
}

// Create creates a single-use invitation token. The raw token is returned only
// to the caller; the database stores its one-way digest.
func (s *Service) Create(ctx context.Context, in CreateInput) (Invitation, string, error) {
	return s.create(ctx, "", "", in)
}

// CreateForActor records the invitation issuance in the same transaction as
// the hashed token. The caller must authorize the actor against the target
// Space before invoking this method.
func (s *Service) CreateForActor(ctx context.Context, actorType, actorID string, in CreateInput) (Invitation, string, error) {
	return s.create(ctx, actorType, actorID, in)
}

func (s *Service) create(ctx context.Context, actorType, actorID string, in CreateInput) (Invitation, string, error) {
	if s == nil || s.Store == nil {
		return Invitation{}, "", errors.New("invitation store is required")
	}
	email, err := normalizeEmail(in.Email)
	if err != nil {
		return Invitation{}, "", err
	}
	if strings.TrimSpace(in.SpaceID) == "" {
		return Invitation{}, "", apierr.New("VALIDATION_FAILED", "space_id is required")
	}
	expiresAt := in.ExpiresAt
	if expiresAt.IsZero() {
		expiresAt = time.Now().UTC().Add(tokenLifetime)
	}
	if !expiresAt.After(time.Now().UTC()) {
		return Invitation{}, "", apierr.New("VALIDATION_FAILED", "invitation expiry must be in the future")
	}
	raw, hash, err := newToken()
	if err != nil {
		return Invitation{}, "", err
	}
	var row db.InvitationToken
	err = s.Store.InTx(ctx, func(q *db.Queries) error {
		memberID := pgtype.Text{}
		if value := strings.TrimSpace(in.MemberID); value != "" {
			memberID = pgtype.Text{String: value, Valid: true}
			if actorType != "member" || s.Authorization == nil {
				return apierr.New("USER_ACCOUNT_REQUIRED", "binding invitations require a human member")
			}
			if err := s.Authorization.CheckInvitationBindingTx(ctx, q, in.InviterUserID, actorID, in.SpaceID, value, email, true); err != nil {
				return err
			}
		}
		inviterMember := pgtype.Text{}
		if actorType == "member" && actorID != "" {
			inviterMember = pgtype.Text{String: actorID, Valid: true}
		}
		inviterUser := pgtype.Text{}
		if in.InviterUserID != "" {
			inviterUser = pgtype.Text{String: in.InviterUserID, Valid: true}
		}
		row, err = q.CreateInvitationToken(ctx, db.CreateInvitationTokenParams{
			ID: string(ids.New[ids.InvitationID]("ivt")), SpaceID: in.SpaceID,
			EmailNormalized: pgtype.Text{String: email, Valid: true},
			MemberID:        memberID,
			InviterMemberID: inviterMember, InviterUserID: inviterUser,
			TokenHash: hash, ExpiresAt: pgtype.Timestamptz{Time: expiresAt.UTC(), Valid: true},
		})
		if err != nil {
			return err
		}
		if strings.TrimSpace(actorID) != "" {
			return audit.Write(ctx, q, actorType, actorID, "invitation.create", row.ID, "success")
		}
		return nil
	})
	if err != nil {
		return Invitation{}, "", err
	}
	return fromRow(row), raw, nil
}

// Consume atomically marks a valid token as used. A token can therefore be
// accepted by at most one concurrent caller.
func (s *Service) Consume(ctx context.Context, raw string) (Invitation, error) {
	if s == nil || s.Store == nil {
		return Invitation{}, errors.New("invitation store is required")
	}
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return Invitation{}, apierr.New("invalid_grant", "invitation token is invalid or expired")
	}
	sum := sha256.Sum256([]byte(raw))
	var row db.InvitationToken
	err := s.Store.InTx(ctx, func(q *db.Queries) error {
		var consumeErr error
		row, consumeErr = q.ConsumeInvitationToken(ctx, db.ConsumeInvitationTokenParams{TokenHash: sum[:]})
		return consumeErr
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return Invitation{}, apierr.New("invalid_grant", "invitation token is invalid or expired")
	}
	if err != nil {
		return Invitation{}, err
	}
	return fromRow(row), nil
}

func (s *Service) RegisterNewUser(ctx context.Context, raw, email, password string) (Acceptance, error) {
	if s == nil || s.Store == nil || s.Accounts == nil || s.Accounts.Settings == nil || s.Accounts.Mailer == nil {
		return Acceptance{}, apierr.New("UNAVAILABLE", "invited registration is unavailable")
	}
	if len(raw) != 46 || !strings.HasPrefix(raw, "iv_") {
		return Acceptance{}, apierr.New("invalid_grant", "invitation token is invalid or expired")
	}
	normalized, err := normalizeEmail(email)
	if err != nil {
		return Acceptance{}, err
	}
	if s.Accounts.Limiter != nil {
		allowed, err := s.Accounts.Limiter.Allow(ctx, "register:"+normalized, 10, time.Hour)
		if err != nil {
			return Acceptance{}, err
		}
		if !allowed {
			return Acceptance{}, apierr.New("rate_limited", "too many registration attempts")
		}
	}
	sum := sha256.Sum256([]byte(raw))
	preflight, err := s.Store.Queries().GetInvitationByToken(ctx, db.GetInvitationByTokenParams{TokenHash: sum[:]})
	if errors.Is(err, pgx.ErrNoRows) {
		return Acceptance{}, apierr.New("invalid_grant", "invitation token is invalid or expired")
	}
	if err != nil {
		return Acceptance{}, err
	}
	if preflight.EmailNormalized != normalized {
		return Acceptance{}, apierr.New("invalid_grant", "invitation token is invalid or expired")
	}
	settings, err := s.Accounts.Settings.Get(ctx)
	if err != nil {
		return Acceptance{}, err
	}
	if settings.RegistrationMode == "closed" {
		return Acceptance{}, apierr.New("forbidden", "registration is closed")
	}
	if len(password) < settings.PasswordMinLength || len(password) > security.MaxPasswordBytes {
		return Acceptance{}, apierr.New("invalid_request", "password does not meet the configured length policy")
	}
	passwordHash, err := s.Accounts.Passwords.Hash(password)
	if err != nil {
		return Acceptance{}, err
	}
	var accepted Acceptance
	err = s.Store.InTx(ctx, func(q *db.Queries) error {
		current, err := s.Accounts.Settings.GetTx(ctx, q)
		if err != nil {
			return err
		}
		if current.RegistrationMode == "closed" {
			return apierr.New("forbidden", "registration is closed")
		}
		if len(password) < current.PasswordMinLength {
			return apierr.New("invalid_request", "password does not meet the configured minimum length")
		}
		inv, err := q.GetInvitationForRegistration(ctx, db.GetInvitationForRegistrationParams{TokenHash: sum[:]})
		if errors.Is(err, pgx.ErrNoRows) {
			return apierr.New("invalid_grant", "invitation token is invalid or expired")
		}
		if err != nil {
			return err
		}
		if inv.EmailNormalized != normalized {
			return apierr.New("invalid_grant", "invitation token is invalid or expired")
		}
		if inv.MemberID.Valid {
			if !inv.InviterMemberID.Valid || !inv.InviterUserID.Valid || s.Authorization == nil {
				return apierr.New("AUTHORITY_DELTA_NOT_COVERED", "the invitation's binding authority cannot be verified")
			}
			if err := s.Authorization.CheckInvitationBindingTx(ctx, q, inv.InviterUserID.String, inv.InviterMemberID.String, inv.SpaceID, inv.MemberID.String, normalized, false); err != nil {
				return err
			}
		} else if err := activeSpaceTx(ctx, q, inv.SpaceID); err != nil {
			return err
		}
		user, err := s.Accounts.CreatePendingInvitedUserTx(ctx, q, normalized, passwordHash)
		if err != nil {
			return err
		}
		if err := q.CreatePendingInvitationRegistration(ctx, db.CreatePendingInvitationRegistrationParams{
			UserID: user.ID, InvitationID: inv.ID,
		}); err != nil {
			return err
		}
		accepted = Acceptance{PendingVerification: true}
		return nil
	})
	var constraint *pgconn.PgError
	if errors.As(err, &constraint) && constraint.Code == "23505" {
		return Acceptance{}, apierr.New("conflict", "an account with this email already exists")
	}
	return accepted, err
}

func (s *Service) FinalizeVerifiedUserTx(ctx context.Context, q *db.Queries, userID string) error {
	if s == nil || s.Store == nil {
		return errors.New("invitation store is required")
	}
	invitationID, err := q.GetPendingInvitationForUser(ctx, db.GetPendingInvitationForUserParams{UserID: userID})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	user, err := q.LockUserForStatus(ctx, db.LockUserForStatusParams{ID: userID})
	if err != nil {
		return err
	}
	if user.Status != "active" || !user.EmailVerifiedAt.Valid || user.DisabledAt.Valid {
		return apierr.New("UNAUTHENTICATED", "the user account is unavailable")
	}
	inv, err := q.ConsumeInvitationByID(ctx, db.ConsumeInvitationByIDParams{ID: invitationID})
	if errors.Is(err, pgx.ErrNoRows) {
		return apierr.New("invalid_grant", "invitation token is invalid or expired")
	}
	if err != nil {
		return err
	}
	if user.EmailNormalized != inv.EmailNormalized {
		return apierr.New("invalid_grant", "invitation token is invalid or expired")
	}
	if inv.MemberID.Valid {
		if err := s.acceptExistingMemberTx(ctx, q, inv, userID); err != nil {
			return err
		}
	} else if _, err := acceptNewMemberTx(ctx, q, inv, userID, user.EmailNormalized); err != nil {
		return err
	}
	return q.DeletePendingInvitationRegistration(ctx, db.DeletePendingInvitationRegistrationParams{UserID: userID})
}

// AcceptVerifiedUser creates or binds a human member and consumes the invitation
// in the same transaction.
func (s *Service) AcceptVerifiedUser(ctx context.Context, raw, userID string) (Acceptance, error) {
	if s == nil || s.Store == nil {
		return Acceptance{}, errors.New("invitation store is required")
	}
	if len(raw) != 46 || !strings.HasPrefix(raw, "iv_") || userID == "" {
		return Acceptance{}, apierr.New("invalid_grant", "invitation token is invalid or expired")
	}
	sum := sha256.Sum256([]byte(raw))
	var accepted Acceptance
	err := s.Store.InTx(ctx, func(q *db.Queries) error {
		user, err := q.LockUserForStatus(ctx, db.LockUserForStatusParams{ID: userID})
		if errors.Is(err, pgx.ErrNoRows) {
			return apierr.New("UNAUTHENTICATED", "the user account is unavailable")
		}
		if err != nil {
			return err
		}
		if user.Status != "active" || user.DisabledAt.Valid {
			return apierr.New("UNAUTHENTICATED", "the user account is unavailable")
		}
		if !user.EmailVerifiedAt.Valid {
			return apierr.New("EMAIL_VERIFICATION_REQUIRED", "verify your email before accepting the invitation")
		}
		inv, err := q.ConsumeInvitationToken(ctx, db.ConsumeInvitationTokenParams{TokenHash: sum[:]})
		if errors.Is(err, pgx.ErrNoRows) {
			return apierr.New("invalid_grant", "invitation token is invalid or expired")
		}
		if err != nil {
			return err
		}
		if user.EmailNormalized != inv.EmailNormalized {
			return apierr.New("invalid_grant", "invitation token is invalid or expired")
		}
		if inv.MemberID.Valid {
			accepted = Acceptance{SpaceID: inv.SpaceID, MemberID: inv.MemberID.String}
			return s.acceptExistingMemberTx(ctx, q, inv, user.ID)
		}
		accepted, err = acceptNewMemberTx(ctx, q, inv, user.ID, user.EmailNormalized)
		return err
	})
	return accepted, err
}

func (s *Service) acceptExistingMemberTx(ctx context.Context, q *db.Queries, inv db.InvitationToken, userID string) error {
	if !inv.InviterMemberID.Valid || !inv.InviterUserID.Valid || s.Authorization == nil {
		return apierr.New("AUTHORITY_DELTA_NOT_COVERED", "the invitation's binding authority cannot be verified")
	}
	if operators, err := q.CountOperatorsForUser(ctx, db.CountOperatorsForUserParams{UserID: userID}); err != nil {
		return err
	} else if operators != 0 {
		return apierr.New("CONFLICT", "an operator identity cannot become a member")
	}
	if err := s.Authorization.BindInvitationTx(ctx, q, inv.InviterUserID.String, inv.InviterMemberID.String, inv.SpaceID, inv.MemberID.String, userID); err != nil {
		return err
	}
	return audit.Write(ctx, q, "user", userID, "invitation.accept", inv.ID, "success")
}

func acceptNewMemberTx(ctx context.Context, q *db.Queries, inv db.InvitationToken, userID, email string) (Acceptance, error) {
	if operators, err := q.CountOperatorsForUser(ctx, db.CountOperatorsForUserParams{UserID: userID}); err != nil {
		return Acceptance{}, err
	} else if operators != 0 {
		return Acceptance{}, apierr.New("CONFLICT", "an operator identity cannot become a member")
	}
	if err := activeSpaceTx(ctx, q, inv.SpaceID); err != nil {
		return Acceptance{}, err
	}
	member, err := q.CreateMemberWithPolicy(ctx, db.CreateMemberWithPolicyParams{
		ID: string(ids.New[ids.MemberID]("mem")), SpaceID: inv.SpaceID,
		Name: email, Type: "human", BindingPolicy: "single",
	})
	if err != nil {
		return Acceptance{}, err
	}
	if err := q.BindUserMember(ctx, db.BindUserMemberParams{UserID: userID, MemberID: member.ID}); err != nil {
		return Acceptance{}, err
	}
	if _, err := q.BumpPolicyVersion(ctx, db.BumpPolicyVersionParams{ID: inv.SpaceID}); err != nil {
		return Acceptance{}, err
	}
	if err := audit.Write(ctx, q, "user", userID, "invitation.accept", inv.ID, "success"); err != nil {
		return Acceptance{}, err
	}
	return Acceptance{SpaceID: inv.SpaceID, MemberID: member.ID}, nil
}

func activeSpaceTx(ctx context.Context, q *db.Queries, invitedSpaceID string) error {
	seen := map[string]struct{}{}
	spaceID := invitedSpaceID
	for depth := 0; depth < 64; depth++ {
		if _, found := seen[spaceID]; found {
			return apierr.New("INVALID_RESOURCE", "Space hierarchy contains a cycle")
		}
		seen[spaceID] = struct{}{}
		space, err := q.LockSpaceForAuthorization(ctx, db.LockSpaceForAuthorizationParams{ID: spaceID})
		if errors.Is(err, pgx.ErrNoRows) || err == nil && space.Status != "active" {
			return apierr.New("SPACE_INACTIVE", "the invited Space is unavailable")
		}
		if err != nil {
			return err
		}
		if !space.ParentID.Valid {
			return nil
		}
		spaceID = space.ParentID.String
	}
	return apierr.New("INVALID_RESOURCE", "Space hierarchy is too deep")
}

func newToken() (string, []byte, error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", nil, err
	}
	raw := "iv_" + base64.RawURLEncoding.EncodeToString(buf)
	sum := sha256.Sum256([]byte(raw))
	return raw, sum[:], nil
}

func normalizeEmail(value string) (string, error) {
	email := strings.ToLower(strings.TrimSpace(value))
	parsed, err := mail.ParseAddress(email)
	if err != nil || parsed.Address != email || !strings.Contains(email, "@") {
		return "", apierr.New("VALIDATION_FAILED", "a valid email is required")
	}
	return email, nil
}

func fromRow(row db.InvitationToken) Invitation {
	var consumedAt *time.Time
	if row.ConsumedAt.Valid {
		v := row.ConsumedAt.Time
		consumedAt = &v
	}
	return Invitation{ID: row.ID, SpaceID: row.SpaceID, EmailNormalized: row.EmailNormalized, MemberID: row.MemberID.String, ExpiresAt: row.ExpiresAt.Time, ConsumedAt: consumedAt, CreatedAt: row.CreatedAt.Time}
}
