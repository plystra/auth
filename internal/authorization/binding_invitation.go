package authorization

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/plystra/auth/internal/apierr"
	"github.com/plystra/auth/internal/db"
	"github.com/plystra/auth/internal/stepup"
)

func (s *Service) checkBindingTargetTx(ctx context.Context, q *db.Queries, actorMemberID, spaceID, memberID, identity string, validateUser bool) error {
	member, err := q.LockMemberInSpace(ctx, db.LockMemberInSpaceParams{ID: memberID, SpaceID: spaceID})
	if errors.Is(err, pgx.ErrNoRows) {
		return apierr.New("NOT_FOUND", "member was not found in this Space")
	}
	if err != nil {
		return err
	}
	if member.Status != "active" {
		return apierr.New("CONFLICT", "member is not active")
	}
	if member.Type != "human" {
		return apierr.New("VALIDATION_FAILED", "only human members can bind a user")
	}
	if validateUser {
		user, err := q.GetUserByID(ctx, db.GetUserByIDParams{ID: identity})
		if errors.Is(err, pgx.ErrNoRows) {
			return apierr.New("NOT_FOUND", "user was not found")
		}
		if err != nil {
			return err
		}
		if user.Status != "active" {
			return apierr.New("CONFLICT", "user is not active")
		}
		if operators, err := q.CountOperatorsForUser(ctx, db.CountOperatorsForUserParams{UserID: identity}); err != nil {
			return err
		} else if operators != 0 {
			return apierr.New("CONFLICT", "an operator identity cannot become a member")
		}
	}
	change, err := s.bindingAuthorityDeltaTx(ctx, q, memberID, identity, spaceID)
	if err != nil {
		return err
	}
	if len(change.Permissions) != 0 {
		if err := s.authorizeTargetTx(ctx, q, actorMemberID, "auth.grants:assign", spaceID, memberID); err != nil {
			return err
		}
	}
	if len(change.Rights) != 0 {
		if err := s.authorizeTargetTx(ctx, q, actorMemberID, "auth.assign_rights:manage", spaceID, memberID); err != nil {
			return err
		}
	}
	if err := s.coverPositiveGrantDeltaTx(ctx, q, change, actorMemberID, member.ID, member.Type, spaceID); err != nil {
		return err
	}
	count, err := q.CountActiveMemberBindings(ctx, db.CountActiveMemberBindingsParams{MemberID: memberID})
	if err != nil {
		return err
	}
	if member.BindingPolicy == "single" && count > 0 {
		return apierr.New("CONFLICT", "a single-binding member can have only one active user binding")
	}
	return nil
}

// CheckInvitationBindingTx validates the issuing human's current authority.
// identity names the prospective recipient for the delta evaluator; at issue
// time it can be the normalized email because the user may not exist yet.
func (s *Service) CheckInvitationBindingTx(ctx context.Context, q *db.Queries, inviterUserID, inviterMemberID, spaceID, memberID, identity string, consumeProof bool) error {
	if s == nil || inviterUserID == "" || inviterMemberID == "" {
		return apierr.New("USER_ACCOUNT_REQUIRED", "binding invitations require a human member")
	}
	if err := s.authorizeTargetTx(ctx, q, inviterMemberID, "auth.bindings:manage", spaceID, memberID); err != nil {
		return err
	}
	actor, err := q.GetMemberForAuthorization(ctx, db.GetMemberForAuthorizationParams{ID: inviterMemberID})
	if err != nil {
		return err
	}
	if actor.Type != "human" || actor.Status != "active" {
		return apierr.New("USER_ACCOUNT_REQUIRED", "binding invitations require an active human member")
	}
	user, err := q.GetUserByID(ctx, db.GetUserByIDParams{ID: inviterUserID})
	if errors.Is(err, pgx.ErrNoRows) {
		return apierr.New("ACTOR_USER_INACTIVE", "the inviter account is unavailable")
	}
	if err != nil {
		return err
	}
	if user.Status != "active" || user.DisabledAt.Valid {
		return apierr.New("ACTOR_USER_INACTIVE", "the inviter account is unavailable")
	}
	binding, err := q.GetUserMemberBinding(ctx, db.GetUserMemberBindingParams{UserID: inviterUserID, MemberID: inviterMemberID})
	if errors.Is(err, pgx.ErrNoRows) {
		return apierr.New("BINDING_REVOKED", "the inviter's member binding is unavailable")
	}
	if err != nil {
		return err
	}
	if binding.Status != "active" || binding.RevokedAt.Valid || binding.ExpiresAt.Valid && !binding.ExpiresAt.Time.After(time.Now().UTC()) {
		return apierr.New("BINDING_REVOKED", "the inviter's member binding is unavailable")
	}
	if consumeProof {
		if _, ok := stepup.RequirementFromContext(ctx); !ok {
			return apierr.New("STEP_UP_REQUIRED", "complete step-up for this invitation")
		}
		if err := s.consumeStepUpTx(ctx, q); err != nil {
			return err
		}
	}
	return s.checkBindingTargetTx(ctx, q, inviterMemberID, spaceID, memberID, identity, false)
}

func (s *Service) BindInvitationTx(ctx context.Context, q *db.Queries, inviterUserID, inviterMemberID, spaceID, memberID, userID string) error {
	if err := s.CheckInvitationBindingTx(ctx, q, inviterUserID, inviterMemberID, spaceID, memberID, userID, false); err != nil {
		return err
	}
	if err := q.BindUserMember(ctx, db.BindUserMemberParams{UserID: userID, MemberID: memberID}); err != nil {
		return err
	}
	_, err := q.BumpPolicyVersion(ctx, db.BumpPolicyVersionParams{ID: spaceID})
	return err
}
