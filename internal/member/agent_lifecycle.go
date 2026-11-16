package member

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/plystra/auth/internal/apierr"
	"github.com/plystra/auth/internal/db"
)

// RequireActiveApplicationTx prevents local member recovery or credential
// takeover from undoing an operator's global application suspension. Callers
// hold the member chain locks shared with the suspension transaction.
func RequireActiveApplicationTx(ctx context.Context, q *db.Queries, memberID string) error {
	active, err := q.MemberApplicationIsActive(ctx, db.MemberApplicationIsActiveParams{MemberID: memberID})
	if err != nil {
		return err
	}
	if !active.Valid || !active.Bool {
		return apierr.New("CONFLICT", "the member's application is not active")
	}
	return nil
}

// SetAgentSubtreeStatusTx changes the selected Agent and its owned group,
// never the containing group it shares with its siblings. The caller checks
// authority and writes the operation audit in this same transaction.
func SetAgentSubtreeStatusTx(ctx context.Context, q *db.Queries, memberID, status string) error {
	if status != "suspended" && status != "removed" {
		return apierr.New("VALIDATION_FAILED", "Agent subtree status is invalid")
	}
	if err := LockChainsTx(ctx, q, memberID); err != nil {
		return err
	}
	if _, err := q.GetAgentMember(ctx, db.GetAgentMemberParams{MemberID: memberID}); err != nil {
		return err
	}
	if status == "removed" {
		if err := q.DeleteAgentMember(ctx, db.DeleteAgentMemberParams{MemberID: memberID}); err != nil {
			return err
		}
	} else if err := q.StopAgentMember(ctx, db.StopAgentMemberParams{MemberID: memberID}); err != nil {
		return err
	}
	if err := q.RevokeAgentCredentials(ctx, db.RevokeAgentCredentialsParams{MemberID: memberID}); err != nil {
		return err
	}
	if status == "suspended" {
		return SuspendOwnedAgentsTx(ctx, q, memberID)
	}
	group, err := q.GetAgentsGroupByOwner(ctx, db.GetAgentsGroupByOwnerParams{OwnerMemberID: pgtype.Text{String: memberID, Valid: true}})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	if status == "removed" {
		if err := q.DeleteAgentSubtree(ctx, db.DeleteAgentSubtreeParams{GroupID: group.ID}); err != nil {
			return err
		}
		if err := q.RevokeAgentGrantsInGroupSubtree(ctx, db.RevokeAgentGrantsInGroupSubtreeParams{GroupID: group.ID}); err != nil {
			return err
		}
		if err := q.RevokeGroupGrantsInGroupSubtree(ctx, db.RevokeGroupGrantsInGroupSubtreeParams{GroupID: group.ID}); err != nil {
			return err
		}
		if err := q.RemoveAgentGroupSubtree(ctx, db.RemoveAgentGroupSubtreeParams{GroupID: group.ID}); err != nil {
			return err
		}
	}
	return q.RevokeAgentCredentialsInGroupSubtree(ctx, db.RevokeAgentCredentialsInGroupSubtreeParams{GroupID: group.ID})
}

// SuspendOwnedAgentsTx also supports application owners, which are not Agents
// themselves. The owner lock serializes the subtree read with child creation.
func SuspendOwnedAgentsTx(ctx context.Context, q *db.Queries, ownerID string) error {
	if err := LockChainsTx(ctx, q, ownerID); err != nil {
		return err
	}
	group, err := q.GetAgentsGroupByOwner(ctx, db.GetAgentsGroupByOwnerParams{OwnerMemberID: pgtype.Text{String: ownerID, Valid: true}})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	if err := q.StopAgentSubtree(ctx, db.StopAgentSubtreeParams{GroupID: group.ID}); err != nil {
		return err
	}
	return q.RevokeAgentCredentialsInGroupSubtree(ctx, db.RevokeAgentCredentialsInGroupSubtreeParams{GroupID: group.ID})
}
