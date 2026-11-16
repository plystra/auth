package member

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/plystra/auth/internal/apierr"
	"github.com/plystra/auth/internal/db"
)

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
	} else if err := q.StopAgentSubtree(ctx, db.StopAgentSubtreeParams{GroupID: group.ID}); err != nil {
		return err
	}
	return q.RevokeAgentCredentialsInGroupSubtree(ctx, db.RevokeAgentCredentialsInGroupSubtreeParams{GroupID: group.ID})
}
