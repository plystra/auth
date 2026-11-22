package authorization

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/plystra/auth/internal/audit"
	"github.com/plystra/auth/internal/authz/engine"
	"github.com/plystra/auth/internal/db"
)

type governanceApprovalKey struct{}

type governanceApproval struct {
	id         string
	operation  string
	resourceID string
	digest     []byte
}

// WithGovernanceApproval passes an Approval-Id and the canonical request digest
// to the mutation transaction. The transaction must verify and consume both.
func WithGovernanceApproval(ctx context.Context, id, operation, resourceID string, digest []byte) context.Context {
	return context.WithValue(ctx, governanceApprovalKey{}, governanceApproval{
		id: id, operation: operation, resourceID: resourceID, digest: append([]byte(nil), digest...),
	})
}

// BindGovernanceApproval retains the submitted approval ID but binds its use
// to the domain operation's actual resource and normalized inputs.
func BindGovernanceApproval(ctx context.Context, operation, resourceID string, digest []byte) context.Context {
	if proof, ok := ctx.Value(governanceApprovalKey{}).(governanceApproval); ok {
		return WithGovernanceApproval(ctx, proof.id, operation, resourceID, digest)
	}
	return ctx
}

func (s *Service) checkGovernanceTx(ctx context.Context, q *db.Queries, in CheckRequest) (engine.Decision, error) {
	decision, err := s.CheckTx(ctx, q, in)
	if err != nil || decision.Code != "APPROVAL_REQUIRED" {
		return decision, err
	}
	proof, ok := ctx.Value(governanceApprovalKey{}).(governanceApproval)
	if !ok || proof.id == "" || len(proof.digest) != 32 {
		return decision, nil
	}
	row, err := q.LockApprovalRequest(ctx, db.LockApprovalRequestParams{ID: proof.id})
	if errors.Is(err, pgx.ErrNoRows) {
		return decision, nil
	}
	if err != nil {
		return engine.Decision{}, err
	}
	if row.Kind != "governance" || row.AgentMemberID != in.MemberID || row.PermissionKey != in.Permission ||
		row.ResourceSpaceID != in.ResourceSpace || row.ResourceGroupID != approvalNullableText(in.ResourceGroup) ||
		row.ResourceID != proof.resourceID || row.Operation.String != proof.operation || !bytes.Equal(row.RequestDigest, proof.digest) {
		return decision, nil
	}
	ownerID, err := s.TopHumanOwnerTx(ctx, q, in.MemberID)
	if err != nil {
		return engine.Decision{}, err
	}
	if ownerID != row.ApproverMemberID {
		return decision, nil
	}
	if row.Status == "pending" && row.ExpiresAt.Time.After(time.Now().UTC()) {
		decision = decision.WithApprovalStatus("APPROVAL_PENDING")
		return decision, nil
	}
	if row.Status == "rejected" && row.ExpiresAt.Time.After(time.Now().UTC()) {
		decision = decision.WithApprovalStatus("APPROVAL_REJECTED")
		return decision, nil
	}
	if row.Status != "approved" || !row.ApprovedExpiresAt.Valid || !row.ApprovedExpiresAt.Time.After(time.Now().UTC()) {
		return decision, nil
	}
	in.approved = true
	allowed, err := s.CheckTx(ctx, q, in)
	if err != nil || allowed.Effect != engine.Allow {
		return allowed, err
	}
	count, err := q.ConsumeApprovedApprovalRequest(ctx, db.ConsumeApprovedApprovalRequestParams{ID: row.ID})
	if err != nil {
		return engine.Decision{}, err
	}
	if count != 1 {
		return decision, nil
	}
	if err := audit.WriteSecurityEvent(ctx, q, audit.SecurityEvent{
		ActorType: "member", ActorID: in.MemberID, Action: "approval.consume", Outcome: "success", MemberID: in.MemberID,
		Resource:   audit.Resource{Type: "approval", ID: row.ID, SpaceID: in.ResourceSpace, GroupID: in.ResourceGroup},
		Permission: in.Permission,
		Metadata: map[string]string{
			"request_digest": hex.EncodeToString(row.RequestDigest), "approver_member_id": row.ApproverMemberID,
			"requested_resource_type": row.ResourceType, "requested_resource_id": row.ResourceID,
		},
	}); err != nil {
		return engine.Decision{}, err
	}
	return allowed, nil
}
