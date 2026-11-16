package authorization

import (
	"context"
	"encoding/hex"
	"errors"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/plystra/auth/internal/apierr"
	"github.com/plystra/auth/internal/audit"
	"github.com/plystra/auth/internal/authz/engine"
	"github.com/plystra/auth/internal/db"
)

func (s *Service) TopHumanOwnerTx(ctx context.Context, q *db.Queries, agentMemberID string) (string, error) {
	seen := map[string]struct{}{}
	memberID := agentMemberID
	for depth := 0; depth < s.maxDelegationDepth(); depth++ {
		if _, exists := seen[memberID]; exists {
			return "", apierr.New("OWNER_INACTIVE", "the Agent owner chain contains a cycle")
		}
		seen[memberID] = struct{}{}
		agent, err := q.GetAgentMember(ctx, db.GetAgentMemberParams{MemberID: memberID})
		if errors.Is(err, pgx.ErrNoRows) || err == nil && (!agent.OwnerMemberID.Valid || agent.OwnerMemberID.String == "") {
			return "", apierr.New("OWNER_INACTIVE", "the Agent owner is unavailable")
		}
		if err != nil {
			return "", err
		}
		owner, err := q.GetMemberForAuthorization(ctx, db.GetMemberForAuthorizationParams{ID: agent.OwnerMemberID.String})
		if errors.Is(err, pgx.ErrNoRows) || err == nil && owner.Status != "active" {
			return "", apierr.New("OWNER_INACTIVE", "the Agent owner is unavailable")
		}
		if err != nil {
			return "", err
		}
		if owner.Type == "human" {
			return owner.ID, nil
		}
		if owner.Type == "application" {
			return "", apierr.New("APPROVAL_REQUIRED", "this Agent has no configured human approver")
		}
		memberID = owner.ID
	}
	return "", apierr.New("OWNER_INACTIVE", "the Agent owner chain is too deep")
}

// CheckBusiness consumes a persisted approval only when current policy still
// allows the Agent action. A normal Check, explain, or management preflight
// cannot consume a business approval.
func (s *Service) CheckBusiness(ctx context.Context, in CheckRequest, resourceType, resourceID string) (engine.Decision, int64, error) {
	return s.checkBusiness(ctx, in, resourceType, resourceID, true)
}

// ExplainBusiness evaluates the same persisted approval and current authority
// as CheckBusiness without consuming the approval or executing the action.
func (s *Service) ExplainBusiness(ctx context.Context, in CheckRequest, resourceType, resourceID string) (engine.Decision, int64, error) {
	return s.checkBusiness(ctx, in, resourceType, resourceID, false)
}

func (s *Service) checkBusiness(ctx context.Context, in CheckRequest, resourceType, resourceID string, consume bool) (engine.Decision, int64, error) {
	if s == nil || s.Store == nil {
		return engine.Decision{}, 0, apierr.New("UNAVAILABLE", "authorization is unavailable")
	}
	var decision engine.Decision
	var version int64
	err := s.Store.InTx(ctx, func(q *db.Queries) error {
		var err error
		decision, version, err = s.checkQueries(ctx, q, in, 0, false)
		if err != nil || decision.Code != "APPROVAL_REQUIRED" || resourceType == "" || resourceID == "" {
			return err
		}
		approved, err := q.FindApprovedApprovalRequest(ctx, db.FindApprovedApprovalRequestParams{
			AgentMemberID: in.MemberID, PermissionKey: in.Permission,
			ResourceType: resourceType, ResourceID: resourceID, ResourceSpaceID: in.ResourceSpace,
			ResourceGroupID: approvalNullableText(in.ResourceGroup), ResourceOwnerMemberID: approvalNullableText(in.ResourceOwner),
		})
		if errors.Is(err, pgx.ErrNoRows) {
			latest, latestErr := q.FindPendingOrRejectedApprovalRequest(ctx, db.FindPendingOrRejectedApprovalRequestParams{
				AgentMemberID: in.MemberID, PermissionKey: in.Permission,
				ResourceType: resourceType, ResourceID: resourceID, ResourceSpaceID: in.ResourceSpace,
				ResourceGroupID: approvalNullableText(in.ResourceGroup), ResourceOwnerMemberID: approvalNullableText(in.ResourceOwner),
			})
			if errors.Is(latestErr, pgx.ErrNoRows) {
				return nil
			}
			if latestErr != nil {
				return latestErr
			}
			ownerID, ownerErr := s.TopHumanOwnerTx(ctx, q, in.MemberID)
			if ownerErr == nil && ownerID == latest.ApproverMemberID {
				if latest.Status == "pending" {
					decision = decision.WithApprovalStatus("APPROVAL_PENDING")
				} else {
					decision = decision.WithApprovalStatus("APPROVAL_REJECTED")
				}
			}
			return nil
		}
		if err != nil {
			return err
		}
		ownerID, err := s.TopHumanOwnerTx(ctx, q, in.MemberID)
		if err != nil || ownerID != approved.ApproverMemberID {
			return err
		}
		in.approved = true
		allowed, allowedVersion, err := s.checkQueries(ctx, q, in, 0, false)
		if err != nil {
			return err
		}
		if allowed.Effect != engine.Allow {
			return nil
		}
		if !consume {
			decision, version = allowed, allowedVersion
			return nil
		}
		count, err := q.ConsumeApprovedApprovalRequest(ctx, db.ConsumeApprovedApprovalRequestParams{ID: approved.ID})
		if err != nil {
			return err
		}
		if count != 1 {
			return apierr.New("CONFLICT", "the approval was already used")
		}
		if err := audit.WriteSecurityEvent(ctx, q, audit.SecurityEvent{
			ActorType: "member", ActorID: in.MemberID, Action: "approval.consume", Outcome: "success", MemberID: in.MemberID,
			Resource:   audit.Resource{Type: "approval", ID: approved.ID, SpaceID: in.ResourceSpace, GroupID: in.ResourceGroup},
			Permission: in.Permission, PolicyVersion: allowedVersion,
			Metadata: map[string]string{
				"request_digest": hex.EncodeToString(approved.RequestDigest), "approver_member_id": approved.ApproverMemberID,
				"requested_resource_type": resourceType, "requested_resource_id": resourceID,
			},
		}); err != nil {
			return err
		}
		decision, version = allowed, allowedVersion
		return nil
	})
	return decision, version, err
}

func approvalNullableText(value string) pgtype.Text {
	return pgtype.Text{String: value, Valid: value != ""}
}
