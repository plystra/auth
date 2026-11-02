package approval

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/plystra/auth/internal/apierr"
	"github.com/plystra/auth/internal/audit"
	"github.com/plystra/auth/internal/authorization"
	"github.com/plystra/auth/internal/authz/engine"
	"github.com/plystra/auth/internal/db"
	"github.com/plystra/auth/internal/ids"
	"github.com/plystra/auth/internal/stepup"
	"github.com/plystra/auth/internal/store"
)

const pendingLifetime = 24 * time.Hour

type Service struct {
	Store         *store.Store
	Authorization *authorization.Service
	StepUp        stepup.Consumer
}

type Resource struct {
	Type          string `json:"type"`
	ID            string `json:"id"`
	SpaceID       string `json:"space_id"`
	GroupID       string `json:"group_id,omitempty"`
	OwnerMemberID string `json:"owner_member_id,omitempty"`
}

type Request struct {
	ID             string          `json:"id"`
	Kind           string          `json:"kind"`
	AgentMemberID  string          `json:"agent_member_id"`
	Action         string          `json:"action"`
	Resource       Resource        `json:"resource"`
	Operation      string          `json:"operation,omitempty"`
	RequestDetails json.RawMessage `json:"request_details,omitempty"`
	RequestDigest  string          `json:"request_digest"`
	Reason         string          `json:"reason,omitempty"`
	Status         string          `json:"status"`
	ExpiresAt      time.Time       `json:"expires_at"`
	CreatedAt      time.Time       `json:"created_at"`
}

type GovernanceInput struct {
	AgentMemberID  string
	Permission     string
	Operation      string
	SpaceID        string
	TargetMemberID string
	ResourceGroup  string
	RequestDigest  []byte
	RequestDetails json.RawMessage
}

func (s *Service) CreateGovernance(ctx context.Context, in GovernanceInput) (Request, error) {
	if s == nil || s.Store == nil || s.Authorization == nil {
		return Request{}, apierr.New("UNAVAILABLE", "approvals are unavailable")
	}
	if in.AgentMemberID == "" || in.Permission == "" || in.Operation == "" || in.SpaceID == "" ||
		in.TargetMemberID == "" || len(in.RequestDigest) != sha256.Size || !json.Valid(in.RequestDetails) {
		return Request{}, apierr.New("VALIDATION_FAILED", "governance approval request is invalid")
	}
	var details struct {
		Operation string `json:"operation"`
		SpaceID   string `json:"space_id"`
		MemberID  string `json:"member_id"`
	}
	if err := json.Unmarshal(in.RequestDetails, &details); err != nil || details.Operation != in.Operation ||
		details.SpaceID != in.SpaceID || details.MemberID != in.TargetMemberID {
		return Request{}, apierr.New("VALIDATION_FAILED", "governance approval details do not match the target")
	}
	canonicalDigest, err := stepup.Digest(in.RequestDetails)
	if err != nil || !bytes.Equal(canonicalDigest, in.RequestDigest) {
		return Request{}, apierr.New("VALIDATION_FAILED", "governance approval digest does not match its details")
	}
	var created db.ApprovalRequest
	err = s.Store.InTx(ctx, func(q *db.Queries) error {
		decision, err := s.Authorization.CheckTx(ctx, q, authorization.CheckRequest{
			MemberID: in.AgentMemberID, Permission: in.Permission,
			ResourceSpace: in.SpaceID, ResourceGroup: in.ResourceGroup,
		})
		if err != nil {
			return err
		}
		if decision.Effect != engine.Deny || decision.Code != "APPROVAL_REQUIRED" {
			return apierr.New("VALIDATION_FAILED", "the Agent action is not awaiting human approval")
		}
		approverMemberID, err := s.Authorization.TopHumanOwnerTx(ctx, q, in.AgentMemberID)
		if err != nil {
			return err
		}
		created, err = q.CreateGovernanceApprovalRequest(ctx, db.CreateGovernanceApprovalRequestParams{
			ID: string(ids.New[ids.ApprovalID]("apr")), AgentMemberID: in.AgentMemberID,
			ApproverMemberID: approverMemberID, PermissionKey: in.Permission,
			ResourceID: in.TargetMemberID, ResourceSpaceID: in.SpaceID,
			ResourceGroupID: nullableText(in.ResourceGroup), Operation: nullableText(in.Operation),
			RequestDetails: append([]byte(nil), in.RequestDetails...),
			RequestDigest:  append([]byte(nil), in.RequestDigest...),
			ExpiresAt:      pgtype.Timestamptz{Time: time.Now().UTC().Add(pendingLifetime), Valid: true},
		})
		if err != nil {
			return err
		}
		return audit.Write(ctx, q, "member", in.AgentMemberID, "approval.create", created.ID, "success")
	})
	if err != nil {
		return Request{}, err
	}
	return publicRequest(created), nil
}

func (s *Service) CreateBusiness(ctx context.Context, applicationKeyID, agentMemberID, action string, resource Resource, digest []byte, reason string) (Request, error) {
	if s == nil || s.Store == nil || s.Authorization == nil {
		return Request{}, apierr.New("UNAVAILABLE", "approvals are unavailable")
	}
	if agentMemberID == "" || action == "" || strings.TrimSpace(resource.Type) == "" || strings.TrimSpace(resource.ID) == "" || resource.SpaceID == "" || len(digest) != sha256.Size || utf8.RuneCountInString(reason) > 2000 {
		return Request{}, apierr.New("VALIDATION_FAILED", "approval subject, action, resource, digest or reason is invalid")
	}
	var created db.ApprovalRequest
	err := s.Store.InTx(ctx, func(q *db.Queries) error {
		decision, err := s.Authorization.CheckTx(ctx, q, authorization.CheckRequest{
			MemberID: agentMemberID, Permission: action, ResourceSpace: resource.SpaceID,
			ResourceGroup: resource.GroupID, ResourceOwner: resource.OwnerMemberID,
		})
		if err != nil {
			return err
		}
		if decision.Effect != engine.Deny || decision.Code != "APPROVAL_REQUIRED" {
			return apierr.New("VALIDATION_FAILED", "the Agent action is not awaiting human approval")
		}
		approverMemberID, err := s.Authorization.TopHumanOwnerTx(ctx, q, agentMemberID)
		if err != nil {
			return err
		}
		created, err = q.CreateApprovalRequest(ctx, db.CreateApprovalRequestParams{
			ID: string(ids.New[ids.ApprovalID]("apr")), AgentMemberID: agentMemberID,
			ApproverMemberID: approverMemberID, PermissionKey: action,
			ResourceType: resource.Type, ResourceID: resource.ID, ResourceSpaceID: resource.SpaceID,
			ResourceGroupID: nullableText(resource.GroupID), ResourceOwnerMemberID: nullableText(resource.OwnerMemberID),
			RequestDigest: append([]byte(nil), digest...), Reason: strings.TrimSpace(reason),
			ExpiresAt: pgtype.Timestamptz{Time: time.Now().UTC().Add(pendingLifetime), Valid: true},
		})
		if err != nil {
			return err
		}
		return audit.Write(ctx, q, "application", applicationKeyID, "approval.create", created.ID, "success")
	})
	if err != nil {
		return Request{}, err
	}
	return publicRequest(created), nil
}

func (s *Service) ListForUser(ctx context.Context, userID string) ([]Request, error) {
	if s == nil || s.Store == nil {
		return nil, apierr.New("UNAVAILABLE", "approvals are unavailable")
	}
	rows, err := s.Store.Queries().ListPendingApprovalRequestsForUser(ctx, db.ListPendingApprovalRequestsForUserParams{UserID: userID})
	if err != nil {
		return nil, err
	}
	out := make([]Request, 0, len(rows))
	for _, row := range rows {
		out = append(out, publicRequest(row))
	}
	return out, nil
}

func (s *Service) Decide(ctx context.Context, userID, approvalID string, approve bool) (Request, error) {
	if s == nil || s.Store == nil || s.Authorization == nil || s.StepUp == nil {
		return Request{}, apierr.New("UNAVAILABLE", "approvals are unavailable")
	}
	if _, ok := stepup.RequirementFromContext(ctx); !ok {
		return Request{}, apierr.New("STEP_UP_REQUIRED", "complete step-up for this approval")
	}
	var decided db.ApprovalRequest
	err := s.Store.InTx(ctx, func(q *db.Queries) error {
		row, err := q.LockApprovalRequest(ctx, db.LockApprovalRequestParams{ID: approvalID})
		if errors.Is(err, pgx.ErrNoRows) {
			return apierr.New("NOT_FOUND", "approval request was not found")
		}
		if err != nil {
			return err
		}
		if row.Status != "pending" || !row.ExpiresAt.Time.After(time.Now().UTC()) {
			return apierr.New("CONFLICT", "approval request is no longer pending")
		}
		currentOwnerID, err := s.Authorization.TopHumanOwnerTx(ctx, q, row.AgentMemberID)
		if err != nil {
			return err
		}
		if currentOwnerID != row.ApproverMemberID {
			return apierr.New("PERMISSION_DENIED", "the approval owner has changed")
		}
		user, err := q.GetUserByID(ctx, db.GetUserByIDParams{ID: userID})
		if errors.Is(err, pgx.ErrNoRows) || err == nil && (user.Status != "active" || user.DisabledAt.Valid) {
			return apierr.New("ACTOR_USER_INACTIVE", "the approver account is unavailable")
		}
		if err != nil {
			return err
		}
		owner, err := q.GetMemberForAuthorization(ctx, db.GetMemberForAuthorizationParams{ID: row.ApproverMemberID})
		if errors.Is(err, pgx.ErrNoRows) || err == nil && (owner.Type != "human" || owner.Status != "active") {
			return apierr.New("OWNER_INACTIVE", "the approval owner is unavailable")
		}
		if err != nil {
			return err
		}
		binding, err := q.GetUserMemberBinding(ctx, db.GetUserMemberBindingParams{UserID: userID, MemberID: owner.ID})
		if errors.Is(err, pgx.ErrNoRows) || err == nil && (binding.Status != "active" || binding.RevokedAt.Valid || binding.ExpiresAt.Valid && !binding.ExpiresAt.Time.After(time.Now().UTC())) {
			return apierr.New("PERMISSION_DENIED", "the user is not an approver for this request")
		}
		if err != nil {
			return err
		}
		if err := s.StepUp.ConsumeStepUpTx(ctx, q); err != nil {
			return err
		}
		status := "rejected"
		if approve {
			status = "approved"
		}
		decided, err = q.DecideApprovalRequest(ctx, db.DecideApprovalRequestParams{
			ID: approvalID, Status: status, UserID: nullableText(userID),
		})
		if err != nil {
			return err
		}
		return audit.Write(ctx, q, "user", userID, "approval."+status, approvalID, "success")
	})
	if err != nil {
		return Request{}, err
	}
	return publicRequest(decided), nil
}

func nullableText(value string) pgtype.Text {
	return pgtype.Text{String: value, Valid: value != ""}
}

func publicRequest(row db.ApprovalRequest) Request {
	return Request{
		ID: row.ID, Kind: row.Kind, AgentMemberID: row.AgentMemberID, Action: row.PermissionKey,
		Resource: Resource{Type: row.ResourceType, ID: row.ResourceID, SpaceID: row.ResourceSpaceID,
			GroupID: row.ResourceGroupID.String, OwnerMemberID: row.ResourceOwnerMemberID.String},
		Operation: row.Operation.String, RequestDetails: json.RawMessage(row.RequestDetails),
		RequestDigest: hex.EncodeToString(row.RequestDigest), Reason: row.Reason,
		Status: row.Status, ExpiresAt: row.ExpiresAt.Time, CreatedAt: row.CreatedAt.Time,
	}
}
