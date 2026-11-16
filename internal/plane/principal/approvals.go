package principal

import (
	"context"

	"github.com/danielgtaylor/huma/v2"
	"github.com/plystra/auth/internal/apierr"
	"github.com/plystra/auth/internal/approval"
	"github.com/plystra/auth/internal/route"
)

type listApprovalsInput struct {
	Authorization string `header:"Authorization"`
}

type decideApprovalInput struct {
	Authorization string `header:"Authorization"`
	ID            string `path:"id"`
}

type approvalListOutput struct {
	Body struct {
		Data []approval.InboxRequest `json:"data"`
	}
}

type approvalDecisionOutput struct {
	Body struct {
		Data approval.Request `json:"data"`
	}
}

func (a *API) registerApprovalRoutes(api huma.API) {
	route.Register(api, route.NewSpec("approvals.list", "GET", "/v1/approvals", route.Principal, "", []route.Subject{route.User}), a.listApprovals)
	route.Register(api, route.NewSpec("approvals.approve", "POST", "/v1/approvals/{id}/approve", route.Principal, "", []route.Subject{route.User}, route.WithStepUp()), a.approveApproval)
	route.Register(api, route.NewSpec("approvals.reject", "POST", "/v1/approvals/{id}/reject", route.Principal, "", []route.Subject{route.User}, route.WithStepUp()), a.rejectApproval)
}

func (a *API) listApprovals(ctx context.Context, in *listApprovalsInput) (*approvalListOutput, error) {
	if a.Approvals == nil {
		return nil, apierr.New("UNAVAILABLE", "approvals are unavailable")
	}
	claims, err := a.authenticatePrincipal(ctx, in.Authorization)
	if err != nil {
		return nil, err
	}
	if claims.Type != "user" {
		return nil, apierr.New("USER_ACCOUNT_REQUIRED", "approval requires a user account")
	}
	rows, err := a.Approvals.ListForUser(ctx, claims.Subject)
	if err != nil {
		return nil, err
	}
	out := &approvalListOutput{}
	out.Body.Data = rows
	return out, nil
}

func (a *API) approveApproval(ctx context.Context, in *decideApprovalInput) (*approvalDecisionOutput, error) {
	return a.decideApproval(ctx, in, true)
}

func (a *API) rejectApproval(ctx context.Context, in *decideApprovalInput) (*approvalDecisionOutput, error) {
	return a.decideApproval(ctx, in, false)
}

func (a *API) decideApproval(ctx context.Context, in *decideApprovalInput, approve bool) (*approvalDecisionOutput, error) {
	if a.Approvals == nil {
		return nil, apierr.New("UNAVAILABLE", "approvals are unavailable")
	}
	claims, err := a.authenticatePrincipal(ctx, in.Authorization)
	if err != nil {
		return nil, err
	}
	if claims.Type != "user" {
		return nil, apierr.New("USER_ACCOUNT_REQUIRED", "approval requires a user account")
	}
	operation := "approvals.reject"
	if approve {
		operation = "approvals.approve"
	}
	ctx, err = a.principalStepUpContext(principalAuditContext(ctx, claims), in.Authorization, operation, map[string]any{"approval_id": in.ID})
	if err != nil {
		return nil, err
	}
	decided, err := a.Approvals.Decide(ctx, claims.Subject, in.ID, approve)
	if err != nil {
		return nil, err
	}
	out := &approvalDecisionOutput{}
	out.Body.Data = decided
	return out, nil
}
