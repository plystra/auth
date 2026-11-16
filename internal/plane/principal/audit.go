package principal

import (
	"context"

	"github.com/plystra/auth/internal/audit"
	"github.com/plystra/auth/internal/authorization"
)

type auditLogsInput struct {
	Authorization string `header:"Authorization"`
	ID            string `path:"id"`
	GroupID       string `query:"group_id" maxLength:"128"`
	MemberID      string `query:"member_id" maxLength:"128"`
	DecisionID    string `query:"decision_id" maxLength:"128"`
	RequestID     string `query:"request_id" maxLength:"128"`
	Action        string `query:"action" maxLength:"128"`
	Cursor        string `query:"cursor" maxLength:"512"`
	Limit         int    `query:"limit" default:"50" minimum:"1" maximum:"100"`
}

type auditLogsOutput struct {
	Body struct {
		Data       []audit.Event `json:"data"`
		NextCursor string        `json:"next_cursor,omitempty"`
	}
}

func (a *API) listAuditLogs(ctx context.Context, in *auditLogsInput) (*auditLogsOutput, error) {
	actor, ctx, err := a.resolvePrincipalMember(ctx, in.Authorization, in.ID)
	if err != nil {
		return nil, err
	}
	page, err := a.Authorization.ListAuditLogs(ctx, actor.ID, authorization.AuditQuery{
		SpaceID: in.ID, GroupID: in.GroupID, MemberID: in.MemberID,
		DecisionID: in.DecisionID, RequestID: in.RequestID, Action: in.Action,
		Cursor: in.Cursor, Limit: in.Limit,
	})
	if err != nil {
		return nil, err
	}
	out := &auditLogsOutput{}
	out.Body.Data, out.Body.NextCursor = page.Events, page.NextCursor
	return out, nil
}
