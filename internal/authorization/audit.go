package authorization

import (
	"context"
	"encoding/base64"
	"errors"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/plystra/auth/internal/apierr"
	"github.com/plystra/auth/internal/audit"
	"github.com/plystra/auth/internal/authz/engine"
	"github.com/plystra/auth/internal/db"
	"github.com/plystra/auth/internal/ids"
)

type AuditQuery struct {
	SpaceID    string
	GroupID    string
	MemberID   string
	DecisionID string
	RequestID  string
	Action     string
	Cursor     string
	Limit      int
}

type AuditPage struct {
	Events     []audit.Event
	NextCursor string
}

func (s *Service) ListAuditLogs(ctx context.Context, actorID string, in AuditQuery) (AuditPage, error) {
	if s == nil || s.Store == nil {
		return AuditPage{}, apierr.New("UNAVAILABLE", "audit queries are unavailable")
	}
	if in.Limit == 0 {
		in.Limit = 50
	}
	if in.Limit < 1 || in.Limit > 100 || len(in.Cursor) > 512 {
		return AuditPage{}, apierr.New("VALIDATION_FAILED", "limit must be between 1 and 100 and cursor must be valid")
	}
	var out AuditPage
	err := s.Store.InTx(ctx, func(q *db.Queries) error {
		if in.GroupID != "" {
			if _, err := q.GetGroupInSpace(ctx, db.GetGroupInSpaceParams{ID: in.GroupID, SpaceID: in.SpaceID}); err != nil {
				if errors.Is(err, pgx.ErrNoRows) {
					return apierr.New("NOT_FOUND", "audit group was not found in this Space")
				}
				return err
			}
		}
		base := CheckRequest{MemberID: actorID, Permission: "auth.audit:read", ResourceSpace: in.SpaceID, ResourceGroup: in.GroupID}
		decision, err := s.CheckTx(ctx, q, base)
		if err != nil {
			return err
		}
		if in.GroupID != "" && decision.Effect != engine.Allow {
			return &apierr.Error{Code: decision.Code, Message: "The authorization engine denied access to these audit records."}
		}
		groups, err := q.ListAuditGroups(ctx, db.ListAuditGroupsParams{SpaceID: in.SpaceID, GroupID: auditNullableText(in.GroupID)})
		if err != nil {
			return err
		}
		visibleGroups := make([]string, 0, len(groups))
		for _, id := range groups {
			groupRequest := base
			groupRequest.ResourceGroup = id
			groupDecision, err := s.CheckTx(ctx, q, groupRequest)
			if err != nil {
				return err
			}
			if groupDecision.Effect == engine.Allow {
				visibleGroups = append(visibleGroups, id)
			}
		}
		includeSpace := in.GroupID == "" && decision.Effect == engine.Allow
		if !includeSpace && len(visibleGroups) == 0 {
			if decision.Effect == engine.Allow {
				return apierr.New("UNAVAILABLE", "Audit scope changed; restart the query with current authority.")
			}
			return &apierr.Error{Code: decision.Code, Message: "The authorization engine denied access to these audit records."}
		}
		params := db.ListSpaceAuditParams{
			SpaceID: auditNullableText(in.SpaceID), IncludeSpaceEvents: includeSpace, VisibleGroupIds: visibleGroups,
			Action: auditNullableText(in.Action), MemberID: auditNullableText(in.MemberID),
			DecisionID: auditNullableText(in.DecisionID), RequestID: auditNullableText(in.RequestID),
			LimitCount: int32(in.Limit + 1),
		}
		if in.Cursor != "" {
			raw, err := base64.RawURLEncoding.Strict().DecodeString(in.Cursor)
			if err != nil || !ids.AuditID(raw).Valid() || strings.ContainsAny(string(raw), "\x00\r\n") {
				return apierr.New("VALIDATION_FAILED", "audit cursor is invalid for this query")
			}
			cursorAt, err := q.GetSpaceAuditCursor(ctx, db.GetSpaceAuditCursorParams{
				ID: string(raw), SpaceID: auditNullableText(in.SpaceID), IncludeSpaceEvents: includeSpace, VisibleGroupIds: visibleGroups,
			})
			if errors.Is(err, pgx.ErrNoRows) {
				return apierr.New("VALIDATION_FAILED", "audit cursor is invalid for this query")
			}
			if err != nil {
				return err
			}
			params.CursorAt, params.CursorID = cursorAt, auditNullableText(string(raw))
		}
		rows, err := q.ListSpaceAudit(ctx, params)
		if err != nil {
			return err
		}
		if len(rows) > in.Limit {
			rows = rows[:in.Limit]
			out.NextCursor = base64.RawURLEncoding.EncodeToString([]byte(rows[len(rows)-1].ID))
		}
		out.Events = make([]audit.Event, 0, len(rows))
		for _, row := range rows {
			// READ COMMITTED can observe a revocation between collecting visible
			// nodes and reading this page. Recheck each returned node and fail
			// closed rather than returning a page built from obsolete authority.
			rowRequest := base
			rowRequest.ResourceGroup = row.ResourceGroupID.String
			current, err := s.CheckTx(ctx, q, rowRequest)
			if err != nil {
				return err
			}
			if current.Effect != engine.Allow {
				return &apierr.Error{Code: current.Code, Message: "Audit access changed; restart the query with current authority."}
			}
			event, err := audit.EventFromRow(row)
			if err != nil {
				return err
			}
			out.Events = append(out.Events, event)
		}
		return nil
	})
	if err != nil {
		return AuditPage{}, err
	}
	return out, nil
}

func auditNullableText(value string) pgtype.Text {
	return pgtype.Text{String: value, Valid: value != ""}
}
