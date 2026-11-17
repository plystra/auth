package authorization

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"slices"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/plystra/auth/internal/apierr"
	"github.com/plystra/auth/internal/authz/engine"
	"github.com/plystra/auth/internal/db"
	"github.com/plystra/auth/internal/ids"
)

type GrantQuery struct {
	SpaceID string
	Cursor  string
	Limit   int
}

type GrantPage struct {
	Grants     []Grant
	NextCursor string
}

func (s *Service) ListGrants(ctx context.Context, actorID string, in GrantQuery) (GrantPage, error) {
	if s == nil || s.Store == nil {
		return GrantPage{}, apierr.New("UNAVAILABLE", "grant queries are unavailable")
	}
	if in.Limit == 0 {
		in.Limit = 50
	}
	if in.Limit < 1 || in.Limit > 100 || len(in.Cursor) > 512 {
		return GrantPage{}, apierr.New("VALIDATION_FAILED", "limit must be between 1 and 100 and cursor must be valid")
	}
	var out GrantPage
	err := s.Store.InTx(ctx, func(q *db.Queries) error {
		if err := lockAuthorizationActorTx(ctx, q, actorID); err != nil {
			return err
		}
		// Membership and group writers hold the governing Space. Hold the same
		// lock while resolving recipient positions and selecting the page, so a
		// concurrent move cannot turn an authorized position into a stale filter.
		if err := lockAuthorizationNodesTx(ctx, q, in.SpaceID, ""); err != nil {
			return err
		}
		if err := validateHumanActorTx(ctx, q, actorID); err != nil {
			return err
		}
		base := CheckRequest{MemberID: actorID, Permission: "auth.grants:assign", ResourceSpace: in.SpaceID}
		decision, err := s.CheckTx(ctx, q, base)
		if err != nil {
			return err
		}
		groups, err := q.ListGrantResourceGroups(ctx, db.ListGrantResourceGroupsParams{SpaceID: in.SpaceID})
		if err != nil {
			return err
		}
		assignments, _, err := s.assignmentsQueries(ctx, q, actorID)
		if err != nil {
			return err
		}
		// An authorized group may currently have no grants. Its grant anchor
		// supplies a candidate resource for an empty list, never an allow result.
		for _, assignment := range assignments {
			if slices.Contains(assignment.Permissions, "auth.grants:assign") && (assignment.Scope.Kind == "group" || assignment.Scope.Kind == "group_tree") {
				groups = append(groups, assignment.Scope.Anchor)
			}
		}
		visibleGroups := make([]string, 0, len(groups))
		for _, id := range uniqueSorted(groups) {
			request := base
			request.ResourceGroup = id
			current, err := s.CheckTx(ctx, q, request)
			if err != nil {
				return err
			}
			if current.Effect == engine.Allow {
				visibleGroups = append(visibleGroups, id)
			}
		}
		includeSpace := decision.Effect == engine.Allow
		if !includeSpace && len(visibleGroups) == 0 {
			return &apierr.Error{Code: decision.Code, Message: "The authorization engine denied access to these grants."}
		}
		params := db.ListGrantsInSpaceParams{
			SpaceID: in.SpaceID, IncludeSpaceGrants: includeSpace, VisibleGroupIds: visibleGroups,
			LimitCount: int32(in.Limit + 1),
		}
		if in.Cursor != "" {
			raw, err := base64.RawURLEncoding.Strict().DecodeString(in.Cursor)
			if err != nil || !ids.GrantID(raw).Valid() || strings.ContainsAny(string(raw), "\x00\r\n") {
				return apierr.New("VALIDATION_FAILED", "grant cursor is invalid for this query")
			}
			cursor, err := q.GetGrantInSpace(ctx, db.GetGrantInSpaceParams{ID: string(raw), SpaceID: in.SpaceID})
			if errors.Is(err, pgx.ErrNoRows) {
				return apierr.New("VALIDATION_FAILED", "grant cursor is invalid for this query")
			}
			if err != nil {
				return err
			}
			request := base
			request.ResourceGroup = cursor.GranteeGroupID.String
			if cursor.GranteeMemberID.Valid {
				request.ResourceGroup, err = resourceGroupForMemberTx(ctx, q, cursor.GranteeMemberID.String, in.SpaceID)
				if err != nil {
					return err
				}
			}
			current, err := s.CheckTx(ctx, q, request)
			if err != nil {
				return err
			}
			if current.Effect != engine.Allow {
				return apierr.New("VALIDATION_FAILED", "grant cursor is invalid for this query")
			}
			params.CursorAt, params.CursorID = cursor.CreatedAt, pgtype.Text{String: cursor.ID, Valid: true}
		}
		rows, err := q.ListGrantsInSpace(ctx, params)
		if err != nil {
			return err
		}
		if len(rows) > in.Limit {
			rows = rows[:in.Limit]
			out.NextCursor = base64.RawURLEncoding.EncodeToString([]byte(rows[len(rows)-1].ID))
		}
		out.Grants = make([]Grant, 0, len(rows))
		for _, row := range rows {
			request := base
			request.ResourceGroup = row.ResourceGroupID
			current, err := s.CheckTx(ctx, q, request)
			if err != nil {
				return err
			}
			if current.Effect != engine.Allow {
				return &apierr.Error{Code: current.Code, Message: "Grant access changed; restart the query with current authority."}
			}
			grant := Grant{ID: row.ID, SpaceID: row.SpaceID, RoleID: row.RoleID.String, GranteeMemberID: row.GranteeMemberID.String,
				GranteeGroupID: row.GranteeGroupID.String, Scope: row.Scope, AnchorSpaceID: row.AnchorSpaceID.String,
				AnchorGroupID: row.AnchorGroupID.String, GrantedBy: row.GrantedBy}
			if !row.RoleID.Valid {
				if err := json.Unmarshal(row.PermissionKeys, &grant.Permissions); err != nil {
					return err
				}
			}
			out.Grants = append(out.Grants, grant)
		}
		return nil
	})
	if err != nil {
		return GrantPage{}, err
	}
	return out, nil
}
