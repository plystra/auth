package authorization

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/plystra/auth/internal/apierr"
	"github.com/plystra/auth/internal/audit"
	"github.com/plystra/auth/internal/authz/delta"
	"github.com/plystra/auth/internal/authz/engine"
	"github.com/plystra/auth/internal/db"
	"github.com/plystra/auth/internal/ids"
)

type AssignmentRight struct {
	ID             string    `json:"id"`
	HolderMemberID string    `json:"holder_member_id"`
	Permissions    []string  `json:"permissions"`
	AnchorSpaceID  string    `json:"anchor_space_id,omitempty"`
	AnchorGroupID  string    `json:"anchor_group_id,omitempty"`
	CoversSubtree  bool      `json:"covers_subtree"`
	CanRedelegate  bool      `json:"can_redelegate"`
	Source         string    `json:"source"`
	ParentID       string    `json:"parent_id,omitempty"`
	ExpiresAt      time.Time `json:"expires_at,omitempty"`
}

func (s *Service) CreateAssignmentRight(ctx context.Context, actorMemberID, spaceID, holderMemberID string, permissions []string, anchorSpaceID, anchorGroupID string, coversSubtree, canRedelegate bool, expiresAt *time.Time) (AssignmentRight, error) {
	permissions = uniqueSorted(permissions)
	if len(permissions) == 0 || len(permissions) > 256 || strings.TrimSpace(holderMemberID) == "" {
		return AssignmentRight{}, apierr.New("VALIDATION_FAILED", "assignment right fields are invalid")
	}
	if anchorSpaceID == "" && anchorGroupID == "" {
		anchorSpaceID = spaceID
	}
	if (anchorSpaceID == "") == (anchorGroupID == "") {
		return AssignmentRight{}, apierr.New("VALIDATION_FAILED", "exactly one assignment-right anchor is required")
	}
	now := time.Now().UTC()
	if expiresAt != nil && !expiresAt.After(now) {
		return AssignmentRight{}, apierr.New("VALIDATION_FAILED", "assignment right must expire in the future")
	}
	var out AssignmentRight
	err := s.Store.InTx(ctx, func(q *db.Queries) error {
		actor, err := q.GetMemberForAuthorization(ctx, db.GetMemberForAuthorizationParams{ID: actorMemberID})
		if err != nil {
			return err
		}
		holder, err := q.GetMemberForAuthorization(ctx, db.GetMemberForAuthorizationParams{ID: holderMemberID})
		if errors.Is(err, pgx.ErrNoRows) {
			return apierr.New("NOT_FOUND", "assignment-right holder was not found")
		}
		if err != nil {
			return err
		}
		if actor.Type != "human" || holder.Type == "application" {
			return apierr.New("AUTHORITY_DELTA_NOT_COVERED", "assignment-right delegation requires human authority coverage")
		}
		if holder.Status != "active" {
			return apierr.New("CONFLICT", "assignment-right holder is not active")
		}
		anchorSpace, anchorGroup, err := assignmentAnchorTx(ctx, q, spaceID, anchorSpaceID, anchorGroupID)
		if err != nil {
			return err
		}
		if err := s.authorizeAssignmentRightTx(ctx, q, actorMemberID, anchorSpace, anchorGroup); err != nil {
			return err
		}
		if err := holderCoversAnchorTx(ctx, q, holder.SpaceID, anchorSpace); err != nil {
			return err
		}
		if err := validateDelegablePermissionsTx(ctx, q, anchorSpace, anchorGroup, permissions); err != nil {
			return err
		}
		storedAnchorSpace := anchorSpace
		if anchorGroup != "" {
			storedAnchorSpace = ""
		}
		graph := delta.Graph{SpaceParent: map[string]string{}, GroupParent: map[string]string{}, GroupSpace: map[string]string{}}
		if err := addCoverageSpaceTx(ctx, q, actor.SpaceID, &graph); err != nil {
			return err
		}
		if err := addCoverageSpaceTx(ctx, q, anchorSpace, &graph); err != nil {
			return err
		}
		if anchorGroup != "" {
			if err := addCoverageGroupTx(ctx, q, anchorGroup, anchorSpace, &graph); err != nil {
				return err
			}
		}
		parentRows, err := q.LockActiveAssignRightsForHolder(ctx, db.LockActiveAssignRightsForHolderParams{HolderMemberID: actorMemberID})
		if err != nil {
			return err
		}
		candidate := delta.Right{Holder: holderMemberID, Position: delta.Node{Kind: delta.Space, ID: holder.SpaceID}, Permissions: permissions, Anchor: assignmentAnchorNode(anchorSpace, anchorGroup), Descendants: coversSubtree, Delegate: canRedelegate}
		parentID, parentExpiry, err := findCoveringAssignmentRight(parentRows, actorMemberID, actor.SpaceID, candidate, graph)
		if err != nil {
			return err
		}
		if parentExpiry.Valid && (expiresAt == nil || expiresAt.After(parentExpiry.Time)) {
			return apierr.New("VALIDATION_FAILED", "assignment right cannot outlive its parent")
		}
		encoded, err := json.Marshal(permissions)
		if err != nil {
			return err
		}
		row, err := q.CreateAssignRight(ctx, db.CreateAssignRightParams{
			ID: string(ids.New[ids.AssignRightID]("ar")), HolderMemberID: holderMemberID, PermissionKeys: encoded,
			AnchorSpaceID: nullableText(storedAnchorSpace), AnchorGroupID: nullableText(anchorGroup),
			CoversSubtree: coversSubtree, CanRedelegate: canRedelegate, Source: "delegated", ParentID: nullableText(parentID),
			GrantedByOperatorUserID: pgtype.Text{}, ExpiresAt: nullableTime(expiresAt),
		})
		if err != nil {
			return normalizeDBError(err)
		}
		if _, err := q.BumpPolicyVersion(ctx, db.BumpPolicyVersionParams{ID: anchorSpace}); err != nil {
			return err
		}
		if err := audit.Write(ctx, q, "member", actorMemberID, "assign_right.create", row.ID, "success"); err != nil {
			return err
		}
		out = assignmentRightFromRow(row, permissions)
		return nil
	})
	return out, err
}

func (s *Service) RevokeAssignmentRight(ctx context.Context, actorMemberID, spaceID, rightID string) error {
	return s.Store.InTx(ctx, func(q *db.Queries) error {
		row, err := q.GetAssignRight(ctx, db.GetAssignRightParams{ID: rightID})
		if errors.Is(err, pgx.ErrNoRows) {
			return apierr.New("NOT_FOUND", "assignment right was not found")
		}
		if err != nil {
			return err
		}
		if row.AnchorSpaceID.Valid {
			if row.AnchorSpaceID.String != spaceID {
				return apierr.New("NOT_FOUND", "assignment right was not found in this Space")
			}
		} else if row.AnchorGroupID.Valid {
			if _, groupErr := q.GetGroupInSpace(ctx, db.GetGroupInSpaceParams{ID: row.AnchorGroupID.String, SpaceID: spaceID}); errors.Is(groupErr, pgx.ErrNoRows) {
				return apierr.New("NOT_FOUND", "assignment right was not found in this Space")
			} else if groupErr != nil {
				return groupErr
			}
		}
		anchorSpace := spaceID
		if row.AnchorSpaceID.Valid {
			anchorSpace = row.AnchorSpaceID.String
		}
		if err := s.authorizeAssignmentRightTx(ctx, q, actorMemberID, anchorSpace, row.AnchorGroupID.String); err != nil {
			return err
		}
		if err := q.RevokeAssignRight(ctx, db.RevokeAssignRightParams{ID: rightID}); err != nil {
			return err
		}
		if _, err := q.BumpPolicyVersion(ctx, db.BumpPolicyVersionParams{ID: anchorSpace}); err != nil {
			return err
		}
		return audit.Write(ctx, q, "member", actorMemberID, "assign_right.revoke", rightID, "success")
	})
}

// ListAssignmentRights returns active, non-expired rights anchored directly
// in the requested Space or in one of its groups. Authorization is performed
// by the caller against the requested Space before this display-only read.
func (s *Service) ListAssignmentRights(ctx context.Context, spaceID string) ([]AssignmentRight, error) {
	rows, err := s.Store.Queries().ListAssignRightsInSpace(ctx, db.ListAssignRightsInSpaceParams{SpaceID: pgtype.Text{String: spaceID, Valid: true}})
	if err != nil {
		return nil, err
	}
	out := make([]AssignmentRight, 0, len(rows))
	for _, row := range rows {
		var permissions []string
		if err := json.Unmarshal(row.PermissionKeys, &permissions); err != nil {
			return nil, err
		}
		out = append(out, assignmentRightFromRow(row, uniqueSorted(permissions)))
	}
	return out, nil
}

func assignmentAnchorTx(ctx context.Context, q *db.Queries, spaceID, anchorSpaceID, anchorGroupID string) (string, string, error) {
	if anchorGroupID != "" {
		group, err := q.GetGroupInSpace(ctx, db.GetGroupInSpaceParams{ID: anchorGroupID, SpaceID: spaceID})
		if errors.Is(err, pgx.ErrNoRows) {
			return "", "", apierr.New("NOT_FOUND", "assignment-right group anchor was not found")
		}
		if err != nil {
			return "", "", err
		}
		if group.Status != "active" {
			return "", "", apierr.New("CONFLICT", "assignment-right group anchor is not active")
		}
		return spaceID, anchorGroupID, nil
	}
	if err := addActiveSpaceCheck(ctx, q, anchorSpaceID); err != nil {
		return "", "", err
	}
	return anchorSpaceID, "", nil
}

func addActiveSpaceCheck(ctx context.Context, q *db.Queries, spaceID string) error {
	if _, err := spaceAncestorsQueries(ctx, q, spaceID); err != nil {
		if errors.Is(err, errSpaceInactive) {
			return apierr.New("CONFLICT", "assignment-right Space anchor is not active")
		}
		return err
	}
	return nil
}

func (s *Service) authorizeAssignmentRightTx(ctx context.Context, q *db.Queries, actorMemberID, anchorSpaceID, anchorGroupID string) error {
	decision, err := s.CheckTx(ctx, q, CheckRequest{MemberID: actorMemberID, Permission: "auth.assign_rights:manage", ResourceSpace: anchorSpaceID, ResourceGroup: anchorGroupID})
	if err != nil {
		return err
	}
	if decision.Effect != engine.Allow {
		return &apierr.Error{Code: decision.Code, Message: "The authorization engine denied this operation.", Details: map[string]string{"permission": "auth.assign_rights:manage"}}
	}
	return nil
}

func holderCoversAnchorTx(ctx context.Context, q *db.Queries, holderSpaceID, anchorSpaceID string) error {
	ancestors, err := spaceAncestorsQueries(ctx, q, anchorSpaceID)
	if err != nil {
		return err
	}
	if holderSpaceID != anchorSpaceID && !slices.Contains(ancestors, holderSpaceID) {
		return apierr.New("SCOPE_OUT_OF_BOUNDS", "assignment-right holder is outside the anchor Space chain")
	}
	return nil
}

func validateDelegablePermissionsTx(ctx context.Context, q *db.Queries, anchorSpaceID, anchorGroupID string, permissions []string) error {
	envelopes := newEnvelopeFacts(q)
	node := delta.Node{Kind: delta.Space, ID: anchorSpaceID}
	if anchorGroupID != "" {
		node = delta.Node{Kind: delta.Group, ID: anchorGroupID}
	}
	for _, key := range permissions {
		permission, err := q.GetPermissionByKey(ctx, db.GetPermissionByKeyParams{Key: key})
		if errors.Is(err, pgx.ErrNoRows) {
			return apierr.New("UNKNOWN_PERMISSION", "permission is not registered")
		}
		if err != nil {
			return err
		}
		if permission.Status != "active" || !permission.Delegable {
			return apierr.New("PERMISSION_OUTSIDE_ENVELOPE", "permission cannot be delegated")
		}
		mode, err := envelopes.grantMode(ctx, node, anchorSpaceID, key, permission.Delegable)
		if err != nil {
			return err
		}
		if mode < 3 {
			return apierr.New("PERMISSION_OUTSIDE_ENVELOPE", "permission is not delegable in the anchor envelope")
		}
	}
	return nil
}

func findCoveringAssignmentRight(rows []db.AssignRight, actorID, actorSpaceID string, candidate delta.Right, graph delta.Graph) (string, pgtype.Timestamptz, error) {
	for _, row := range rows {
		keys := []string{}
		if err := json.Unmarshal(row.PermissionKeys, &keys); err != nil {
			return "", pgtype.Timestamptz{}, err
		}
		parent := delta.Right{Holder: actorID, Position: delta.Node{Kind: delta.Space, ID: actorSpaceID}, Permissions: keys, Descendants: row.CoversSubtree, Delegate: row.CanRedelegate}
		if row.AnchorSpaceID.Valid {
			parent.Anchor = delta.Node{Kind: delta.Space, ID: row.AnchorSpaceID.String}
		} else if row.AnchorGroupID.Valid {
			parent.Anchor = delta.Node{Kind: delta.Group, ID: row.AnchorGroupID.String}
		}
		covered, err := delta.CoversAssignmentRight(parent, candidate, graph)
		if err != nil {
			return "", pgtype.Timestamptz{}, err
		}
		if covered {
			return row.ID, row.ExpiresAt, nil
		}
	}
	return "", pgtype.Timestamptz{}, &apierr.Error{Code: "AUTHORITY_DELTA_NOT_COVERED", Message: "The assignment right exceeds the administrator's delegation authority.", Details: map[string]string{"uncovered": strings.Join(candidate.Permissions, ",")}}
}

func assignmentAnchorNode(spaceID, groupID string) delta.Node {
	if groupID != "" {
		return delta.Node{Kind: delta.Group, ID: groupID}
	}
	return delta.Node{Kind: delta.Space, ID: spaceID}
}

func nullableText(value string) pgtype.Text {
	return pgtype.Text{String: value, Valid: value != ""}
}

func nullableTime(value *time.Time) pgtype.Timestamptz {
	if value == nil {
		return pgtype.Timestamptz{}
	}
	return pgtype.Timestamptz{Time: value.UTC(), Valid: true}
}

func assignmentRightFromRow(row db.AssignRight, permissions []string) AssignmentRight {
	out := AssignmentRight{ID: row.ID, HolderMemberID: row.HolderMemberID, Permissions: slices.Clone(permissions), CoversSubtree: row.CoversSubtree, CanRedelegate: row.CanRedelegate, Source: row.Source}
	if row.AnchorSpaceID.Valid {
		out.AnchorSpaceID = row.AnchorSpaceID.String
	}
	if row.AnchorGroupID.Valid {
		out.AnchorGroupID = row.AnchorGroupID.String
	}
	if row.ParentID.Valid {
		out.ParentID = row.ParentID.String
	}
	if row.ExpiresAt.Valid {
		out.ExpiresAt = row.ExpiresAt.Time.UTC()
	}
	return out
}
