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
		if err := lockAuthorizationMembersTx(ctx, q, actorMemberID, holderMemberID); err != nil {
			return err
		}
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
		if actor.Type == "application" || holder.Type == "application" {
			return apierr.New("AUTHORITY_DELTA_NOT_COVERED", "assignment-right delegation requires human authority coverage")
		}
		if holder.Status != "active" {
			return apierr.New("CONFLICT", "assignment-right holder is not active")
		}
		anchorSpace, anchorGroup, err := assignmentAnchorTx(ctx, q, spaceID, anchorSpaceID, anchorGroupID)
		if err != nil {
			return err
		}
		if err := lockAuthorizationNodesTx(ctx, q, anchorSpace, anchorGroup, actor.SpaceID, holder.SpaceID, spaceID); err != nil {
			return err
		}
		if err := s.authorizeAssignmentRightTx(ctx, q, actorMemberID, anchorSpace, anchorGroup); err != nil {
			return err
		}
		if err := s.consumeStepUpTx(ctx, q); err != nil {
			return err
		}
		if err := holderCoversAnchorTx(ctx, q, holder.SpaceID, anchorSpace); err != nil {
			return err
		}
		if err := validateDelegablePermissionsTx(ctx, q, anchorSpace, anchorGroup, permissions, holder.Type, actor.Type == "agent"); err != nil {
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
		if expiresAt != nil {
			candidate.ExpiresAt = expiresAt.UTC()
		}
		parentID, parentExpiry, err := findCoveringAssignmentRight(parentRows, actorMemberID, actor.SpaceID, candidate, graph)
		if err != nil {
			return err
		}
		if actor.Type == "agent" {
			if err := s.requireOwnerAssignmentCoverageTx(ctx, q, actorMemberID, candidate, graph, expiresAt); err != nil {
				return err
			}
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
		version, err := q.BumpPolicyVersion(ctx, db.BumpPolicyVersionParams{ID: anchorSpace})
		if err != nil {
			return err
		}
		if err := audit.WriteSecurityEvent(ctx, q, audit.SecurityEvent{
			ActorType: "member", ActorID: actorMemberID, MemberID: actorMemberID,
			Action: "assign_right.create", Outcome: "success", Permission: "auth.assign_rights:manage", PolicyVersion: version,
			Resource: audit.Resource{Type: "assign_right", ID: row.ID, SpaceID: anchorSpace, GroupID: anchorGroup},
			Metadata: map[string]string{"holder_member_id": row.HolderMemberID, "parent_assignment_right_id": row.ParentID.String},
		}); err != nil {
			return err
		}
		out = assignmentRightFromRow(row, permissions)
		return nil
	})
	return out, err
}

// G8: an Agent may use an assignment right only while every owner in its
// chain still has a covering right. This keeps delegated authority bounded by
// the owner's current authority without copying owner state onto the Agent.
func (s *Service) requireOwnerAssignmentCoverageTx(ctx context.Context, q *db.Queries, agentMemberID string, candidate delta.Right, graph delta.Graph, expiresAt *time.Time) error {
	current := agentMemberID
	seen := map[string]struct{}{}
	for depth := 0; depth <= s.maxDelegationDepth(); depth++ {
		if _, ok := seen[current]; ok {
			return apierr.New("OWNER_INACTIVE", "the Agent owner chain contains a cycle")
		}
		seen[current] = struct{}{}
		member, err := q.GetMemberForAuthorization(ctx, db.GetMemberForAuthorizationParams{ID: current})
		if err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return apierr.New("OWNER_INACTIVE", "the Agent owner member was not found")
			}
			return err
		}
		if member.Status != "active" {
			return apierr.New("OWNER_INACTIVE", "the Agent owner member is not active")
		}
		if member.Type != "agent" {
			return nil
		}
		agent, err := q.GetAgentMember(ctx, db.GetAgentMemberParams{MemberID: member.ID})
		if err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return apierr.New("OWNER_INACTIVE", "the Agent owner record was not found")
			}
			return err
		}
		if !agent.OwnerMemberID.Valid || agent.OwnerMemberID.String == "" {
			return apierr.New("OWNER_INACTIVE", "the Agent owner is missing")
		}
		owner, err := q.GetMemberForAuthorization(ctx, db.GetMemberForAuthorizationParams{ID: agent.OwnerMemberID.String})
		if err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return apierr.New("OWNER_INACTIVE", "the Agent owner member was not found")
			}
			return err
		}
		if owner.Status != "active" {
			return apierr.New("OWNER_INACTIVE", "the Agent owner member is not active")
		}
		rows, err := q.LockActiveAssignRightsForHolder(ctx, db.LockActiveAssignRightsForHolderParams{HolderMemberID: owner.ID})
		if err != nil {
			return err
		}
		if err := addCoverageSpaceTx(ctx, q, owner.SpaceID, &graph); err != nil {
			return err
		}
		_, ownerExpiry, covered, err := coveringAssignmentRight(rows, owner.ID, owner.SpaceID, candidate, graph)
		if err != nil {
			return err
		}
		if !covered {
			return &apierr.Error{Code: "AUTHORITY_DELTA_NOT_COVERED", Message: "The Agent assignment right exceeds its owner's delegation authority.", Details: map[string]string{"uncovered": strings.Join(candidate.Permissions, ",")}}
		}
		if ownerExpiry.Valid && (expiresAt == nil || expiresAt.After(ownerExpiry.Time)) {
			return apierr.New("VALIDATION_FAILED", "assignment right cannot outlive its owner authority")
		}
		if owner.Type != "agent" {
			return nil
		}
		current = owner.ID
	}
	return apierr.New("OWNER_INACTIVE", "the Agent owner chain exceeds the maximum depth")
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
		holder, err := q.GetMemberForAuthorization(ctx, db.GetMemberForAuthorizationParams{ID: row.HolderMemberID})
		if errors.Is(err, pgx.ErrNoRows) {
			return apierr.New("OWNER_INACTIVE", "assignment-right holder was not found")
		}
		if err != nil {
			return err
		}
		if err := lockAuthorizationMembersTx(ctx, q, actorMemberID, row.HolderMemberID); err != nil {
			return err
		}
		if err := lockAuthorizationNodesTx(ctx, q, anchorSpace, row.AnchorGroupID.String, holder.SpaceID, spaceID); err != nil {
			return err
		}
		row, err = q.LockAssignRight(ctx, db.LockAssignRightParams{ID: rightID})
		if errors.Is(err, pgx.ErrNoRows) {
			return apierr.New("NOT_FOUND", "assignment right was not found")
		}
		if err != nil {
			return err
		}
		if err := s.authorizeAssignmentRightTx(ctx, q, actorMemberID, anchorSpace, row.AnchorGroupID.String); err != nil {
			return err
		}
		if err := s.consumeStepUpTx(ctx, q); err != nil {
			return err
		}
		if err := q.RevokeAssignRight(ctx, db.RevokeAssignRightParams{ID: rightID}); err != nil {
			return err
		}
		version, err := q.BumpPolicyVersion(ctx, db.BumpPolicyVersionParams{ID: anchorSpace})
		if err != nil {
			return err
		}
		return audit.WriteSecurityEvent(ctx, q, audit.SecurityEvent{
			ActorType: "member", ActorID: actorMemberID, MemberID: actorMemberID,
			Action: "assign_right.revoke", Outcome: "success", Permission: "auth.assign_rights:manage", PolicyVersion: version,
			Resource: audit.Resource{Type: "assign_right", ID: rightID, SpaceID: anchorSpace, GroupID: row.AnchorGroupID.String},
			Metadata: map[string]string{"holder_member_id": row.HolderMemberID, "parent_assignment_right_id": row.ParentID.String},
		})
	})
}

// ListAssignmentRights returns active, non-expired rights anchored directly
// in the requested Space or in one of its groups. Authorization is performed
// by the caller against the requested Space before this display-only read.
func (s *Service) ListAssignmentRights(ctx context.Context, spaceID string) ([]AssignmentRight, error) {
	var rows []db.AssignRight
	err := s.Store.InTx(ctx, func(q *db.Queries) error {
		if err := s.consumeStepUpTx(ctx, q); err != nil {
			return err
		}
		var err error
		rows, err = q.ListAssignRightsInSpace(ctx, db.ListAssignRightsInSpaceParams{SpaceID: pgtype.Text{String: spaceID, Valid: true}})
		return err
	})
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
	if err := lockAuthorizationMembersTx(ctx, q, actorMemberID); err != nil {
		return err
	}
	if err := lockAuthorizationNodesTx(ctx, q, anchorSpaceID, anchorGroupID); err != nil {
		return err
	}
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

func validateDelegablePermissionsTx(ctx context.Context, q *db.Queries, anchorSpaceID, anchorGroupID string, permissions []string, holderType string, actorIsAgent bool) error {
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
		var principalKinds []string
		if err := json.Unmarshal(permission.PrincipalKinds, &principalKinds); err != nil {
			return err
		}
		if holderType != "" && len(principalKinds) > 0 && !slices.Contains(principalKinds, holderType) {
			return apierr.New("PRINCIPAL_KIND_NOT_ALLOWED", "the permission cannot be delegated to this member type")
		}
		if actorIsAgent && holderType == "agent" && permission.AgentApproval == "required" {
			return apierr.New("AUTHORITY_DELTA_NOT_COVERED", "Agent approval-required permissions cannot be delegated to a child Agent")
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
	id, expiry, covered, err := coveringAssignmentRight(rows, actorID, actorSpaceID, candidate, graph)
	if err != nil {
		return "", pgtype.Timestamptz{}, err
	}
	if !covered {
		return "", pgtype.Timestamptz{}, &apierr.Error{Code: "AUTHORITY_DELTA_NOT_COVERED", Message: "The assignment right exceeds the administrator's delegation authority.", Details: map[string]string{"uncovered": strings.Join(candidate.Permissions, ",")}}
	}
	return id, expiry, nil
}

func coveringAssignmentRight(rows []db.AssignRight, actorID, actorSpaceID string, candidate delta.Right, graph delta.Graph) (string, pgtype.Timestamptz, bool, error) {
	for _, row := range rows {
		keys := []string{}
		if err := json.Unmarshal(row.PermissionKeys, &keys); err != nil {
			return "", pgtype.Timestamptz{}, false, err
		}
		parent := delta.Right{Holder: actorID, Position: delta.Node{Kind: delta.Space, ID: actorSpaceID}, Permissions: keys, Descendants: row.CoversSubtree, Delegate: row.CanRedelegate}
		if row.ExpiresAt.Valid {
			parent.ExpiresAt = row.ExpiresAt.Time.UTC()
		}
		if row.AnchorSpaceID.Valid {
			parent.Anchor = delta.Node{Kind: delta.Space, ID: row.AnchorSpaceID.String}
		} else if row.AnchorGroupID.Valid {
			parent.Anchor = delta.Node{Kind: delta.Group, ID: row.AnchorGroupID.String}
		}
		covered, err := delta.CoversAssignmentRight(parent, candidate, graph)
		if err != nil {
			return "", pgtype.Timestamptz{}, false, err
		}
		if covered {
			return row.ID, row.ExpiresAt, true, nil
		}
	}
	return "", pgtype.Timestamptz{}, false, nil
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
