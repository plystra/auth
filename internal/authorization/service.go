package authorization

import (
	"context"
	"encoding/json"
	"errors"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/plystra/auth/internal/apierr"
	"github.com/plystra/auth/internal/audit"
	"github.com/plystra/auth/internal/authz/engine"
	"github.com/plystra/auth/internal/db"
	"github.com/plystra/auth/internal/ids"
	"github.com/plystra/auth/internal/store"
)

var slugPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{1,62}[a-z0-9]$`)

var errSpaceInactive = errors.New("Space or ancestor is inactive")
var errGroupInactive = errors.New("group or ancestor is inactive")

type Service struct{ Store *store.Store }

// CheckRequest describes the persisted facts needed by the authorization
// engine. Callers provide only the subject and resource identity; the service
// resolves member type, grants, scope ancestry, and Agent ownership from the
// database before invoking engine.Check.
type CheckRequest struct {
	MemberID      string
	Permission    string
	ResourceSpace string
	ResourceGroup string
	ResourceOwner string
}

// Check is the single authorization decision entry point shared by all
// interaction planes and state-changing services.
func (s *Service) Check(ctx context.Context, in CheckRequest) (engine.Decision, int64, error) {
	return s.checkQueries(ctx, s.Store.Queries(), in, 0)
}

// CheckTx evaluates the same decision using an existing business transaction.
// It keeps authorization and the mutation on the same database snapshot.
func (s *Service) CheckTx(ctx context.Context, q *db.Queries, in CheckRequest) (engine.Decision, error) {
	decision, _, err := s.checkQueries(ctx, q, in, 0)
	return decision, err
}

func (s *Service) checkQueries(ctx context.Context, q *db.Queries, in CheckRequest, depth int) (engine.Decision, int64, error) {
	if strings.TrimSpace(in.MemberID) == "" || strings.TrimSpace(in.Permission) == "" {
		return engine.Decision{Effect: engine.Deny, Code: "INVALID_SUBJECT"}, 0, nil
	}
	permission, permissionErr := q.GetPermissionByKey(ctx, db.GetPermissionByKeyParams{Key: in.Permission})
	if errors.Is(permissionErr, pgx.ErrNoRows) {
		return engine.Decision{Effect: engine.Deny, Code: "UNKNOWN_PERMISSION"}, 0, nil
	}
	if permissionErr != nil {
		return engine.Decision{}, 0, permissionErr
	}
	if permission.Status == "disabled" {
		return engine.Decision{Effect: engine.Deny, Code: "PERMISSION_DISABLED"}, 0, nil
	}
	if depth > 8 {
		return engine.Decision{Effect: engine.Deny, Code: "OWNER_INACTIVE"}, 0, nil
	}
	member, err := q.GetMemberForAuthorization(ctx, db.GetMemberForAuthorizationParams{ID: in.MemberID})
	if errors.Is(err, pgx.ErrNoRows) {
		return engine.Decision{Effect: engine.Deny, Code: "ACTOR_MEMBER_INACTIVE"}, 0, nil
	}
	if err != nil {
		return engine.Decision{}, 0, err
	}
	if member.Status != "active" {
		return engine.Decision{Effect: engine.Deny, Code: "ACTOR_MEMBER_INACTIVE"}, 0, nil
	}
	if _, err := spaceAncestorsQueries(ctx, q, member.SpaceID); err != nil {
		if errors.Is(err, errSpaceInactive) {
			return engine.Decision{Effect: engine.Deny, Code: "SPACE_INACTIVE"}, 0, nil
		}
		return engine.Decision{}, 0, err
	}
	if in.ResourceSpace == "" {
		in.ResourceSpace = member.SpaceID
	}
	space, err := q.GetSpace(ctx, db.GetSpaceParams{ID: in.ResourceSpace})
	if errors.Is(err, pgx.ErrNoRows) {
		return engine.Decision{Effect: engine.Deny, Code: "SPACE_INACTIVE"}, 0, nil
	}
	if err != nil {
		return engine.Decision{}, 0, err
	}
	spaceAncestors, err := spaceAncestorsQueries(ctx, q, in.ResourceSpace)
	if err != nil {
		if errors.Is(err, errSpaceInactive) {
			return engine.Decision{Effect: engine.Deny, Code: "SPACE_INACTIVE"}, space.PolicyVersion, nil
		}
		return engine.Decision{}, 0, err
	}
	var groupAncestors []string
	if in.ResourceGroup != "" {
		group, groupErr := q.GetGroupInSpace(ctx, db.GetGroupInSpaceParams{ID: in.ResourceGroup, SpaceID: in.ResourceSpace})
		if errors.Is(groupErr, pgx.ErrNoRows) {
			return engine.Decision{Effect: engine.Deny, Code: "RESOURCE_GROUP_NOT_FOUND"}, space.PolicyVersion, nil
		}
		if groupErr != nil {
			return engine.Decision{}, 0, groupErr
		}
		if group.Status != "active" {
			return engine.Decision{Effect: engine.Deny, Code: "RESOURCE_GROUP_INACTIVE"}, space.PolicyVersion, nil
		}
		groupAncestors, err = groupAncestorsQueries(ctx, q, in.ResourceGroup, in.ResourceSpace)
		if err != nil {
			if errors.Is(err, errGroupInactive) {
				return engine.Decision{Effect: engine.Deny, Code: "RESOURCE_GROUP_INACTIVE"}, space.PolicyVersion, nil
			}
			return engine.Decision{}, 0, err
		}
	}
	assignments, _, err := s.assignmentsQueries(ctx, q, in.MemberID)
	if err != nil {
		return engine.Decision{}, 0, err
	}
	request := engine.Request{
		MemberID:               in.MemberID,
		PrincipalType:          member.Type,
		Permission:             in.Permission,
		ResourceSpace:          in.ResourceSpace,
		ResourceSpaceAncestors: spaceAncestors,
		ResourceGroup:          in.ResourceGroup,
		ResourceGroupAncestors: groupAncestors,
		ResourceOwner:          in.ResourceOwner,
		Assignments:            assignments,
	}
	// G12 must load a verified, single-use approval from Auth state before
	// setting ApprovalValid. Callers cannot assert approval as a request fact.
	if in.ResourceOwner != "" && in.ResourceOwner != in.MemberID {
		owned, ownerErr := q.CanManageAgent(ctx, db.CanManageAgentParams{OwnerMemberID: in.MemberID, TargetMemberID: in.ResourceOwner})
		if ownerErr != nil {
			return engine.Decision{}, 0, ownerErr
		}
		if owned {
			request.SelfOwners = []string{in.ResourceOwner}
		}
	}
	if member.Type == "agent" {
		owner, ownerErr := q.GetAgentMember(ctx, db.GetAgentMemberParams{MemberID: in.MemberID})
		if ownerErr != nil && !errors.Is(ownerErr, pgx.ErrNoRows) {
			return engine.Decision{}, 0, ownerErr
		}
		if ownerErr == nil && owner.OwnerMemberID.Valid && owner.OwnerMemberID.String != "" {
			// Rebuild the owner request from the same persisted facts. The owner
			// decision itself is intentionally recomputed by engine.Check so the
			// Agent result preserves OWNER_ENVELOPE_EXCLUDED.
			ownerRequest, buildErr := s.ownerRequestQueries(ctx, q, owner.OwnerMemberID.String, in, depth+1)
			if buildErr != nil {
				return engine.Decision{}, 0, buildErr
			}
			request.Owner = ownerRequest
		}
	}
	return engine.Check(request), space.PolicyVersion, nil
}

func (s *Service) ownerRequestQueries(ctx context.Context, q *db.Queries, memberID string, in CheckRequest, depth int) (*engine.Request, error) {
	if depth > 8 {
		return nil, nil
	}
	member, err := q.GetMemberForAuthorization(ctx, db.GetMemberForAuthorizationParams{ID: memberID})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if member.Status != "active" {
		return nil, nil
	}
	if _, err := spaceAncestorsQueries(ctx, q, member.SpaceID); err != nil {
		if errors.Is(err, errSpaceInactive) {
			return nil, nil
		}
		return nil, err
	}
	assignments, _, err := s.assignmentsQueries(ctx, q, memberID)
	if err != nil {
		return nil, err
	}
	spaceAncestors, err := spaceAncestorsQueries(ctx, q, in.ResourceSpace)
	if err != nil {
		return nil, err
	}
	var groupAncestors []string
	if in.ResourceGroup != "" {
		groupAncestors, err = groupAncestorsQueries(ctx, q, in.ResourceGroup, in.ResourceSpace)
		if err != nil {
			return nil, err
		}
	}
	request := &engine.Request{MemberID: memberID, PrincipalType: member.Type, Permission: in.Permission, ResourceSpace: in.ResourceSpace, ResourceSpaceAncestors: spaceAncestors, ResourceGroup: in.ResourceGroup, ResourceGroupAncestors: groupAncestors, ResourceOwner: in.ResourceOwner, Assignments: assignments, SkipApproval: true}
	if in.ResourceOwner != "" && in.ResourceOwner != memberID {
		owned, ownerErr := q.CanManageAgent(ctx, db.CanManageAgentParams{OwnerMemberID: memberID, TargetMemberID: in.ResourceOwner})
		if ownerErr != nil {
			return nil, ownerErr
		}
		if owned {
			request.SelfOwners = []string{in.ResourceOwner}
		}
	}
	if member.Type == "agent" {
		owner, ownerErr := q.GetAgentMember(ctx, db.GetAgentMemberParams{MemberID: memberID})
		if ownerErr != nil && !errors.Is(ownerErr, pgx.ErrNoRows) {
			return nil, ownerErr
		}
		if ownerErr == nil && owner.OwnerMemberID.Valid && owner.OwnerMemberID.String != "" {
			request.Owner, err = s.ownerRequestQueries(ctx, q, owner.OwnerMemberID.String, in, depth+1)
			if err != nil {
				return nil, err
			}
		}
	}
	return request, nil
}

func spaceAncestorsQueries(ctx context.Context, q *db.Queries, spaceID string) ([]string, error) {
	ancestors := make([]string, 0, 4)
	seen := map[string]struct{}{spaceID: {}}
	current := spaceID
	for len(ancestors) < 64 {
		space, err := q.GetSpace(ctx, db.GetSpaceParams{ID: current})
		if err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return nil, errSpaceInactive
			}
			return nil, err
		}
		if space.Status != "active" {
			return nil, errSpaceInactive
		}
		if !space.ParentID.Valid || space.ParentID.String == "" {
			return ancestors, nil
		}
		parent := space.ParentID.String
		if _, ok := seen[parent]; ok {
			return nil, apierr.New("INVALID_RESOURCE", "Space hierarchy contains a cycle")
		}
		seen[parent] = struct{}{}
		ancestors = append(ancestors, parent)
		current = parent
	}
	return nil, apierr.New("INVALID_RESOURCE", "Space hierarchy is too deep")
}

func groupAncestorsQueries(ctx context.Context, q *db.Queries, groupID, spaceID string) ([]string, error) {
	ancestors := make([]string, 0, 4)
	seen := map[string]struct{}{groupID: {}}
	current := groupID
	for len(ancestors) < 64 {
		group, err := q.GetGroupInSpace(ctx, db.GetGroupInSpaceParams{ID: current, SpaceID: spaceID})
		if err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return nil, errGroupInactive
			}
			return nil, err
		}
		if group.Status != "active" {
			return nil, errGroupInactive
		}
		if !group.ParentID.Valid || group.ParentID.String == "" {
			return ancestors, nil
		}
		parent := group.ParentID.String
		if _, ok := seen[parent]; ok {
			return nil, apierr.New("INVALID_RESOURCE", "group hierarchy contains a cycle")
		}
		seen[parent] = struct{}{}
		ancestors = append(ancestors, parent)
		current = parent
	}
	return nil, apierr.New("INVALID_RESOURCE", "group hierarchy is too deep")
}

type Space struct {
	ID            string `json:"id"`
	Name          string `json:"name"`
	Slug          string `json:"slug"`
	ParentID      string `json:"parent_id,omitempty"`
	Status        string `json:"status"`
	PolicyVersion int64  `json:"policy_version"`
}

type Member struct {
	ID            string `json:"id"`
	SpaceID       string `json:"space_id"`
	Name          string `json:"name"`
	Kind          string `json:"type"`
	BindingPolicy string `json:"binding_policy"`
	Status        string `json:"status"`
}

type Binding struct {
	UserID    string `json:"user_id"`
	MemberID  string `json:"member_id"`
	Email     string `json:"email"`
	Status    string `json:"status"`
	ExpiresAt string `json:"expires_at,omitempty"`
}

type Role struct {
	ID          string   `json:"id"`
	SpaceID     string   `json:"space_id"`
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Managed     bool     `json:"managed"`
	Permissions []string `json:"permissions"`
}

type Grant struct {
	ID              string   `json:"id"`
	SpaceID         string   `json:"space_id"`
	RoleID          string   `json:"role_id"`
	Permissions     []string `json:"permissions,omitempty"`
	GranteeMemberID string   `json:"grantee_member_id"`
	Scope           string   `json:"scope"`
	AnchorSpaceID   string   `json:"anchor_space_id,omitempty"`
	GrantedBy       string   `json:"granted_by"`
}

// EffectivePermission is a display-only view of a permission that is both
// granted to a member and usable in the listed scope. It is never used as an
// authorization input; every operation still calls Check.
type EffectivePermission struct {
	Permission string `json:"permission"`
	Scope      string `json:"scope"`
	Anchor     string `json:"anchor,omitempty"`
	Role       string `json:"role,omitempty"`
}

var administratorPermissions = []string{
	"self:read",
	"auth.spaces:manage",
	"auth.members:read",
	"auth.members:manage",
	"auth.bindings:manage",
	"auth.roles:manage",
	"auth.grants:assign",
	"auth.assign_rights:manage",
	"auth.envelopes:manage",
	"auth.audit:read",
	"auth.authz:check",
	"auth.tokens:introspect",
}

func (s *Service) CreateSpace(ctx context.Context, userID, name, slug string) (Space, Member, error) {
	return s.createSpace(ctx, userID, userID, "human", userID, name, slug)
}

// CreateSpaceByAgent creates the administrator member as a human member bound
// to the Agent's owner account. The Agent is the audited actor, while the
// resulting membership stays within the normal one-Space-per-member model.
func (s *Service) CreateSpaceByAgent(ctx context.Context, actorMemberID, ownerUserID, name, slug string) (Space, Member, error) {
	return s.createSpace(ctx, ownerUserID, actorMemberID, "agent", actorMemberID, name, slug)
}

func (s *Service) createSpace(ctx context.Context, userID, grantedBy, actorType, actorID, name, slug string) (Space, Member, error) {
	name = strings.TrimSpace(name)
	slug = strings.ToLower(strings.TrimSpace(slug))
	if name == "" || len(name) > 128 || !slugPattern.MatchString(slug) {
		return Space{}, Member{}, apierr.New("VALIDATION_FAILED", "name and slug are invalid")
	}
	var outSpace Space
	var outMember Member
	err := s.Store.InTx(ctx, func(q *db.Queries) error {
		spaceRow, err := q.CreateSpace(ctx, db.CreateSpaceParams{ID: string(ids.New[ids.SpaceID]("spc")), Name: name, Slug: slug})
		if err != nil {
			return normalizeDBError(err)
		}
		memberRow, err := q.CreateMemberWithPolicy(ctx, db.CreateMemberWithPolicyParams{
			ID: string(ids.New[ids.MemberID]("mem")), SpaceID: spaceRow.ID, Name: name, Type: "human", BindingPolicy: "single",
		})
		if err != nil {
			return err
		}
		if err := q.LinkUserMember(ctx, db.LinkUserMemberParams{UserID: userID, MemberID: memberRow.ID}); err != nil {
			return err
		}
		role, err := q.CreateRole(ctx, db.CreateRoleParams{ID: string(ids.New[ids.RoleID]("rol")), SpaceID: spaceRow.ID, Name: "administrator", Description: "Space administrator", Managed: true})
		if err != nil {
			return err
		}
		if err := addRolePermissions(ctx, q, role.ID, administratorPermissions); err != nil {
			return err
		}
		if _, err := q.CreateGrant(ctx, db.CreateGrantParams{
			ID: string(ids.New[ids.GrantID]("grt")), SpaceID: spaceRow.ID, RoleID: pgtype.Text{String: role.ID, Valid: true},
			GranteeMemberID: pgtype.Text{String: memberRow.ID, Valid: true}, Scope: "space",
			AnchorGroupID: pgtype.Text{},
			AnchorSpaceID: pgtype.Text{String: spaceRow.ID, Valid: true}, GrantedBy: grantedBy,
		}); err != nil {
			return err
		}
		if err := audit.Write(ctx, q, actorType, actorID, "space.create", spaceRow.ID, "success"); err != nil {
			return err
		}
		outSpace = toSpace(spaceRow)
		outMember = Member{ID: memberRow.ID, SpaceID: memberRow.SpaceID, Name: memberRow.Name, Kind: memberRow.Type, BindingPolicy: memberRow.BindingPolicy, Status: memberRow.Status}
		return nil
	})
	return outSpace, outMember, err
}

func (s *Service) GetSpace(ctx context.Context, id string) (Space, error) {
	row, err := s.Store.Queries().GetSpace(ctx, db.GetSpaceParams{ID: id})
	if errors.Is(err, pgx.ErrNoRows) {
		return Space{}, apierr.New("NOT_FOUND", "Space was not found")
	}
	if err != nil {
		return Space{}, err
	}
	return toSpace(row), nil
}

func (s *Service) ListChildren(ctx context.Context, id string) ([]Space, error) {
	rows, err := s.Store.Queries().ListChildSpaces(ctx, db.ListChildSpacesParams{ParentID: pgtype.Text{String: id, Valid: true}})
	if err != nil {
		return nil, err
	}
	out := make([]Space, 0, len(rows))
	for _, row := range rows {
		out = append(out, toSpace(row))
	}
	return out, nil
}

func (s *Service) GetMemberForUser(ctx context.Context, userID, spaceID string) (Member, error) {
	row, err := s.Store.Queries().GetMemberForUser(ctx, db.GetMemberForUserParams{UserID: userID, SpaceID: spaceID})
	if errors.Is(err, pgx.ErrNoRows) {
		return Member{}, apierr.New("PERMISSION_DENIED", "The current user is not a member of this Space.")
	}
	if err != nil {
		return Member{}, err
	}
	return Member{ID: row.ID, SpaceID: row.SpaceID, Name: row.Name, Kind: row.Type, BindingPolicy: row.BindingPolicy, Status: row.Status}, nil
}

// ListMembersForUser returns the user's active, unexpired member bindings
// across all Spaces. Revoked bindings and inactive members are omitted by the
// query so callers cannot accidentally expose stale identities.
func (s *Service) ListMembersForUser(ctx context.Context, userID, memberType string) ([]Member, error) {
	if memberType != "" && memberType != "human" && memberType != "agent" && memberType != "application" {
		return nil, apierr.New("VALIDATION_FAILED", "type must be human, agent, or application")
	}
	if memberType == "" {
		rows, err := s.Store.Queries().ListMembersForUser(ctx, db.ListMembersForUserParams{UserID: userID})
		if err != nil {
			return nil, err
		}
		out := make([]Member, 0, len(rows))
		for _, row := range rows {
			out = append(out, Member{ID: row.ID, SpaceID: row.SpaceID, Name: row.Name, Kind: row.Type, BindingPolicy: row.BindingPolicy, Status: row.Status})
		}
		return out, nil
	}
	rows, err := s.Store.Queries().ListMembersForUserByType(ctx, db.ListMembersForUserByTypeParams{UserID: userID, MemberType: memberType})
	if err != nil {
		return nil, err
	}
	out := make([]Member, 0, len(rows))
	for _, row := range rows {
		out = append(out, Member{ID: row.ID, SpaceID: row.SpaceID, Name: row.Name, Kind: row.Type, BindingPolicy: row.BindingPolicy, Status: row.Status})
	}
	return out, nil
}

func (s *Service) GetMember(ctx context.Context, memberID, spaceID string) (Member, error) {
	row, err := s.Store.Queries().GetMemberInSpace(ctx, db.GetMemberInSpaceParams{ID: memberID, SpaceID: spaceID})
	if errors.Is(err, pgx.ErrNoRows) {
		return Member{}, apierr.New("SUBJECT_NOT_FOUND", "The subject is not a member of the requested Space.")
	}
	if err != nil {
		return Member{}, err
	}
	if row.Status != "active" {
		return Member{}, apierr.New("ACTOR_MEMBER_INACTIVE", "The member is not active.")
	}
	return Member{ID: row.ID, SpaceID: row.SpaceID, Name: row.Name, Kind: row.Type, BindingPolicy: row.BindingPolicy, Status: row.Status}, nil
}

// GetMemberAnySpace resolves a live member without treating the requested
// resource Space as the member's home Space. The authorization engine applies
// the ancestor and scope rules after this lookup.
func (s *Service) GetMemberAnySpace(ctx context.Context, memberID string) (Member, error) {
	row, err := s.Store.Queries().GetMemberForAuthorization(ctx, db.GetMemberForAuthorizationParams{ID: memberID})
	if errors.Is(err, pgx.ErrNoRows) {
		return Member{}, apierr.New("SUBJECT_NOT_FOUND", "The subject member was not found.")
	}
	if err != nil {
		return Member{}, err
	}
	if row.Status != "active" {
		return Member{}, apierr.New("ACTOR_MEMBER_INACTIVE", "The member is not active.")
	}
	return Member{ID: row.ID, SpaceID: row.SpaceID, Name: row.Name, Kind: row.Type, BindingPolicy: row.BindingPolicy, Status: row.Status}, nil
}

// OwnerUserID resolves the active user at the top of a member's Agent
// ownership chain. It is used only for operations whose result must create a
// user-bound member, such as creating a new Space on behalf of an Agent.
func (s *Service) OwnerUserID(ctx context.Context, memberID string) (string, error) {
	current := strings.TrimSpace(memberID)
	seen := map[string]struct{}{}
	for depth := 0; depth <= 8; depth++ {
		if current == "" {
			return "", apierr.New("OWNER_INACTIVE", "the owner chain is incomplete")
		}
		if _, ok := seen[current]; ok {
			return "", apierr.New("OWNER_INACTIVE", "the owner chain contains a cycle")
		}
		seen[current] = struct{}{}
		member, err := s.Store.Queries().GetMemberForAuthorization(ctx, db.GetMemberForAuthorizationParams{ID: current})
		if errors.Is(err, pgx.ErrNoRows) {
			return "", apierr.New("OWNER_INACTIVE", "the owner member was not found")
		}
		if err != nil {
			return "", err
		}
		if member.Status != "active" {
			return "", apierr.New("OWNER_INACTIVE", "the owner member is not active")
		}
		if member.Type == "human" {
			bindings, err := s.Store.Queries().ListMemberBindings(ctx, db.ListMemberBindingsParams{MemberID: current})
			if err != nil {
				return "", err
			}
			ownerUserID := ""
			for _, binding := range bindings {
				if binding.Status != "active" || binding.RevokedAt.Valid || (binding.ExpiresAt.Valid && !binding.ExpiresAt.Time.After(time.Now().UTC())) {
					continue
				}
				user, userErr := s.Store.Queries().GetUserByID(ctx, db.GetUserByIDParams{ID: binding.UserID})
				if errors.Is(userErr, pgx.ErrNoRows) {
					continue
				}
				if userErr != nil {
					return "", userErr
				}
				if user.Status != "active" {
					continue
				}
				if ownerUserID != "" {
					return "", apierr.New("USER_ACCOUNT_REQUIRED", "the Agent owner has multiple active user accounts")
				}
				ownerUserID = binding.UserID
			}
			if ownerUserID == "" {
				return "", apierr.New("USER_ACCOUNT_REQUIRED", "the Agent owner has no active user account")
			}
			return ownerUserID, nil
		}
		if member.Type != "agent" {
			return "", apierr.New("USER_ACCOUNT_REQUIRED", "the Agent owner chain does not end in a user account")
		}
		agent, agentErr := s.Store.Queries().GetAgentMember(ctx, db.GetAgentMemberParams{MemberID: current})
		if errors.Is(agentErr, pgx.ErrNoRows) {
			return "", apierr.New("OWNER_INACTIVE", "the Agent owner record was not found")
		}
		if agentErr != nil {
			return "", agentErr
		}
		if !agent.OwnerMemberID.Valid || agent.OwnerMemberID.String == "" {
			return "", apierr.New("OWNER_INACTIVE", "the Agent owner is missing")
		}
		current = agent.OwnerMemberID.String
	}
	return "", apierr.New("OWNER_INACTIVE", "the owner chain exceeds the maximum depth")
}

// ResourceGroupForMember resolves the persisted resource node used when a
// management action targets a member. A member in several groups has no
// unique group resource node, so whole-member operations use its Space node.
func (s *Service) ResourceGroupForMember(ctx context.Context, memberID, spaceID string) (string, error) {
	q := s.Store.Queries()
	if _, err := q.GetMemberInSpace(ctx, db.GetMemberInSpaceParams{ID: memberID, SpaceID: spaceID}); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return "", apierr.New("SUBJECT_NOT_FOUND", "The target member is not in the requested Space.")
		}
		return "", err
	}
	groups, err := q.ListMemberGroups(ctx, db.ListMemberGroupsParams{MemberID: memberID, SpaceID: spaceID})
	if err != nil || len(groups) != 1 {
		return "", err
	}
	return groups[0].ID, nil
}

func (s *Service) UserBoundToMember(ctx context.Context, userID, memberID string) (bool, error) {
	row, err := s.Store.Queries().GetUserMemberBinding(ctx, db.GetUserMemberBindingParams{UserID: userID, MemberID: memberID})
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return row.Status == "active" && !row.RevokedAt.Valid && (!row.ExpiresAt.Valid || row.ExpiresAt.Time.After(time.Now().UTC())), nil
}

func (s *Service) PolicyVersion(ctx context.Context, spaceID string) (int64, error) {
	row, err := s.Store.Queries().GetSpace(ctx, db.GetSpaceParams{ID: spaceID})
	if errors.Is(err, pgx.ErrNoRows) {
		return 0, apierr.New("NOT_FOUND", "Space was not found")
	}
	return row.PolicyVersion, err
}

// EnsureDefaultMembershipTx is part of the caller's registration transaction.
func (s *Service) EnsureDefaultMembershipTx(ctx context.Context, q *db.Queries, userID, displayName string) (string, error) {
	if existing, err := q.GetMemberForUser(ctx, db.GetMemberForUserParams{UserID: userID, SpaceID: "spc_01h00000000000000000000000"}); err == nil {
		return existing.ID, nil
	} else if !errors.Is(err, pgx.ErrNoRows) {
		return "", err
	}
	member, err := q.CreateMemberWithPolicy(ctx, db.CreateMemberWithPolicyParams{
		ID: string(ids.New[ids.MemberID]("mem")), SpaceID: "spc_01h00000000000000000000000", Name: displayName, Type: "human", BindingPolicy: "single",
	})
	if err != nil {
		return "", err
	}
	if err := q.LinkUserMember(ctx, db.LinkUserMemberParams{UserID: userID, MemberID: member.ID}); err != nil {
		return "", err
	}
	role, err := q.GetRoleInSpace(ctx, db.GetRoleInSpaceParams{ID: "rol_01h00000000000000000000001", SpaceID: "spc_01h00000000000000000000000"})
	if err != nil {
		return "", err
	}
	if _, err := q.CreateGrant(ctx, db.CreateGrantParams{ID: string(ids.New[ids.GrantID]("grt")), SpaceID: role.SpaceID, RoleID: pgtype.Text{String: role.ID, Valid: true}, GranteeMemberID: pgtype.Text{String: member.ID, Valid: true}, Scope: "space", AnchorGroupID: pgtype.Text{}, AnchorSpaceID: pgtype.Text{String: role.SpaceID, Valid: true}, GrantedBy: "system"}); err != nil {
		return "", err
	}
	if err := audit.Write(ctx, q, "system", "system", "member.default_bind", member.ID, "success"); err != nil {
		return "", err
	}
	return member.ID, nil
}

func (s *Service) ListMembers(ctx context.Context, spaceID string) ([]Member, error) {
	rows, err := s.Store.Queries().ListMembersInSpace(ctx, db.ListMembersInSpaceParams{SpaceID: spaceID})
	if err != nil {
		return nil, err
	}
	out := make([]Member, 0, len(rows))
	for _, row := range rows {
		out = append(out, Member{ID: row.ID, SpaceID: row.SpaceID, Name: row.Name, Kind: row.Type, BindingPolicy: row.BindingPolicy, Status: row.Status})
	}
	return out, nil
}

func (s *Service) CreateMember(ctx context.Context, actorMemberID, userID, spaceID, name, kind, bindingPolicy string) (Member, error) {
	name = strings.TrimSpace(name)
	if kind == "user" {
		kind = "human"
	}
	if kind == "service" {
		kind = "application"
	}
	if name == "" || len(name) > 128 || kind != "human" || (bindingPolicy != "single" && bindingPolicy != "shared") {
		return Member{}, apierr.New("VALIDATION_FAILED", "member fields are invalid")
	}
	var out Member
	err := s.Store.InTx(ctx, func(q *db.Queries) error {
		if err := s.authorizeTx(ctx, q, actorMemberID, "auth.members:manage", spaceID); err != nil {
			return err
		}
		memberRow, err := q.CreateMemberWithPolicy(ctx, db.CreateMemberWithPolicyParams{ID: string(ids.New[ids.MemberID]("mem")), SpaceID: spaceID, Name: name, Type: kind, BindingPolicy: bindingPolicy})
		if err != nil {
			return err
		}
		if userID != "" {
			if kind != "human" {
				return apierr.New("VALIDATION_FAILED", "only human members can bind a user")
			}
			if err := q.LinkUserMember(ctx, db.LinkUserMemberParams{UserID: userID, MemberID: memberRow.ID}); err != nil {
				return err
			}
		}
		if err := audit.Write(ctx, q, "member", actorMemberID, "member.create", memberRow.ID, "success"); err != nil {
			return err
		}
		out = Member{ID: memberRow.ID, SpaceID: memberRow.SpaceID, Name: memberRow.Name, Kind: memberRow.Type, BindingPolicy: memberRow.BindingPolicy, Status: memberRow.Status}
		return nil
	})
	return out, err
}

func (s *Service) ListBindings(ctx context.Context, memberID string) ([]Binding, error) {
	rows, err := s.Store.Queries().ListMemberBindings(ctx, db.ListMemberBindingsParams{MemberID: memberID})
	if err != nil {
		return nil, err
	}
	out := make([]Binding, 0, len(rows))
	for _, row := range rows {
		binding := Binding{UserID: row.UserID, MemberID: row.MemberID, Email: row.Email, Status: row.Status}
		if row.ExpiresAt.Valid {
			binding.ExpiresAt = row.ExpiresAt.Time.UTC().Format("2006-01-02T15:04:05Z07:00")
		}
		out = append(out, binding)
	}
	return out, nil
}

func (s *Service) BindUser(ctx context.Context, actorMemberID, spaceID, memberID, userID string) error {
	if userID == "" {
		return apierr.New("VALIDATION_FAILED", "user_id is required")
	}
	return s.Store.InTx(ctx, func(q *db.Queries) error {
		if err := s.authorizeTargetTx(ctx, q, actorMemberID, "auth.bindings:manage", spaceID, memberID); err != nil {
			return err
		}
		member, err := q.LockMemberInSpace(ctx, db.LockMemberInSpaceParams{ID: memberID, SpaceID: spaceID})
		if err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return apierr.New("NOT_FOUND", "member was not found in this Space")
			}
			return err
		}
		if member.Status != "active" {
			return apierr.New("CONFLICT", "member is not active")
		}
		if member.Type != "human" {
			return apierr.New("VALIDATION_FAILED", "only human members can bind a user")
		}
		user, err := q.GetUserByID(ctx, db.GetUserByIDParams{ID: userID})
		if err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return apierr.New("NOT_FOUND", "user was not found")
			}
			return err
		}
		if user.Status != "active" {
			return apierr.New("CONFLICT", "user is not active")
		}
		if err := s.authorityCoverageTx(ctx, q, actorMemberID, memberID); err != nil {
			return err
		}
		count, err := q.CountActiveMemberBindings(ctx, db.CountActiveMemberBindingsParams{MemberID: memberID})
		if err != nil {
			return err
		}
		if member.BindingPolicy == "single" && count > 0 {
			return apierr.New("CONFLICT", "a single-binding member can have only one active user binding")
		}
		if err := q.BindUserMember(ctx, db.BindUserMemberParams{UserID: userID, MemberID: memberID}); err != nil {
			return err
		}
		if _, err := q.BumpPolicyVersion(ctx, db.BumpPolicyVersionParams{ID: spaceID}); err != nil {
			return err
		}
		return audit.Write(ctx, q, "member", actorMemberID, "member.binding.create", memberID, "success")
	})
}

func (s *Service) UnbindUser(ctx context.Context, actorMemberID, spaceID, memberID, userID string) error {
	return s.Store.InTx(ctx, func(q *db.Queries) error {
		if err := s.authorizeTargetTx(ctx, q, actorMemberID, "auth.bindings:manage", spaceID, memberID); err != nil {
			return err
		}
		if _, err := q.GetMemberInSpace(ctx, db.GetMemberInSpaceParams{ID: memberID, SpaceID: spaceID}); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return apierr.New("NOT_FOUND", "member was not found in this Space")
			}
			return err
		}
		binding, err := q.GetUserMemberBinding(ctx, db.GetUserMemberBindingParams{UserID: userID, MemberID: memberID})
		if err != nil || binding.Status != "active" {
			if errors.Is(err, pgx.ErrNoRows) || err == nil {
				return apierr.New("NOT_FOUND", "active user binding was not found")
			}
			return err
		}
		if err := q.RevokeUserMember(ctx, db.RevokeUserMemberParams{UserID: userID, MemberID: memberID}); err != nil {
			return err
		}
		if err := q.RevokeUserSessions(ctx, db.RevokeUserSessionsParams{UserID: userID}); err != nil {
			return err
		}
		if err := q.RevokeUserRefreshTokens(ctx, db.RevokeUserRefreshTokensParams{UserID: userID}); err != nil {
			return err
		}
		if _, err := q.BumpPolicyVersion(ctx, db.BumpPolicyVersionParams{ID: spaceID}); err != nil {
			return err
		}
		return audit.Write(ctx, q, "member", actorMemberID, "member.binding.revoke", memberID, "success")
	})
}

func (s *Service) SetBindingPolicy(ctx context.Context, actorMemberID, spaceID, memberID, policy string) error {
	if policy != "single" && policy != "shared" {
		return apierr.New("VALIDATION_FAILED", "binding_policy must be single or shared")
	}
	return s.Store.InTx(ctx, func(q *db.Queries) error {
		if err := s.authorizeTargetTx(ctx, q, actorMemberID, "auth.bindings:manage", spaceID, memberID); err != nil {
			return err
		}
		member, err := q.LockMemberInSpace(ctx, db.LockMemberInSpaceParams{ID: memberID, SpaceID: spaceID})
		if err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return apierr.New("NOT_FOUND", "member was not found in this Space")
			}
			return err
		}
		if policy == "single" {
			count, err := q.CountActiveMemberBindings(ctx, db.CountActiveMemberBindingsParams{MemberID: memberID})
			if err != nil {
				return err
			}
			if count > 1 {
				return apierr.New("CONFLICT", "cannot make a member single while it has multiple active bindings")
			}
		}
		if err := q.SetMemberBindingPolicy(ctx, db.SetMemberBindingPolicyParams{ID: memberID, SpaceID: spaceID, BindingPolicy: policy}); err != nil {
			return err
		}
		if _, err := q.BumpPolicyVersion(ctx, db.BumpPolicyVersionParams{ID: spaceID}); err != nil {
			return err
		}
		return audit.Write(ctx, q, "member", actorMemberID, "member.binding_policy.update", member.ID, "success")
	})
}

func (s *Service) SetMemberStatus(ctx context.Context, actorMemberID, spaceID, memberID, status string) error {
	if status != "active" && status != "suspended" && status != "removed" {
		return apierr.New("VALIDATION_FAILED", "member status is invalid")
	}
	return s.Store.InTx(ctx, func(q *db.Queries) error {
		if err := s.authorizeTargetTx(ctx, q, actorMemberID, "auth.members:manage", spaceID, memberID); err != nil {
			return err
		}
		if _, err := q.GetMemberInSpace(ctx, db.GetMemberInSpaceParams{ID: memberID, SpaceID: spaceID}); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return apierr.New("NOT_FOUND", "member was not found in this Space")
			}
			return err
		}
		if err := q.SetMemberStatus(ctx, db.SetMemberStatusParams{ID: memberID, SpaceID: spaceID, Status: status}); err != nil {
			return err
		}
		bindings, err := q.ListMemberBindings(ctx, db.ListMemberBindingsParams{MemberID: memberID})
		if err != nil {
			return err
		}
		for _, binding := range bindings {
			if binding.Status == "active" {
				if err := q.RevokeUserSessions(ctx, db.RevokeUserSessionsParams{UserID: binding.UserID}); err != nil {
					return err
				}
				if err := q.RevokeUserRefreshTokens(ctx, db.RevokeUserRefreshTokensParams{UserID: binding.UserID}); err != nil {
					return err
				}
			}
		}
		if _, err := q.BumpPolicyVersion(ctx, db.BumpPolicyVersionParams{ID: spaceID}); err != nil {
			return err
		}
		return audit.Write(ctx, q, "member", actorMemberID, "member.status.update", memberID, "success")
	})
}

func (s *Service) ListRoles(ctx context.Context, spaceID string) ([]Role, error) {
	rows, err := s.Store.Queries().ListRolesInSpace(ctx, db.ListRolesInSpaceParams{SpaceID: spaceID})
	if err != nil {
		return nil, err
	}
	out := make([]Role, 0, len(rows))
	for _, row := range rows {
		permissions, err := s.Store.Queries().ListRolePermissions(ctx, db.ListRolePermissionsParams{RoleID: row.ID})
		if err != nil {
			return nil, err
		}
		keys := make([]string, 0, len(permissions))
		for _, p := range permissions {
			keys = append(keys, p.Key)
		}
		out = append(out, Role{ID: row.ID, SpaceID: row.SpaceID, Name: row.Name, Description: row.Description, Managed: row.Managed, Permissions: keys})
	}
	return out, nil
}

func (s *Service) CreateRole(ctx context.Context, actorMemberID, spaceID, name, description string, permissions []string) (Role, error) {
	name = strings.TrimSpace(name)
	if name == "" || len(name) > 128 || len(permissions) > 256 {
		return Role{}, apierr.New("VALIDATION_FAILED", "role fields are invalid")
	}
	permissions = uniqueSorted(permissions)
	var out Role
	err := s.Store.InTx(ctx, func(q *db.Queries) error {
		if err := s.authorizeTx(ctx, q, actorMemberID, "auth.roles:manage", spaceID); err != nil {
			return err
		}
		row, err := q.CreateRole(ctx, db.CreateRoleParams{ID: string(ids.New[ids.RoleID]("rol")), SpaceID: spaceID, Name: name, Description: description, Managed: false})
		if err != nil {
			return normalizeDBError(err)
		}
		if err := addRolePermissions(ctx, q, row.ID, permissions); err != nil {
			return err
		}
		if _, err := q.BumpPolicyVersion(ctx, db.BumpPolicyVersionParams{ID: spaceID}); err != nil {
			return err
		}
		if err := audit.Write(ctx, q, "member", actorMemberID, "role.create", row.ID, "success"); err != nil {
			return err
		}
		out = Role{ID: row.ID, SpaceID: row.SpaceID, Name: row.Name, Description: row.Description, Managed: row.Managed, Permissions: permissions}
		return nil
	})
	return out, err
}

func (s *Service) CreateGrant(ctx context.Context, actorMemberID, spaceID, granteeMemberID, roleID, scope, anchorSpaceID string) (Grant, error) {
	if scope == "" {
		scope = "space"
	}
	if scope != "self" && scope != "space" && scope != "space_tree" {
		return Grant{}, apierr.New("VALIDATION_FAILED", "only self, space, and space_tree scopes are available for member grants")
	}
	if anchorSpaceID == "" {
		anchorSpaceID = spaceID
	}
	var out Grant
	err := s.Store.InTx(ctx, func(q *db.Queries) error {
		if err := s.authorizeTx(ctx, q, actorMemberID, "auth.grants:assign", spaceID); err != nil {
			return err
		}
		if _, err := q.GetMemberInSpace(ctx, db.GetMemberInSpaceParams{ID: granteeMemberID, SpaceID: spaceID}); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return apierr.New("NOT_FOUND", "grantee member was not found in this Space")
			}
			return err
		}
		role, err := q.GetRoleInSpace(ctx, db.GetRoleInSpaceParams{ID: roleID, SpaceID: spaceID})
		if err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return apierr.New("NOT_FOUND", "role was not found in this Space")
			}
			return err
		}
		rolePermissions, err := q.ListRolePermissions(ctx, db.ListRolePermissionsParams{RoleID: role.ID})
		if err != nil {
			return err
		}
		actorPermissions, err := authorityKeysTx(ctx, q, actorMemberID)
		if err != nil {
			return err
		}
		for _, permission := range rolePermissions {
			if permission.Status != "active" || !actorPermissions[permission.Key] {
				return &apierr.Error{Code: "AUTHORITY_DELTA_NOT_COVERED", Message: "The grant exceeds the actor's current authority.", Details: map[string]string{"permission": permission.Key}}
			}
		}
		row, err := q.CreateGrant(ctx, db.CreateGrantParams{ID: string(ids.New[ids.GrantID]("grt")), SpaceID: spaceID, RoleID: pgtype.Text{String: roleID, Valid: true}, GranteeMemberID: pgtype.Text{String: granteeMemberID, Valid: true}, Scope: scope, AnchorGroupID: pgtype.Text{}, AnchorSpaceID: pgtype.Text{String: anchorSpaceID, Valid: true}, GrantedBy: actorMemberID})
		if err != nil {
			return normalizeDBError(err)
		}
		if _, err := q.BumpPolicyVersion(ctx, db.BumpPolicyVersionParams{ID: spaceID}); err != nil {
			return err
		}
		if err := audit.Write(ctx, q, "member", actorMemberID, "grant.create", row.ID, "success"); err != nil {
			return err
		}
		out = Grant{ID: row.ID, SpaceID: row.SpaceID, RoleID: row.RoleID.String, GranteeMemberID: granteeMemberID, Scope: row.Scope, AnchorSpaceID: anchorSpaceID, GrantedBy: row.GrantedBy}
		return nil
	})
	return out, err
}

// CreateInlineGrant records a permission set directly on one grant. It is
// intentionally separate from named roles so short-lived consent (such as an
// OAuth Agent authorization) does not create or mutate the Space role catalog.
func (s *Service) CreateInlineGrant(ctx context.Context, actorMemberID, spaceID, granteeMemberID string, permissions []string, scope, anchorSpaceID string) (Grant, error) {
	permissions = uniqueSorted(permissions)
	if len(permissions) == 0 || len(permissions) > 256 {
		return Grant{}, apierr.New("VALIDATION_FAILED", "at least one permission is required")
	}
	if scope == "" {
		scope = "space"
	}
	if scope != "self" && scope != "space" && scope != "space_tree" {
		return Grant{}, apierr.New("VALIDATION_FAILED", "only self, space, and space_tree scopes are available for member grants")
	}
	if anchorSpaceID == "" {
		anchorSpaceID = spaceID
	}
	encoded, err := json.Marshal(permissions)
	if err != nil {
		return Grant{}, err
	}
	var out Grant
	err = s.Store.InTx(ctx, func(q *db.Queries) error {
		if err := s.authorizeTx(ctx, q, actorMemberID, "auth.grants:assign", spaceID); err != nil {
			return err
		}
		if _, err := q.GetMemberInSpace(ctx, db.GetMemberInSpaceParams{ID: granteeMemberID, SpaceID: spaceID}); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return apierr.New("NOT_FOUND", "grantee member was not found in this Space")
			}
			return err
		}
		actorPermissions, err := authorityKeysTx(ctx, q, actorMemberID)
		if err != nil {
			return err
		}
		for _, permission := range permissions {
			if !actorPermissions[permission] {
				return &apierr.Error{Code: "AUTHORITY_DELTA_NOT_COVERED", Message: "The grant exceeds the actor's current authority.", Details: map[string]string{"permission": permission}}
			}
		}
		row, err := q.CreateGrant(ctx, db.CreateGrantParams{
			ID: string(ids.New[ids.GrantID]("grt")), SpaceID: spaceID,
			PermissionKeys: encoded, GranteeMemberID: pgtype.Text{String: granteeMemberID, Valid: true},
			Scope: scope, AnchorSpaceID: pgtype.Text{String: anchorSpaceID, Valid: true}, AnchorGroupID: pgtype.Text{}, GrantedBy: actorMemberID,
		})
		if err != nil {
			return normalizeDBError(err)
		}
		if _, err := q.BumpPolicyVersion(ctx, db.BumpPolicyVersionParams{ID: spaceID}); err != nil {
			return err
		}
		if err := audit.Write(ctx, q, "member", actorMemberID, "grant.inline.create", row.ID, "success"); err != nil {
			return err
		}
		out = Grant{ID: row.ID, SpaceID: row.SpaceID, Permissions: permissions, GranteeMemberID: granteeMemberID, Scope: row.Scope, AnchorSpaceID: anchorSpaceID, GrantedBy: row.GrantedBy}
		return nil
	})
	return out, err
}

func (s *Service) RevokeGrant(ctx context.Context, actorMemberID, spaceID, grantID string) error {
	return s.Store.InTx(ctx, func(q *db.Queries) error {
		if err := s.authorizeTx(ctx, q, actorMemberID, "auth.grants:assign", spaceID); err != nil {
			return err
		}
		row, err := q.GetGrantInSpace(ctx, db.GetGrantInSpaceParams{ID: grantID, SpaceID: spaceID})
		if err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return apierr.New("NOT_FOUND", "grant was not found in this Space")
			}
			return err
		}
		if err := q.RevokeGrant(ctx, db.RevokeGrantParams{ID: grantID}); err != nil {
			return err
		}
		if _, err := q.BumpPolicyVersion(ctx, db.BumpPolicyVersionParams{ID: spaceID}); err != nil {
			return err
		}
		return audit.Write(ctx, q, "member", actorMemberID, "grant.revoke", row.ID, "success")
	})
}

func (s *Service) Assignments(ctx context.Context, memberID string) ([]engine.Assignment, int64, error) {
	return s.assignmentsQueries(ctx, s.Store.Queries(), memberID)
}

// ListEffectivePermissions returns the permissions currently usable by a
// member for display in the principal plane. It intentionally evaluates each
// candidate through Check so Agent owner envelopes and directory status have
// the same semantics as every other authorization decision.
func (s *Service) ListEffectivePermissions(ctx context.Context, memberID string) ([]EffectivePermission, error) {
	member, err := s.GetMemberAnySpace(ctx, memberID)
	if err != nil {
		return nil, err
	}
	assignments, _, err := s.Assignments(ctx, memberID)
	if err != nil {
		return nil, err
	}
	out := make([]EffectivePermission, 0)
	seen := make(map[string]struct{})
	for _, assignment := range assignments {
		for _, permission := range assignment.Envelope {
			request := CheckRequest{MemberID: memberID, Permission: permission, ResourceSpace: member.SpaceID}
			switch assignment.Scope.Kind {
			case "self":
				request.ResourceOwner = memberID
			case "group", "group_tree":
				request.ResourceGroup = assignment.Scope.Anchor
			}
			decision, _, err := s.Check(ctx, request)
			if err != nil {
				return nil, err
			}
			if decision.Effect != engine.Allow {
				continue
			}
			key := permission + "\x00" + assignment.Scope.Kind + "\x00" + assignment.Scope.Anchor
			if _, ok := seen[key]; ok {
				continue
			}
			seen[key] = struct{}{}
			out = append(out, EffectivePermission{Permission: permission, Scope: assignment.Scope.Kind, Anchor: assignment.Scope.Anchor, Role: assignment.Role})
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Permission != out[j].Permission {
			return out[i].Permission < out[j].Permission
		}
		if out[i].Scope != out[j].Scope {
			return out[i].Scope < out[j].Scope
		}
		return out[i].Anchor < out[j].Anchor
	})
	return out, nil
}

func (s *Service) assignmentsQueries(ctx context.Context, q *db.Queries, memberID string) ([]engine.Assignment, int64, error) {
	rows, err := q.ListMemberAssignments(ctx, db.ListMemberAssignmentsParams{MemberID: pgtype.Text{String: memberID, Valid: true}})
	if err != nil {
		return nil, 0, err
	}
	if len(rows) == 0 {
		return nil, 0, nil
	}
	member, err := q.GetMemberForAuthorization(ctx, db.GetMemberForAuthorizationParams{ID: memberID})
	if err != nil {
		return nil, 0, err
	}
	envelopes := newEnvelopeFacts(q)
	type aggregate struct {
		assignment engine.Assignment
		seen       map[string]struct{}
	}
	aggs := map[string]*aggregate{}
	var policyVersion int64
	for _, row := range rows {
		permitted, err := envelopes.permitsAssignment(ctx, row, member.SpaceID)
		if err != nil {
			return nil, 0, err
		}
		if row.PolicyVersion > policyVersion {
			policyVersion = row.PolicyVersion
		}
		// Keep each permission's directory facts with that permission. A role
		// can contain entries with different principal kinds or approval rules.
		aggregateKey := row.GrantID + "\x00" + row.PermissionKey
		item := aggs[aggregateKey]
		if item == nil {
			anchor := ""
			if row.AnchorSpaceID.Valid {
				anchor = row.AnchorSpaceID.String
			}
			if row.AnchorGroupID.Valid {
				anchor = row.AnchorGroupID.String
			}
			var principalKinds []string
			_ = json.Unmarshal(row.PrincipalKinds, &principalKinds)
			item = &aggregate{assignment: engine.Assignment{MemberID: memberID, Role: row.RoleName, Scope: engine.Scope{Kind: row.Scope, Anchor: anchor}, EnvelopeEnforced: true, PrincipalKinds: principalKinds, AgentApprovalRequired: row.AgentApproval == "required"}, seen: map[string]struct{}{}}
			aggs[aggregateKey] = item
		}
		if _, ok := item.seen[row.PermissionKey]; !ok {
			item.assignment.Permissions = append(item.assignment.Permissions, row.PermissionKey)
			if permitted {
				item.assignment.Envelope = append(item.assignment.Envelope, row.PermissionKey)
			}
			item.seen[row.PermissionKey] = struct{}{}
		}
	}
	out := make([]engine.Assignment, 0, len(aggs))
	for _, item := range aggs {
		sort.Strings(item.assignment.Permissions)
		out = append(out, item.assignment)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Role < out[j].Role })
	return out, policyVersion, nil
}

func addRolePermissions(ctx context.Context, q *db.Queries, roleID string, keys []string) error {
	for _, key := range keys {
		permission, err := q.GetPermissionByKey(ctx, db.GetPermissionByKeyParams{Key: key})
		if err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return &apierr.Error{Code: "UNKNOWN_PERMISSION", Message: "The permission is not registered.", Details: map[string]string{"permission": key}}
			}
			return err
		}
		if err := q.GrantRolePermission(ctx, db.GrantRolePermissionParams{RoleID: roleID, PermissionID: permission.ID}); err != nil {
			return err
		}
	}
	return nil
}

func (s *Service) authorizeTx(ctx context.Context, q *db.Queries, memberID, permission, spaceID string) error {
	decision, err := s.CheckTx(ctx, q, CheckRequest{MemberID: memberID, Permission: permission, ResourceSpace: spaceID})
	if err != nil {
		return err
	}
	if decision.Effect == engine.Allow {
		return nil
	}
	return &apierr.Error{Code: decision.Code, Message: "The authorization engine denied this operation.", Details: map[string]string{"permission": permission}}
}

func (s *Service) authorizeTargetTx(ctx context.Context, q *db.Queries, actorMemberID, permission, spaceID, targetMemberID string) error {
	groupID, err := resourceGroupForMemberTx(ctx, q, targetMemberID, spaceID)
	if err != nil {
		return err
	}
	decision, err := s.CheckTx(ctx, q, CheckRequest{
		MemberID: actorMemberID, Permission: permission, ResourceSpace: spaceID, ResourceGroup: groupID,
	})
	if err != nil {
		return err
	}
	if decision.Effect == engine.Allow {
		return nil
	}
	return &apierr.Error{Code: decision.Code, Message: "The authorization engine denied this operation.", Details: map[string]string{"permission": permission}}
}

func resourceGroupForMemberTx(ctx context.Context, q *db.Queries, memberID, spaceID string) (string, error) {
	if _, err := q.GetMemberInSpace(ctx, db.GetMemberInSpaceParams{ID: memberID, SpaceID: spaceID}); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return "", apierr.New("NOT_FOUND", "member was not found in this Space")
		}
		return "", err
	}
	groups, err := q.ListMemberGroups(ctx, db.ListMemberGroupsParams{MemberID: memberID, SpaceID: spaceID})
	if err != nil || len(groups) != 1 {
		return "", err
	}
	return groups[0].ID, nil
}

// authorityCoverageTx is the temporary G8 compatibility check for binding
// authority deltas (see auth-docs/roadmap.md, G8 "权威增量求值器"). The
// authoritative incremental evaluator will replace this key-only comparison;
// all ordinary permission decisions already use Check.
func (s *Service) authorityCoverageTx(ctx context.Context, q *db.Queries, actorMemberID, targetMemberID string) error {
	actor, err := authorityKeysTx(ctx, q, actorMemberID)
	if err != nil {
		return err
	}
	target, err := authorityKeysTx(ctx, q, targetMemberID)
	if err != nil {
		return err
	}
	for permission := range target {
		if !actor[permission] {
			return &apierr.Error{Code: "AUTHORITY_DELTA_NOT_COVERED", Message: "The binding would transfer authority the actor does not hold.", Details: map[string]string{"permission": permission}}
		}
	}
	return nil
}

func authorityKeysTx(ctx context.Context, q *db.Queries, memberID string) (map[string]bool, error) {
	set := map[string]bool{}
	rows, err := q.ListMemberAssignments(ctx, db.ListMemberAssignmentsParams{MemberID: pgtype.Text{String: memberID, Valid: true}})
	if err != nil {
		return nil, err
	}
	for _, row := range rows {
		set[row.PermissionKey] = true
	}
	return set, nil
}

func normalizeDBError(err error) error {
	if err == nil {
		return nil
	}
	message := strings.ToLower(err.Error())
	if strings.Contains(message, "duplicate") || strings.Contains(message, "unique") {
		return apierr.New("CONFLICT", "the resource already exists")
	}
	return err
}

func uniqueSorted(values []string) []string {
	set := make(map[string]struct{}, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value != "" {
			set[value] = struct{}{}
		}
	}
	out := make([]string, 0, len(set))
	for value := range set {
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}

func toSpace(row db.Space) Space {
	out := Space{ID: row.ID, Name: row.Name, Slug: row.Slug, Status: row.Status, PolicyVersion: row.PolicyVersion}
	if row.ParentID.Valid {
		out.ParentID = row.ParentID.String
	}
	return out
}
