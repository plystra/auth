package authorization

import (
	"context"
	"encoding/json"
	"errors"
	"regexp"
	"sort"
	"strings"

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

type Service struct{ Store *store.Store }

type Space struct {
	ID            string `json:"id"`
	Name          string `json:"name"`
	Slug          string `json:"slug"`
	ParentID      string `json:"parent_id,omitempty"`
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
			AnchorSpaceID: pgtype.Text{String: spaceRow.ID, Valid: true}, GrantedBy: userID,
		}); err != nil {
			return err
		}
		if err := audit.Write(ctx, q, "human", userID, "space.create", spaceRow.ID, "success"); err != nil {
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

func (s *Service) PolicyVersion(ctx context.Context, spaceID string) (int64, error) {
	row, err := s.Store.Queries().GetSpace(ctx, db.GetSpaceParams{ID: spaceID})
	if errors.Is(err, pgx.ErrNoRows) {
		return 0, apierr.New("NOT_FOUND", "Space was not found")
	}
	return row.PolicyVersion, err
}

// EnsureDefaultMembership gives a newly registered user the default Space
// identity while keeping the member, role grant, and audit record atomic.
func (s *Service) EnsureDefaultMembership(ctx context.Context, userID, displayName string) error {
	return s.Store.InTx(ctx, func(q *db.Queries) error {
		if _, err := q.GetMemberForUser(ctx, db.GetMemberForUserParams{UserID: userID, SpaceID: "spc_01h00000000000000000000000"}); err == nil {
			return nil
		} else if !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
		member, err := q.CreateMemberWithPolicy(ctx, db.CreateMemberWithPolicyParams{
			ID: string(ids.New[ids.MemberID]("mem")), SpaceID: "spc_01h00000000000000000000000", Name: displayName, Type: "human", BindingPolicy: "single",
		})
		if err != nil {
			return err
		}
		if err := q.LinkUserMember(ctx, db.LinkUserMemberParams{UserID: userID, MemberID: member.ID}); err != nil {
			return err
		}
		role, err := q.GetRoleInSpace(ctx, db.GetRoleInSpaceParams{ID: "rol_01h00000000000000000000001", SpaceID: "spc_01h00000000000000000000000"})
		if err != nil {
			return err
		}
		if _, err := q.CreateGrant(ctx, db.CreateGrantParams{ID: string(ids.New[ids.GrantID]("grt")), SpaceID: role.SpaceID, RoleID: pgtype.Text{String: role.ID, Valid: true}, GranteeMemberID: pgtype.Text{String: member.ID, Valid: true}, Scope: "space", AnchorGroupID: pgtype.Text{}, AnchorSpaceID: pgtype.Text{String: role.SpaceID, Valid: true}, GrantedBy: "system"}); err != nil {
			return err
		}
		return audit.Write(ctx, q, "system", "system", "member.default_bind", member.ID, "success")
	})
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
		if err := requirePermissionTx(ctx, q, actorMemberID, "auth.members:manage"); err != nil {
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
		if err := requirePermissionTx(ctx, q, actorMemberID, "auth.bindings:manage"); err != nil {
			return err
		}
		member, err := q.GetMemberInSpace(ctx, db.GetMemberInSpaceParams{ID: memberID, SpaceID: spaceID})
		if err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return apierr.New("NOT_FOUND", "member was not found in this Space")
			}
			return err
		}
		if member.Status != "active" {
			return apierr.New("CONFLICT", "member is not active")
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
		if err := ensureAuthorityCoverageTx(ctx, q, actorMemberID, memberID); err != nil {
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
		if err := requirePermissionTx(ctx, q, actorMemberID, "auth.bindings:manage"); err != nil {
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
		if err := requirePermissionTx(ctx, q, actorMemberID, "auth.bindings:manage"); err != nil {
			return err
		}
		member, err := q.GetMemberInSpace(ctx, db.GetMemberInSpaceParams{ID: memberID, SpaceID: spaceID})
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
		if err := requirePermissionTx(ctx, q, actorMemberID, "auth.members:manage"); err != nil {
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
		if err := requirePermissionTx(ctx, q, actorMemberID, "auth.roles:manage"); err != nil {
			return err
		}
		actorPermissions, err := permissionSetTx(ctx, q, actorMemberID)
		if err != nil {
			return err
		}
		for _, key := range permissions {
			if !actorPermissions[key] {
				return &apierr.Error{Code: "AUTHORITY_DELTA_NOT_COVERED", Message: "The role would grant a permission the actor does not hold.", Details: map[string]string{"permission": key}}
			}
		}
		row, err := q.CreateRole(ctx, db.CreateRoleParams{ID: string(ids.New[ids.RoleID]("rol")), SpaceID: spaceID, Name: name, Description: description, Managed: false})
		if err != nil {
			return normalizeDBError(err)
		}
		if err := addRolePermissions(ctx, q, row.ID, permissions); err != nil {
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
		if err := requirePermissionTx(ctx, q, actorMemberID, "auth.grants:assign"); err != nil {
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
		actorPermissions, err := permissionSetTx(ctx, q, actorMemberID)
		if err != nil {
			return err
		}
		for _, permission := range rolePermissions {
			if !permission.Enabled || !actorPermissions[permission.Key] {
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
		if err := requirePermissionTx(ctx, q, actorMemberID, "auth.grants:assign"); err != nil {
			return err
		}
		if _, err := q.GetMemberInSpace(ctx, db.GetMemberInSpaceParams{ID: granteeMemberID, SpaceID: spaceID}); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return apierr.New("NOT_FOUND", "grantee member was not found in this Space")
			}
			return err
		}
		actorPermissions, err := permissionSetTx(ctx, q, actorMemberID)
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
		if err := requirePermissionTx(ctx, q, actorMemberID, "auth.grants:assign"); err != nil {
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
	rows, err := s.Store.Queries().ListMemberAssignments(ctx, db.ListMemberAssignmentsParams{MemberID: pgtype.Text{String: memberID, Valid: true}})
	if err != nil {
		return nil, 0, err
	}
	type aggregate struct {
		assignment engine.Assignment
		seen       map[string]struct{}
	}
	aggs := map[string]*aggregate{}
	var policyVersion int64
	for _, row := range rows {
		if row.PolicyVersion > policyVersion {
			policyVersion = row.PolicyVersion
		}
		item := aggs[row.GrantID]
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
			item = &aggregate{assignment: engine.Assignment{MemberID: memberID, Role: row.RoleName, Scope: engine.Scope{Kind: row.Scope, Anchor: anchor}, PrincipalKinds: principalKinds, AgentApprovalRequired: row.AgentApproval == "required"}, seen: map[string]struct{}{}}
			aggs[row.GrantID] = item
		}
		if _, ok := item.seen[row.PermissionKey]; !ok {
			item.assignment.Permissions = append(item.assignment.Permissions, row.PermissionKey)
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

func (s *Service) HasPermission(ctx context.Context, memberID, permission string) (bool, error) {
	assignments, _, err := s.Assignments(ctx, memberID)
	if err != nil {
		return false, err
	}
	for _, assignment := range assignments {
		for _, key := range assignment.Permissions {
			if key == permission {
				return true, nil
			}
		}
	}
	legacy, err := s.Store.Queries().ListMemberPermissions(ctx, db.ListMemberPermissionsParams{MemberID: memberID})
	if err != nil {
		return false, err
	}
	for _, row := range legacy {
		if row.PermissionKey == permission {
			return true, nil
		}
	}
	return false, nil
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

func requirePermissionTx(ctx context.Context, q *db.Queries, memberID, permission string) error {
	permissions, err := permissionSetTx(ctx, q, memberID)
	if err != nil {
		return err
	}
	if !permissions[permission] {
		return &apierr.Error{Code: "PERMISSION_DENIED", Message: "The current member does not have the required permission.", Details: map[string]string{"permission": permission}}
	}
	return nil
}

func ensureAuthorityCoverageTx(ctx context.Context, q *db.Queries, actorMemberID, targetMemberID string) error {
	actor, err := permissionSetTx(ctx, q, actorMemberID)
	if err != nil {
		return err
	}
	target, err := permissionSetTx(ctx, q, targetMemberID)
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

func permissionSetTx(ctx context.Context, q *db.Queries, memberID string) (map[string]bool, error) {
	set := map[string]bool{}
	rows, err := q.ListMemberAssignments(ctx, db.ListMemberAssignmentsParams{MemberID: pgtype.Text{String: memberID, Valid: true}})
	if err != nil {
		return nil, err
	}
	for _, row := range rows {
		set[row.PermissionKey] = true
	}
	legacy, err := q.ListMemberPermissions(ctx, db.ListMemberPermissionsParams{MemberID: memberID})
	if err != nil {
		return nil, err
	}
	for _, row := range legacy {
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
	out := Space{ID: row.ID, Name: row.Name, Slug: row.Slug, PolicyVersion: row.PolicyVersion}
	if row.ParentID.Valid {
		out.ParentID = row.ParentID.String
	}
	return out
}
