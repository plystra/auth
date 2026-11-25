package enterprise

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/plystra/auth/internal/apierr"
	"github.com/plystra/auth/internal/audit"
	"github.com/plystra/auth/internal/db"
	"github.com/plystra/auth/internal/ids"
	"github.com/plystra/auth/internal/member"
	"github.com/plystra/auth/internal/secret"
	"github.com/plystra/auth/internal/security"
)

const MaxSCIMPageSize = 100

type SCIMUserInput struct {
	ExternalID     string
	UserName       string
	DisplayName    string
	Active         bool
	ActiveSet      bool
	DisplayNameSet bool
	Name           SCIMName
	NamePatches    []SCIMName // A nil patch clears the entire name.
	Emails         []SCIMEmail
	EmailPatches   []SCIMEmailPatch
}

type SCIMUser struct {
	ID          string
	ExternalID  string
	UserName    string
	DisplayName string
	Name        SCIMName
	Emails      []SCIMEmail
	GroupIDs    []string
	Active      bool
	Version     int64
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

type SCIMGroupInput struct {
	ExternalID  string
	DisplayName string
	MemberIDs   []string
}

type SCIMGroup struct {
	ID          string
	ExternalID  string
	DisplayName string
	MemberIDs   []string
	Version     int64
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

type SCIMCollectionFilter struct {
	Name       string
	ExternalID string
	Active     *bool
}

func (s *Service) CreateSCIMUser(ctx context.Context, directoryID string, token secret.String, in SCIMUserInput) (SCIMUser, error) {
	directory, err := s.authenticateDirectory(ctx, directoryID, token)
	if err != nil {
		return SCIMUser{}, err
	}
	in.ExternalID = strings.TrimSpace(in.ExternalID)
	in.UserName = strings.TrimSpace(strings.ToLower(in.UserName))
	in.DisplayName = strings.TrimSpace(in.DisplayName)
	if in.ExternalID == "" || len(in.ExternalID) > 512 || !ValidSCIMUserName(in.UserName) || len(in.DisplayName) > 256 {
		return SCIMUser{}, apierr.New("invalid_request", "SCIM user fields are invalid")
	}
	name, err := encodeSCIMName(in.Name, nil)
	if err != nil {
		return SCIMUser{}, apierr.New("invalid_request", "SCIM name is invalid")
	}
	emails, err := encodeSCIMEmails(in.Emails, nil)
	if err != nil {
		return SCIMUser{}, err
	}
	var out SCIMUser
	err = s.withDirectoryTx(ctx, directory, token, true, func(ctx context.Context, q *db.Queries, directory db.Directory) error {
		if _, err := q.GetDirectoryUserByExternalID(ctx, db.GetDirectoryUserByExternalIDParams{DirectoryID: directory.ID, ExternalID: in.ExternalID}); err == nil {
			return apierr.New("conflict", "externalId already exists in this directory")
		} else if !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
		if _, err := q.GetUserByEmail(ctx, db.GetUserByEmailParams{EmailNormalized: in.UserName}); err == nil {
			return apierr.New("conflict", "userName is already owned by an existing account")
		} else if !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
		password, err := randomOpaque("scim_pw_")
		if err != nil {
			return err
		}
		hasher := s.Passwords
		if hasher.Memory == 0 {
			hasher = security.DefaultPasswordHasher()
		}
		passwordHash, err := hasher.Hash(password)
		if err != nil {
			return err
		}
		user, err := q.CreateDirectoryProvisionedUser(ctx, db.CreateDirectoryProvisionedUserParams{
			ID: string(ids.New[ids.UserID]("usr")), Email: in.UserName, EmailNormalized: in.UserName, PasswordHash: passwordHash, DisplayName: in.DisplayName,
		})
		if err != nil {
			return err
		}
		memberRow, err := q.CreateMemberWithPolicy(ctx, db.CreateMemberWithPolicyParams{
			ID: string(ids.New[ids.MemberID]("mem")), SpaceID: directory.SpaceID, Name: in.DisplayNameOrUserName(), Type: "human", BindingPolicy: "single",
		})
		if err != nil {
			return err
		}
		if err := q.BindUserMember(ctx, db.BindUserMemberParams{UserID: user.ID, MemberID: memberRow.ID}); err != nil {
			return err
		}
		policyVersion, err := q.BumpPolicyVersion(ctx, db.BumpPolicyVersionParams{ID: directory.SpaceID})
		if err != nil {
			return err
		}
		created, err := q.CreateDirectoryUser(ctx, db.CreateDirectoryUserParams{
			ID: string(ids.New[ids.ID]("dusr")), DirectoryID: directory.ID, ExternalID: in.ExternalID,
			UserID: user.ID, MemberID: memberRow.ID, UserName: in.UserName, DisplayName: in.DisplayName, Active: in.Active, ScimName: name, ScimEmails: emails,
		})
		if err != nil {
			return err
		}
		if !in.Active {
			if err := q.RevokeUserMember(ctx, db.RevokeUserMemberParams{UserID: user.ID, MemberID: memberRow.ID}); err != nil {
				return err
			}
		}
		out, err = scimUserFromRow(created)
		if err != nil {
			return err
		}
		return audit.WriteSecurityEvent(ctx, q, audit.SecurityEvent{ActorType: "directory", ActorID: directory.ID, MemberID: memberRow.ID, Action: "scim.user.create", Outcome: "success", PolicyVersion: policyVersion, Resource: audit.Resource{Type: "directory_user", ID: created.ID, SpaceID: directory.SpaceID}, Metadata: map[string]string{"external_id": in.ExternalID, "active": boolString(in.Active), "space_id": directory.SpaceID}})
	})
	if err != nil {
		return SCIMUser{}, normalizeSCIMError(err)
	}
	return out, nil
}

func (s *Service) ListSCIMUsers(ctx context.Context, directoryID string, token secret.String, filter SCIMCollectionFilter, startIndex, count int32, includeGroups bool) ([]SCIMUser, int64, error) {
	directory, err := s.authenticateDirectory(ctx, directoryID, token)
	if err != nil {
		return nil, 0, err
	}
	if startIndex < 1 || count < 0 || count > MaxSCIMPageSize {
		return nil, 0, apierr.New("invalid_request", "SCIM pagination is invalid")
	}
	users := []SCIMUser{}
	var total int64
	var active pgtype.Bool
	if filter.Active != nil {
		active = pgtype.Bool{Bool: *filter.Active, Valid: true}
	}
	err = s.withDirectoryTx(ctx, directory, token, false, func(ctx context.Context, q *db.Queries, _ db.Directory) error {
		rows, e := q.ListDirectoryUsers(ctx, db.ListDirectoryUsersParams{
			DirectoryID: directory.ID, FilterUserName: filter.Name, FilterExternalID: filter.ExternalID, FilterActive: active,
			OffsetCount: startIndex - 1, LimitCount: count,
		})
		if e != nil {
			return e
		}
		total, e = q.CountDirectoryUsers(ctx, db.CountDirectoryUsersParams{
			DirectoryID: directory.ID, FilterUserName: filter.Name, FilterExternalID: filter.ExternalID, FilterActive: active,
		})
		if e != nil {
			return e
		}
		for _, row := range rows {
			user, err := scimUserFromRow(row)
			if err != nil {
				return err
			}
			users = append(users, user)
		}
		if includeGroups && len(users) != 0 {
			ids := make([]string, 0, len(users))
			for _, user := range users {
				ids = append(ids, user.ID)
			}
			groups, err := scimUserGroupsTx(ctx, q, directory.ID, ids)
			if err != nil {
				return err
			}
			for i := range users {
				users[i].GroupIDs = groups[users[i].ID]
			}
		}
		return nil
	})
	if err != nil {
		return nil, 0, err
	}
	return users, total, nil
}

func (s *Service) GetSCIMUser(ctx context.Context, directoryID string, token secret.String, userID string, includeGroups bool) (SCIMUser, error) {
	directory, err := s.authenticateDirectory(ctx, directoryID, token)
	if err != nil {
		return SCIMUser{}, err
	}
	var out SCIMUser
	err = s.withDirectoryTx(ctx, directory, token, false, func(ctx context.Context, q *db.Queries, _ db.Directory) error {
		row, err := q.GetDirectoryUserByID(ctx, db.GetDirectoryUserByIDParams{DirectoryID: directory.ID, ID: strings.TrimSpace(userID)})
		if errors.Is(err, pgx.ErrNoRows) {
			return apierr.New("not_found", "SCIM user was not found")
		}
		if err != nil {
			return err
		}
		if includeGroups {
			out, err = scimUserWithGroupsTx(ctx, q, row)
		} else {
			out, err = scimUserFromRow(row)
		}
		return err
	})
	if err != nil {
		return SCIMUser{}, err
	}
	return out, nil
}

func (s *Service) ReplaceSCIMUser(ctx context.Context, directoryID string, token secret.String, userID string, in SCIMUserInput, version int64) (SCIMUser, error) {
	return s.mutateSCIMUser(ctx, directoryID, token, userID, in, version, false)
}

func (s *Service) PatchSCIMUser(ctx context.Context, directoryID string, token secret.String, userID string, in SCIMUserInput, version int64) (SCIMUser, error) {
	return s.mutateSCIMUser(ctx, directoryID, token, userID, in, version, true)
}

func (s *Service) DeleteSCIMUser(ctx context.Context, directoryID string, token secret.String, userID string, version int64) (SCIMUser, error) {
	directory, err := s.authenticateDirectory(ctx, directoryID, token)
	if err != nil {
		return SCIMUser{}, err
	}
	var out SCIMUser
	err = s.withDirectoryTx(ctx, directory, token, true, func(ctx context.Context, q *db.Queries, directory db.Directory) error {
		row, err := q.LockDirectoryUser(ctx, db.LockDirectoryUserParams{DirectoryID: directory.ID, ID: strings.TrimSpace(userID)})
		if errors.Is(err, pgx.ErrNoRows) {
			return apierr.New("not_found", "SCIM user was not found")
		}
		if err != nil {
			return err
		}
		if row.Version != version {
			return apierr.New("precondition_failed", "SCIM resource version does not match")
		}
		if row.Active {
			if err := revokeDirectoryBindingTx(ctx, q, directory, row); err != nil {
				return err
			}
		}
		deleted, err := q.TombstoneDirectoryUser(ctx, db.TombstoneDirectoryUserParams{DirectoryID: directory.ID, ID: row.ID, Version: row.Version})
		if err != nil {
			return err
		}
		if err := q.RemoveTombstonedUserDirectoryMemberships(ctx, db.RemoveTombstonedUserDirectoryMembershipsParams{
			DirectoryID: directory.ID, MemberID: row.MemberID, SpaceID: directory.SpaceID,
		}); err != nil {
			return err
		}
		policyVersion, err := q.BumpPolicyVersion(ctx, db.BumpPolicyVersionParams{ID: directory.SpaceID})
		if err != nil {
			return err
		}
		out, err = scimUserFromRow(deleted)
		if err != nil {
			return err
		}
		return audit.WriteSecurityEvent(ctx, q, audit.SecurityEvent{ActorType: "directory", ActorID: directory.ID, MemberID: row.MemberID, Action: "scim.user.delete", Outcome: "success", PolicyVersion: policyVersion, Resource: audit.Resource{Type: "directory_user", ID: row.ID, SpaceID: directory.SpaceID}, Metadata: map[string]string{"space_id": directory.SpaceID}})
	})
	if err != nil {
		return SCIMUser{}, normalizeSCIMError(err)
	}
	return out, nil
}

func (s *Service) mutateSCIMUser(ctx context.Context, directoryID string, token secret.String, userID string, in SCIMUserInput, version int64, patch bool) (SCIMUser, error) {
	directory, err := s.authenticateDirectory(ctx, directoryID, token)
	if err != nil {
		return SCIMUser{}, err
	}
	in.ExternalID = strings.TrimSpace(in.ExternalID)
	in.UserName = strings.TrimSpace(strings.ToLower(in.UserName))
	in.DisplayName = strings.TrimSpace(in.DisplayName)
	if !patch && (in.ExternalID == "" || !ValidSCIMUserName(in.UserName)) || len(in.UserName) > 320 || len(in.DisplayName) > 256 {
		return SCIMUser{}, apierr.New("invalid_request", "SCIM user fields are invalid")
	}
	var out SCIMUser
	err = s.withDirectoryTx(ctx, directory, token, true, func(ctx context.Context, q *db.Queries, directory db.Directory) error {
		row, err := q.LockDirectoryUser(ctx, db.LockDirectoryUserParams{DirectoryID: directory.ID, ID: strings.TrimSpace(userID)})
		if errors.Is(err, pgx.ErrNoRows) {
			return apierr.New("not_found", "SCIM user was not found")
		}
		if err != nil {
			return err
		}
		if row.Version != version {
			return apierr.New("precondition_failed", "SCIM resource version does not match")
		}
		initialName := in.Name
		initialEmails := in.Emails
		if patch {
			if err := json.Unmarshal(row.ScimName, &initialName); err != nil {
				return err
			}
			if err := json.Unmarshal(row.ScimEmails, &initialEmails); err != nil {
				return err
			}
		}
		name, err := encodeSCIMName(initialName, in.NamePatches)
		if err != nil {
			return apierr.New("invalid_request", "SCIM name is invalid")
		}
		emails, err := encodeSCIMEmails(initialEmails, in.EmailPatches)
		if err != nil {
			return err
		}
		if in.ExternalID == "" {
			in.ExternalID = row.ExternalID
		}
		if in.UserName == "" {
			in.UserName = row.UserName
		}
		if !in.DisplayNameSet && patch {
			in.DisplayName = row.DisplayName
		}
		if patch && !in.ActiveSet {
			in.Active = row.Active
		}
		if in.ExternalID != row.ExternalID {
			return apierr.New("invalid_request", "externalId cannot be changed")
		}
		if !ValidSCIMUserName(in.UserName) || len(in.DisplayName) > 256 {
			return apierr.New("invalid_request", "SCIM user fields are invalid")
		}
		if in.UserName != row.UserName {
			if existing, err := q.GetUserByEmail(ctx, db.GetUserByEmailParams{EmailNormalized: in.UserName}); err == nil && existing.ID != row.UserID {
				return apierr.New("conflict", "userName is already owned by an existing account")
			} else if err != nil && !errors.Is(err, pgx.ErrNoRows) {
				return err
			}
			if err := q.UpdateDirectoryUserEmail(ctx, db.UpdateDirectoryUserEmailParams{DirectoryID: directory.ID, ID: row.ID, Email: in.UserName, EmailNormalized: in.UserName}); err != nil {
				return err
			}
		}
		if err := q.UpdateDirectoryUserProfile(ctx, db.UpdateDirectoryUserProfileParams{DirectoryID: directory.ID, ID: row.ID, DisplayName: in.DisplayName}); err != nil {
			return err
		}
		if row.Active && !in.Active {
			if err := revokeDirectoryBindingTx(ctx, q, directory, row); err != nil {
				return err
			}
		} else if !row.Active && in.Active {
			if s.Authorization == nil {
				return apierr.New("temporarily_unavailable", "directory authorization service is unavailable")
			}
			if err := s.Authorization.ApplyDirectoryAuthorityTx(ctx, q, directory.ConfiguredByMemberID.String, directory.SpaceID, "", []string{row.MemberID}, func() error {
				return q.BindUserMember(ctx, db.BindUserMemberParams{UserID: row.UserID, MemberID: row.MemberID})
			}); err != nil {
				return err
			}
		}
		updated, err := q.UpdateDirectoryUser(ctx, db.UpdateDirectoryUserParams{DirectoryID: directory.ID, ID: row.ID, UserName: in.UserName, DisplayName: in.DisplayName, Active: in.Active, Version: row.Version, ScimName: name, ScimEmails: emails})
		if err != nil {
			return err
		}
		policyVersion, err := q.BumpPolicyVersion(ctx, db.BumpPolicyVersionParams{ID: directory.SpaceID})
		if err != nil {
			return err
		}
		out, err = scimUserWithGroupsTx(ctx, q, updated)
		if err != nil {
			return err
		}
		return audit.WriteSecurityEvent(ctx, q, audit.SecurityEvent{ActorType: "directory", ActorID: directory.ID, MemberID: row.MemberID, Action: "scim.user.update", Outcome: "success", PolicyVersion: policyVersion, Resource: audit.Resource{Type: "directory_user", ID: row.ID, SpaceID: directory.SpaceID}, Metadata: map[string]string{"active": boolString(in.Active), "space_id": directory.SpaceID}})
	})
	if err != nil {
		return SCIMUser{}, normalizeSCIMError(err)
	}
	return out, nil
}

func revokeDirectoryBindingTx(ctx context.Context, q *db.Queries, directory db.Directory, row db.DirectoryUser) error {
	if err := q.RevokeUserMember(ctx, db.RevokeUserMemberParams{UserID: row.UserID, MemberID: row.MemberID}); err != nil {
		return err
	}
	boundMember := pgtype.Text{String: row.MemberID, Valid: true}
	if err := q.RevokeBindingSessions(ctx, db.RevokeBindingSessionsParams{UserID: row.UserID, MemberID: boundMember}); err != nil {
		return err
	}
	if err := q.RevokeBindingRefreshTokens(ctx, db.RevokeBindingRefreshTokensParams{UserID: row.UserID, MemberID: boundMember}); err != nil {
		return err
	}
	agents, err := q.ListAgentsCreatedByBinding(ctx, db.ListAgentsCreatedByBindingParams{UserID: pgtype.Text{String: row.UserID, Valid: true}, MemberID: boundMember})
	if err != nil {
		return err
	}
	space, err := q.GetSpace(ctx, db.GetSpaceParams{ID: directory.SpaceID})
	if err != nil {
		return err
	}
	for _, agentID := range agents {
		if err := member.SetAgentSubtreeStatusTx(ctx, q, agentID, "suspended"); err != nil {
			return err
		}
		if err := audit.WriteSecurityEvent(ctx, q, audit.SecurityEvent{ActorType: "directory", ActorID: directory.ID, MemberID: agentID, Action: "agent.binding.suspend", Outcome: "success", PolicyVersion: space.PolicyVersion + 1, Metadata: map[string]string{"binding_user_id": row.UserID, "binding_member_id": row.MemberID}}); err != nil {
			return err
		}
	}
	return nil
}

func syncDirectoryGroupMembersTx(ctx context.Context, q *db.Queries, spaceID, directoryGroupID, groupID string, memberIDs []string) error {
	if err := q.DeleteDirectoryGroupMembers(ctx, db.DeleteDirectoryGroupMembersParams{DirectoryGroupID: directoryGroupID}); err != nil {
		return err
	}
	if err := q.DeleteDirectoryManagedGroupMembers(ctx, db.DeleteDirectoryManagedGroupMembersParams{GroupID: groupID, SpaceID: spaceID}); err != nil {
		return err
	}
	for _, memberID := range memberIDs {
		if err := q.AddDirectoryGroupMember(ctx, db.AddDirectoryGroupMemberParams{DirectoryGroupID: directoryGroupID, MemberID: memberID}); err != nil {
			return err
		}
		if err := q.AddDirectoryManagedGroupMember(ctx, db.AddDirectoryManagedGroupMemberParams{GroupID: groupID, MemberID: memberID, SpaceID: spaceID}); err != nil {
			return err
		}
	}
	return nil
}

func (in SCIMUserInput) DisplayNameOrUserName() string {
	if in.DisplayName != "" {
		return in.DisplayName
	}
	return in.UserName
}

func scimUserFromRow(row db.DirectoryUser) (SCIMUser, error) {
	var name SCIMName
	if err := json.Unmarshal(row.ScimName, &name); err != nil {
		return SCIMUser{}, err
	}
	var emails []SCIMEmail
	if err := json.Unmarshal(row.ScimEmails, &emails); err != nil {
		return SCIMUser{}, err
	}
	return SCIMUser{ID: row.ID, ExternalID: row.ExternalID, UserName: row.UserName, DisplayName: row.DisplayName, Name: name, Emails: emails, Active: row.Active, Version: row.Version, CreatedAt: row.CreatedAt.Time, UpdatedAt: row.UpdatedAt.Time}, nil
}

func scimUserWithGroupsTx(ctx context.Context, q *db.Queries, row db.DirectoryUser) (SCIMUser, error) {
	user, err := scimUserFromRow(row)
	if err != nil {
		return SCIMUser{}, err
	}
	groups, err := scimUserGroupsTx(ctx, q, row.DirectoryID, []string{row.ID})
	if err != nil {
		return SCIMUser{}, err
	}
	user.GroupIDs = groups[row.ID]
	return user, nil
}

func scimUserGroupsTx(ctx context.Context, q *db.Queries, directoryID string, ids []string) (map[string][]string, error) {
	memberships, err := q.ListSCIMUserGroups(ctx, db.ListSCIMUserGroupsParams{DirectoryID: directoryID, UserIds: ids})
	if err != nil {
		return nil, err
	}
	groups := make(map[string][]string)
	for _, membership := range memberships {
		groups[membership.UserID] = append(groups[membership.UserID], membership.DirectoryGroupID)
	}
	return groups, nil
}

func scimGroupFromRow(row db.DirectoryGroup, members []string) SCIMGroup {
	return SCIMGroup{ID: row.ID, ExternalID: row.ExternalID, DisplayName: row.DisplayName, MemberIDs: members, Version: row.Version, CreatedAt: row.CreatedAt.Time, UpdatedAt: row.UpdatedAt.Time}
}

// ValidSCIMUserName checks the email form used by directory users and their lookup filters.
func ValidSCIMUserName(value string) bool {
	if len(value) == 0 || len(value) > 320 || strings.ContainsAny(value, " \t\r\n") {
		return false
	}
	at := strings.LastIndexByte(value, '@')
	return at > 0 && at < len(value)-1 && strings.Count(value, "@") == 1
}

func boolString(value bool) string {
	if value {
		return "true"
	}
	return "false"
}

func normalizeSCIMError(err error) error {
	if err == nil {
		return nil
	}
	var public *apierr.Error
	if errors.As(err, &public) {
		return public
	}
	if strings.Contains(strings.ToLower(err.Error()), "duplicate") || strings.Contains(strings.ToLower(err.Error()), "unique") {
		return apierr.New("conflict", "the SCIM resource conflicts with an existing identity")
	}
	return err
}
