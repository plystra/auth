package enterprise

import (
	"context"
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
	"github.com/plystra/auth/internal/security"
)

type SCIMUserInput struct {
	ExternalID  string
	UserName    string
	DisplayName string
	Active      bool
	ActiveSet   bool
}

type SCIMUser struct {
	ID          string
	ExternalID  string
	UserName    string
	DisplayName string
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

func (s *Service) AuthenticateDirectory(ctx context.Context, directoryID, token string) (db.Directory, error) {
	return s.authenticateDirectory(ctx, directoryID, token)
}

func (s *Service) CreateSCIMUser(ctx context.Context, directoryID, token string, in SCIMUserInput) (SCIMUser, error) {
	directory, err := s.authenticateDirectory(ctx, directoryID, token)
	if err != nil {
		return SCIMUser{}, err
	}
	in.ExternalID = strings.TrimSpace(in.ExternalID)
	in.UserName = strings.TrimSpace(strings.ToLower(in.UserName))
	in.DisplayName = strings.TrimSpace(in.DisplayName)
	if in.ExternalID == "" || len(in.ExternalID) > 512 || !validSCIMEmail(in.UserName) || len(in.DisplayName) > 256 {
		return SCIMUser{}, apierr.New("invalid_request", "SCIM user fields are invalid")
	}
	var out SCIMUser
	err = s.Store.InTx(ctx, func(q *db.Queries) error {
		if err := lockActiveDirectory(ctx, q, directory.ID); err != nil {
			return err
		}
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
			ID: string(ids.New[ids.UserID]("usr")), Email: in.UserName, EmailNormalized: in.UserName, PasswordHash: passwordHash,
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
		if _, err := q.BumpPolicyVersion(ctx, db.BumpPolicyVersionParams{ID: directory.SpaceID}); err != nil {
			return err
		}
		created, err := q.CreateDirectoryUser(ctx, db.CreateDirectoryUserParams{
			ID: string(ids.New[ids.ID]("dusr")), DirectoryID: directory.ID, ExternalID: in.ExternalID,
			UserID: user.ID, MemberID: memberRow.ID, UserName: in.UserName, DisplayName: in.DisplayName,
		})
		if err != nil {
			return err
		}
		if !in.Active {
			if err := q.RevokeUserMember(ctx, db.RevokeUserMemberParams{UserID: user.ID, MemberID: memberRow.ID}); err != nil {
				return err
			}
		}
		out = scimUserFromRow(created)
		out.Active = in.Active
		return audit.WriteWithMetadata(ctx, q, "directory", directory.ID, "scim.user.create", created.ID, "success", map[string]string{"external_id": in.ExternalID, "active": boolString(in.Active), "space_id": directory.SpaceID})
	})
	if err != nil {
		return SCIMUser{}, normalizeSCIMError(err)
	}
	return out, nil
}

func (s *Service) ListSCIMUsers(ctx context.Context, directoryID, token, filter string, startIndex, count int32) ([]SCIMUser, int64, error) {
	directory, err := s.authenticateDirectory(ctx, directoryID, token)
	if err != nil {
		return nil, 0, err
	}
	if startIndex < 1 || count < 1 || count > 100 {
		return nil, 0, apierr.New("invalid_request", "SCIM pagination is invalid")
	}
	rows, err := s.Store.Queries().ListDirectoryUsers(ctx, db.ListDirectoryUsersParams{DirectoryID: directory.ID, FilterUserName: filter, OffsetCount: startIndex - 1, LimitCount: count})
	if err != nil {
		return nil, 0, err
	}
	total, err := s.Store.Queries().CountDirectoryUsers(ctx, db.CountDirectoryUsersParams{DirectoryID: directory.ID, FilterUserName: filter})
	if err != nil {
		return nil, 0, err
	}
	users := make([]SCIMUser, 0, len(rows))
	for _, row := range rows {
		users = append(users, scimUserFromRow(row))
	}
	return users, total, nil
}

func (s *Service) GetSCIMUser(ctx context.Context, directoryID, token, userID string) (SCIMUser, error) {
	directory, err := s.authenticateDirectory(ctx, directoryID, token)
	if err != nil {
		return SCIMUser{}, err
	}
	row, err := s.Store.Queries().GetDirectoryUserByID(ctx, db.GetDirectoryUserByIDParams{DirectoryID: directory.ID, ID: strings.TrimSpace(userID)})
	if errors.Is(err, pgx.ErrNoRows) {
		return SCIMUser{}, apierr.New("not_found", "SCIM user was not found")
	}
	if err != nil {
		return SCIMUser{}, err
	}
	return scimUserFromRow(row), nil
}

func (s *Service) ReplaceSCIMUser(ctx context.Context, directoryID, token, userID string, in SCIMUserInput, version int64) (SCIMUser, error) {
	return s.mutateSCIMUser(ctx, directoryID, token, userID, in, version, false)
}

func (s *Service) PatchSCIMUser(ctx context.Context, directoryID, token, userID string, in SCIMUserInput, version int64) (SCIMUser, error) {
	return s.mutateSCIMUser(ctx, directoryID, token, userID, in, version, true)
}

func (s *Service) DeleteSCIMUser(ctx context.Context, directoryID, token, userID string, version int64) (SCIMUser, error) {
	directory, err := s.authenticateDirectory(ctx, directoryID, token)
	if err != nil {
		return SCIMUser{}, err
	}
	var out SCIMUser
	err = s.Store.InTx(ctx, func(q *db.Queries) error {
		if err := lockActiveDirectory(ctx, q, directory.ID); err != nil {
			return err
		}
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
			if err := revokeDirectoryBindingTx(ctx, q, row); err != nil {
				return err
			}
		}
		deleted, err := q.TombstoneDirectoryUser(ctx, db.TombstoneDirectoryUserParams{DirectoryID: directory.ID, ID: row.ID, Version: row.Version})
		if err != nil {
			return err
		}
		out = scimUserFromRow(deleted)
		return audit.WriteWithMetadata(ctx, q, "directory", directory.ID, "scim.user.delete", row.ID, "success", map[string]string{"space_id": directory.SpaceID})
	})
	if err != nil {
		return SCIMUser{}, normalizeSCIMError(err)
	}
	return out, nil
}

func (s *Service) mutateSCIMUser(ctx context.Context, directoryID, token, userID string, in SCIMUserInput, version int64, patch bool) (SCIMUser, error) {
	directory, err := s.authenticateDirectory(ctx, directoryID, token)
	if err != nil {
		return SCIMUser{}, err
	}
	in.ExternalID = strings.TrimSpace(in.ExternalID)
	in.UserName = strings.TrimSpace(strings.ToLower(in.UserName))
	in.DisplayName = strings.TrimSpace(in.DisplayName)
	if !patch && (in.ExternalID == "" || !validSCIMEmail(in.UserName)) || len(in.UserName) > 320 || len(in.DisplayName) > 256 {
		return SCIMUser{}, apierr.New("invalid_request", "SCIM user fields are invalid")
	}
	var out SCIMUser
	err = s.Store.InTx(ctx, func(q *db.Queries) error {
		if err := lockActiveDirectory(ctx, q, directory.ID); err != nil {
			return err
		}
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
		if in.ExternalID == "" {
			in.ExternalID = row.ExternalID
		}
		if in.UserName == "" {
			in.UserName = row.UserName
		}
		if in.DisplayName == "" && patch {
			in.DisplayName = row.DisplayName
		}
		if patch && !in.ActiveSet {
			in.Active = row.Active
		}
		if in.ExternalID != row.ExternalID {
			return apierr.New("invalid_request", "externalId cannot be changed")
		}
		if !validSCIMEmail(in.UserName) || len(in.DisplayName) > 256 {
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
			if err := revokeDirectoryBindingTx(ctx, q, row); err != nil {
				return err
			}
		} else if !row.Active && in.Active {
			if err := q.BindUserMember(ctx, db.BindUserMemberParams{UserID: row.UserID, MemberID: row.MemberID}); err != nil {
				return err
			}
		}
		updated, err := q.UpdateDirectoryUser(ctx, db.UpdateDirectoryUserParams{DirectoryID: directory.ID, ID: row.ID, UserName: in.UserName, DisplayName: in.DisplayName, Active: in.Active, Version: row.Version})
		if err != nil {
			return err
		}
		out = scimUserFromRow(updated)
		return audit.WriteWithMetadata(ctx, q, "directory", directory.ID, "scim.user.update", row.ID, "success", map[string]string{"active": boolString(in.Active), "space_id": directory.SpaceID})
	})
	if err != nil {
		return SCIMUser{}, normalizeSCIMError(err)
	}
	return out, nil
}

func (s *Service) CreateSCIMGroup(ctx context.Context, directoryID, token string, in SCIMGroupInput) (SCIMGroup, error) {
	directory, err := s.authenticateDirectory(ctx, directoryID, token)
	if err != nil {
		return SCIMGroup{}, err
	}
	in.ExternalID = strings.TrimSpace(in.ExternalID)
	in.DisplayName = strings.TrimSpace(in.DisplayName)
	if in.ExternalID == "" || len(in.ExternalID) > 512 || in.DisplayName == "" || len(in.DisplayName) > 256 {
		return SCIMGroup{}, apierr.New("invalid_request", "SCIM group fields are invalid")
	}
	var out SCIMGroup
	err = s.Store.InTx(ctx, func(q *db.Queries) error {
		if err := lockActiveDirectory(ctx, q, directory.ID); err != nil {
			return err
		}
		if _, err := q.GetDirectoryGroupByExternalID(ctx, db.GetDirectoryGroupByExternalIDParams{DirectoryID: directory.ID, ExternalID: in.ExternalID}); err == nil {
			return apierr.New("conflict", "externalId already exists in this directory")
		} else if !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
		group, err := q.CreateStandardGroup(ctx, db.CreateStandardGroupParams{ID: string(ids.New[ids.GroupID]("grp")), SpaceID: directory.SpaceID, Name: in.DisplayName, ParentID: pgtype.Text{}})
		if err != nil {
			return err
		}
		created, err := q.CreateDirectoryGroup(ctx, db.CreateDirectoryGroupParams{ID: string(ids.New[ids.ID]("dgrp")), DirectoryID: directory.ID, ExternalID: in.ExternalID, GroupID: group.ID, DisplayName: in.DisplayName})
		if err != nil {
			return err
		}
		if err := syncDirectoryGroupMembersTx(ctx, q, directory.ID, directory.SpaceID, created.ID, group.ID, in.MemberIDs); err != nil {
			return err
		}
		members, err := q.ListDirectoryGroupUserIDs(ctx, db.ListDirectoryGroupUserIDsParams{DirectoryID: directory.ID, DirectoryGroupID: created.ID})
		if err != nil {
			return err
		}
		out = scimGroupFromRow(created, members)
		return audit.WriteWithMetadata(ctx, q, "directory", directory.ID, "scim.group.create", created.ID, "success", map[string]string{"space_id": directory.SpaceID})
	})
	if err != nil {
		return SCIMGroup{}, normalizeSCIMError(err)
	}
	return out, nil
}

func (s *Service) ListSCIMGroups(ctx context.Context, directoryID, token string, startIndex, count int32) ([]SCIMGroup, int64, error) {
	directory, err := s.authenticateDirectory(ctx, directoryID, token)
	if err != nil {
		return nil, 0, err
	}
	if startIndex < 1 || count < 1 || count > 100 {
		return nil, 0, apierr.New("invalid_request", "SCIM pagination is invalid")
	}
	rows, err := s.Store.Queries().ListDirectoryGroups(ctx, db.ListDirectoryGroupsParams{DirectoryID: directory.ID, OffsetCount: startIndex - 1, LimitCount: count})
	if err != nil {
		return nil, 0, err
	}
	total, err := s.Store.Queries().CountDirectoryGroups(ctx, db.CountDirectoryGroupsParams{DirectoryID: directory.ID})
	if err != nil {
		return nil, 0, err
	}
	groups := make([]SCIMGroup, 0, len(rows))
	for _, row := range rows {
		members, err := s.Store.Queries().ListDirectoryGroupUserIDs(ctx, db.ListDirectoryGroupUserIDsParams{DirectoryID: directory.ID, DirectoryGroupID: row.ID})
		if err != nil {
			return nil, 0, err
		}
		groups = append(groups, scimGroupFromRow(row, members))
	}
	return groups, total, nil
}

func (s *Service) GetSCIMGroup(ctx context.Context, directoryID, token, groupID string) (SCIMGroup, error) {
	directory, err := s.authenticateDirectory(ctx, directoryID, token)
	if err != nil {
		return SCIMGroup{}, err
	}
	row, err := s.Store.Queries().GetDirectoryGroupByID(ctx, db.GetDirectoryGroupByIDParams{DirectoryID: directory.ID, ID: strings.TrimSpace(groupID)})
	if errors.Is(err, pgx.ErrNoRows) {
		return SCIMGroup{}, apierr.New("not_found", "SCIM group was not found")
	}
	if err != nil {
		return SCIMGroup{}, err
	}
	members, err := s.Store.Queries().ListDirectoryGroupUserIDs(ctx, db.ListDirectoryGroupUserIDsParams{DirectoryID: directory.ID, DirectoryGroupID: row.ID})
	if err != nil {
		return SCIMGroup{}, err
	}
	return scimGroupFromRow(row, members), nil
}

func (s *Service) ReplaceSCIMGroup(ctx context.Context, directoryID, token, groupID string, in SCIMGroupInput, version int64) (SCIMGroup, error) {
	directory, err := s.authenticateDirectory(ctx, directoryID, token)
	if err != nil {
		return SCIMGroup{}, err
	}
	in.DisplayName = strings.TrimSpace(in.DisplayName)
	if in.DisplayName == "" || len(in.DisplayName) > 256 {
		return SCIMGroup{}, apierr.New("invalid_request", "SCIM group fields are invalid")
	}
	var out SCIMGroup
	err = s.Store.InTx(ctx, func(q *db.Queries) error {
		if err := lockActiveDirectory(ctx, q, directory.ID); err != nil {
			return err
		}
		row, err := q.LockDirectoryGroup(ctx, db.LockDirectoryGroupParams{DirectoryID: directory.ID, ID: strings.TrimSpace(groupID)})
		if errors.Is(err, pgx.ErrNoRows) {
			return apierr.New("not_found", "SCIM group was not found")
		}
		if err != nil {
			return err
		}
		if row.Version != version {
			return apierr.New("precondition_failed", "SCIM resource version does not match")
		}
		updated, err := q.UpdateDirectoryGroup(ctx, db.UpdateDirectoryGroupParams{DirectoryID: directory.ID, ID: row.ID, DisplayName: in.DisplayName, Version: row.Version})
		if err != nil {
			return err
		}
		if err := syncDirectoryGroupMembersTx(ctx, q, directory.ID, directory.SpaceID, row.ID, row.GroupID, in.MemberIDs); err != nil {
			return err
		}
		members, err := q.ListDirectoryGroupUserIDs(ctx, db.ListDirectoryGroupUserIDsParams{DirectoryID: directory.ID, DirectoryGroupID: row.ID})
		if err != nil {
			return err
		}
		out = scimGroupFromRow(updated, members)
		return audit.WriteWithMetadata(ctx, q, "directory", directory.ID, "scim.group.update", row.ID, "success", map[string]string{"space_id": directory.SpaceID})
	})
	if err != nil {
		return SCIMGroup{}, normalizeSCIMError(err)
	}
	return out, nil
}

func (s *Service) DeleteSCIMGroup(ctx context.Context, directoryID, token, groupID string, version int64) error {
	directory, err := s.authenticateDirectory(ctx, directoryID, token)
	if err != nil {
		return err
	}
	err = s.Store.InTx(ctx, func(q *db.Queries) error {
		if err := lockActiveDirectory(ctx, q, directory.ID); err != nil {
			return err
		}
		row, err := q.LockDirectoryGroup(ctx, db.LockDirectoryGroupParams{DirectoryID: directory.ID, ID: strings.TrimSpace(groupID)})
		if errors.Is(err, pgx.ErrNoRows) {
			return apierr.New("not_found", "SCIM group was not found")
		}
		if err != nil {
			return err
		}
		if row.Version != version {
			return apierr.New("precondition_failed", "SCIM resource version does not match")
		}
		if err := q.DeleteDirectoryManagedGroupMembers(ctx, db.DeleteDirectoryManagedGroupMembersParams{GroupID: row.GroupID, SpaceID: directory.SpaceID}); err != nil {
			return err
		}
		if err := q.RemoveDirectoryBackedGroup(ctx, db.RemoveDirectoryBackedGroupParams{GroupID: row.GroupID, SpaceID: directory.SpaceID}); err != nil {
			return err
		}
		if err := q.DeleteDirectoryGroupMembers(ctx, db.DeleteDirectoryGroupMembersParams{DirectoryGroupID: row.ID}); err != nil {
			return err
		}
		if err := q.DeleteDirectoryGroup(ctx, db.DeleteDirectoryGroupParams{DirectoryID: directory.ID, ID: row.ID, Version: row.Version}); err != nil {
			return err
		}
		return audit.WriteWithMetadata(ctx, q, "directory", directory.ID, "scim.group.delete", row.ID, "success", map[string]string{"space_id": directory.SpaceID})
	})
	return normalizeSCIMError(err)
}

func lockActiveDirectory(ctx context.Context, q *db.Queries, directoryID string) error {
	row, err := q.LockDirectory(ctx, db.LockDirectoryParams{ID: directoryID})
	if errors.Is(err, pgx.ErrNoRows) {
		return apierr.New("not_found", "SCIM directory was not found")
	}
	if err != nil {
		return err
	}
	if row.Status != "active" {
		return apierr.New("unauthenticated", "SCIM directory is disabled")
	}
	return nil
}

func revokeDirectoryBindingTx(ctx context.Context, q *db.Queries, row db.DirectoryUser) error {
	if err := q.RevokeUserMember(ctx, db.RevokeUserMemberParams{UserID: row.UserID, MemberID: row.MemberID}); err != nil {
		return err
	}
	agents, err := q.ListAgentsCreatedByBinding(ctx, db.ListAgentsCreatedByBindingParams{UserID: pgtype.Text{String: row.UserID, Valid: true}, MemberID: pgtype.Text{String: row.MemberID, Valid: true}})
	if err != nil {
		return err
	}
	for _, agentID := range agents {
		if err := member.SetAgentSubtreeStatusTx(ctx, q, agentID, "suspended"); err != nil {
			return err
		}
	}
	return nil
}

func syncDirectoryGroupMembersTx(ctx context.Context, q *db.Queries, directoryID, spaceID, directoryGroupID, groupID string, userIDs []string) error {
	if err := q.DeleteDirectoryGroupMembers(ctx, db.DeleteDirectoryGroupMembersParams{DirectoryGroupID: directoryGroupID}); err != nil {
		return err
	}
	if err := q.DeleteDirectoryManagedGroupMembers(ctx, db.DeleteDirectoryManagedGroupMembersParams{GroupID: groupID, SpaceID: spaceID}); err != nil {
		return err
	}
	seen := make(map[string]struct{}, len(userIDs))
	for _, userID := range userIDs {
		userID = strings.TrimSpace(userID)
		if userID == "" {
			continue
		}
		if _, ok := seen[userID]; ok {
			continue
		}
		seen[userID] = struct{}{}
		user, err := q.GetDirectoryUserByID(ctx, db.GetDirectoryUserByIDParams{DirectoryID: directoryID, ID: userID})
		if errors.Is(err, pgx.ErrNoRows) || !user.Active {
			return apierr.New("invalid_request", "group members must reference active users in this directory")
		}
		if err != nil {
			return err
		}
		if err := q.AddDirectoryGroupMember(ctx, db.AddDirectoryGroupMemberParams{DirectoryGroupID: directoryGroupID, MemberID: user.MemberID}); err != nil {
			return err
		}
		if err := q.AddDirectoryManagedGroupMember(ctx, db.AddDirectoryManagedGroupMemberParams{GroupID: groupID, MemberID: user.MemberID, SpaceID: spaceID}); err != nil {
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

func scimUserFromRow(row db.DirectoryUser) SCIMUser {
	return SCIMUser{ID: row.ID, ExternalID: row.ExternalID, UserName: row.UserName, DisplayName: row.DisplayName, Active: row.Active, Version: row.Version, CreatedAt: row.CreatedAt.Time, UpdatedAt: row.UpdatedAt.Time}
}

func scimGroupFromRow(row db.DirectoryGroup, members []string) SCIMGroup {
	return SCIMGroup{ID: row.ID, ExternalID: row.ExternalID, DisplayName: row.DisplayName, MemberIDs: members, Version: row.Version, CreatedAt: row.CreatedAt.Time, UpdatedAt: row.UpdatedAt.Time}
}

func validSCIMEmail(value string) bool {
	if len(value) == 0 || len(value) > 320 || strings.ContainsAny(value, " \t\r\n") {
		return false
	}
	at := strings.LastIndexByte(value, '@')
	return at > 0 && at < len(value)-1 && !strings.Contains(value[at+1:], "@")
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
