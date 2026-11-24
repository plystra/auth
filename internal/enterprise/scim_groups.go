package enterprise

import (
	"context"
	"errors"
	"slices"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/plystra/auth/internal/apierr"
	"github.com/plystra/auth/internal/audit"
	"github.com/plystra/auth/internal/db"
	"github.com/plystra/auth/internal/ids"
	"github.com/plystra/auth/internal/secret"
)

type SCIMGroupOperation struct {
	Op          string
	Path        string
	DisplayName string
	MemberIDs   []string
}

func (s *Service) CreateSCIMGroup(ctx context.Context, directoryID string, token secret.String, in SCIMGroupInput) (SCIMGroup, error) {
	directory, err := s.authenticateDirectory(ctx, directoryID, token)
	if err != nil {
		return SCIMGroup{}, err
	}
	in.ExternalID = strings.TrimSpace(in.ExternalID)
	in.DisplayName = strings.TrimSpace(in.DisplayName)
	if in.ExternalID == "" || len(in.ExternalID) > 512 || !validSCIMGroupName(in.DisplayName) || len(in.MemberIDs) > 1000 {
		return SCIMGroup{}, apierr.New("invalid_request", "SCIM group fields are invalid")
	}
	var out SCIMGroup
	err = s.withDirectoryTx(ctx, directory, token, true, func(ctx context.Context, q *db.Queries, directory db.Directory) error {
		if _, err := q.GetDirectoryGroupByExternalID(ctx, db.GetDirectoryGroupByExternalIDParams{DirectoryID: directory.ID, ExternalID: in.ExternalID}); err == nil {
			return apierr.New("conflict", "externalId already exists in this directory")
		} else if !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
		// SCIM has a flat group collection; place additional groups under the
		// Space's sole standard root without relaxing the group-tree invariant.
		root, err := q.GetSCIMStandardRoot(ctx, db.GetSCIMStandardRootParams{SpaceID: directory.SpaceID})
		if err != nil && !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
		if err == nil && root.Status != "active" {
			return apierr.New("conflict", "the standard root group is not active")
		}
		parentID := pgtype.Text{String: root.ID, Valid: root.ID != ""}
		group, err := q.CreateStandardGroup(ctx, db.CreateStandardGroupParams{ID: string(ids.New[ids.GroupID]("grp")), SpaceID: directory.SpaceID, Name: in.DisplayName, ParentID: parentID})
		if err != nil {
			return err
		}
		created, err := q.CreateDirectoryGroup(ctx, db.CreateDirectoryGroupParams{ID: string(ids.New[ids.ID]("dgrp")), DirectoryID: directory.ID, ExternalID: in.ExternalID, GroupID: group.ID, DisplayName: in.DisplayName})
		if err != nil {
			return err
		}
		if err := s.syncDirectoryMembersTx(ctx, q, directory, created, in.MemberIDs, false); err != nil {
			return err
		}
		members, err := q.ListDirectoryGroupUserIDs(ctx, db.ListDirectoryGroupUserIDsParams{DirectoryID: directory.ID, DirectoryGroupID: created.ID})
		if err != nil {
			return err
		}
		out = scimGroupFromRow(created, members)
		return writeSCIMGroupAudit(ctx, q, directory, created, "scim.group.create")
	})
	return out, normalizeSCIMError(err)
}

func (s *Service) ListSCIMGroups(ctx context.Context, directoryID string, token secret.String, displayName string, includeMembers bool, startIndex, count int32) ([]SCIMGroup, int64, error) {
	directory, err := s.authenticateDirectory(ctx, directoryID, token)
	if err != nil {
		return nil, 0, err
	}
	if startIndex < 1 || count < 0 || count > MaxSCIMPageSize {
		return nil, 0, apierr.New("invalid_request", "SCIM pagination is invalid")
	}
	groups := []SCIMGroup{}
	var total int64
	err = s.withDirectoryTx(ctx, directory, token, false, func(ctx context.Context, q *db.Queries, directory db.Directory) error {
		rows, err := q.ListDirectoryGroups(ctx, db.ListDirectoryGroupsParams{
			DirectoryID: directory.ID, FilterDisplayName: displayName, OffsetCount: startIndex - 1, LimitCount: count,
		})
		if err != nil {
			return err
		}
		total, err = q.CountDirectoryGroups(ctx, db.CountDirectoryGroupsParams{DirectoryID: directory.ID, FilterDisplayName: displayName})
		if err != nil {
			return err
		}
		for _, row := range rows {
			group, err := loadSCIMGroup(ctx, q, row, includeMembers)
			if err != nil {
				return err
			}
			groups = append(groups, group)
		}
		return nil
	})
	if err != nil {
		return nil, 0, err
	}
	return groups, total, nil
}

func (s *Service) GetSCIMGroup(ctx context.Context, directoryID string, token secret.String, groupID string, includeMembers bool) (SCIMGroup, error) {
	directory, err := s.authenticateDirectory(ctx, directoryID, token)
	if err != nil {
		return SCIMGroup{}, err
	}
	var out SCIMGroup
	err = s.withDirectoryTx(ctx, directory, token, false, func(ctx context.Context, q *db.Queries, directory db.Directory) error {
		row, err := q.GetDirectoryGroupByID(ctx, db.GetDirectoryGroupByIDParams{DirectoryID: directory.ID, ID: strings.TrimSpace(groupID)})
		if errors.Is(err, pgx.ErrNoRows) {
			return apierr.New("not_found", "SCIM group was not found")
		}
		if err != nil {
			return err
		}
		out, err = loadSCIMGroup(ctx, q, row, includeMembers)
		return err
	})
	return out, err
}

func loadSCIMGroup(ctx context.Context, q *db.Queries, row db.DirectoryGroup, includeMembers bool) (SCIMGroup, error) {
	if !includeMembers {
		return scimGroupFromRow(row, nil), nil
	}
	members, err := q.ListDirectoryGroupUserIDs(ctx, db.ListDirectoryGroupUserIDsParams{
		DirectoryID: row.DirectoryID, DirectoryGroupID: row.ID,
	})
	return scimGroupFromRow(row, members), err
}

func (s *Service) ReplaceSCIMGroup(ctx context.Context, directoryID string, token secret.String, groupID string, in SCIMGroupInput, version int64) (SCIMGroup, error) {
	return s.mutateSCIMGroup(ctx, directoryID, token, groupID, in, nil, version, false)
}

func (s *Service) PatchSCIMGroup(ctx context.Context, directoryID string, token secret.String, groupID string, operations []SCIMGroupOperation, version int64) (SCIMGroup, error) {
	if len(operations) == 0 || len(operations) > 100 {
		return SCIMGroup{}, apierr.New("invalid_request", "SCIM PATCH requires 1 to 100 operations")
	}
	return s.mutateSCIMGroup(ctx, directoryID, token, groupID, SCIMGroupInput{}, operations, version, false)
}

func (s *Service) DeleteSCIMGroup(ctx context.Context, directoryID string, token secret.String, groupID string, version int64) error {
	_, err := s.mutateSCIMGroup(ctx, directoryID, token, groupID, SCIMGroupInput{}, nil, version, true)
	return err
}

func (s *Service) mutateSCIMGroup(ctx context.Context, directoryID string, token secret.String, groupID string, in SCIMGroupInput, operations []SCIMGroupOperation, version int64, deleting bool) (SCIMGroup, error) {
	directory, err := s.authenticateDirectory(ctx, directoryID, token)
	if err != nil {
		return SCIMGroup{}, err
	}
	var out SCIMGroup
	err = s.withDirectoryTx(ctx, directory, token, true, func(ctx context.Context, q *db.Queries, directory db.Directory) error {
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
		if deleting {
			children, err := q.CountLiveGroupChildren(ctx, db.CountLiveGroupChildrenParams{GroupID: pgtype.Text{String: row.GroupID, Valid: true}})
			if err != nil {
				return err
			}
			if children != 0 {
				return apierr.New("conflict", "remove child groups before deleting their root")
			}
			if err := s.syncDirectoryMembersTx(ctx, q, directory, row, nil, true); err != nil {
				return err
			}
			if err := q.DeleteDirectoryGroup(ctx, db.DeleteDirectoryGroupParams{DirectoryID: directory.ID, ID: row.ID, Version: version}); err != nil {
				return err
			}
			return writeSCIMGroupAudit(ctx, q, directory, row, "scim.group.delete")
		}
		if operations != nil {
			members, err := q.ListDirectoryGroupUserIDs(ctx, db.ListDirectoryGroupUserIDsParams{DirectoryID: directory.ID, DirectoryGroupID: row.ID})
			if err != nil {
				return err
			}
			in = SCIMGroupInput{ExternalID: row.ExternalID, DisplayName: row.DisplayName, MemberIDs: members}
			for _, op := range operations {
				if op.Op != "add" && op.Op != "replace" && op.Op != "remove" {
					return apierr.New("invalid_request", "SCIM PATCH operation is unsupported")
				}
				switch op.Path {
				case "displayname":
					if op.Op == "remove" {
						return apierr.New("invalid_request", "displayName cannot be removed")
					}
					in.DisplayName = op.DisplayName
				case "members":
					switch op.Op {
					case "add":
						in.MemberIDs = append(in.MemberIDs, op.MemberIDs...)
					case "replace":
						in.MemberIDs = slices.Clone(op.MemberIDs)
					case "remove":
						if op.MemberIDs == nil {
							in.MemberIDs = nil
						} else {
							in.MemberIDs = slices.DeleteFunc(in.MemberIDs, func(id string) bool { return slices.Contains(op.MemberIDs, id) })
						}
					}
				default:
					return apierr.New("invalid_request", "SCIM PATCH path is unsupported")
				}
				if len(in.MemberIDs) > 1000 {
					return apierr.New("invalid_request", "SCIM group member limit exceeded")
				}
			}
		}
		in.DisplayName = strings.TrimSpace(in.DisplayName)
		if !validSCIMGroupName(in.DisplayName) || len(in.MemberIDs) > 1000 || in.ExternalID != "" && in.ExternalID != row.ExternalID {
			return apierr.New("invalid_request", "SCIM group fields are invalid or externalId changed")
		}
		if err := s.syncDirectoryMembersTx(ctx, q, directory, row, in.MemberIDs, false); err != nil {
			return err
		}
		updated, err := q.UpdateDirectoryGroup(ctx, db.UpdateDirectoryGroupParams{DirectoryID: directory.ID, ID: row.ID, DisplayName: in.DisplayName, Version: row.Version})
		if err != nil {
			return err
		}
		if err := q.RenameDirectoryBackedGroup(ctx, db.RenameDirectoryBackedGroupParams{ID: row.GroupID, SpaceID: directory.SpaceID, Name: in.DisplayName}); err != nil {
			return err
		}
		members, err := q.ListDirectoryGroupUserIDs(ctx, db.ListDirectoryGroupUserIDsParams{DirectoryID: directory.ID, DirectoryGroupID: row.ID})
		if err != nil {
			return err
		}
		out = scimGroupFromRow(updated, members)
		return writeSCIMGroupAudit(ctx, q, directory, row, "scim.group.update")
	})
	return out, normalizeSCIMError(err)
}

func (s *Service) syncDirectoryMembersTx(ctx context.Context, q *db.Queries, directory db.Directory, group db.DirectoryGroup, userIDs []string, deleting bool) error {
	if s.Authorization == nil {
		return apierr.New("temporarily_unavailable", "directory authorization service is unavailable")
	}
	members, err := q.ListDirectoryBackedGroupMembers(ctx, db.ListDirectoryBackedGroupMembersParams{GroupID: group.GroupID})
	if err != nil {
		return err
	}
	for _, id := range userIDs {
		user, err := q.GetDirectoryUserByID(ctx, db.GetDirectoryUserByIDParams{DirectoryID: directory.ID, ID: strings.TrimSpace(id)})
		if errors.Is(err, pgx.ErrNoRows) || err == nil && !user.Active {
			return apierr.New("invalid_request", "group members must reference active users in this directory")
		}
		if err != nil {
			return err
		}
		members = append(members, user.MemberID)
	}
	slices.Sort(members)
	members = slices.Compact(members)
	if err := s.Authorization.ApplyDirectoryAuthorityTx(ctx, q, directory.ConfiguredByMemberID.String, directory.SpaceID, group.GroupID, members, func() error {
		if err := syncDirectoryGroupMembersTx(ctx, q, directory.ID, directory.SpaceID, group.ID, group.GroupID, userIDs); err != nil {
			return err
		}
		if deleting {
			return q.RemoveDirectoryBackedGroup(ctx, db.RemoveDirectoryBackedGroupParams{GroupID: group.GroupID, SpaceID: directory.SpaceID})
		}
		return nil
	}); err != nil {
		return err
	}
	_, err = q.BumpPolicyVersion(ctx, db.BumpPolicyVersionParams{ID: directory.SpaceID})
	return err
}

func validSCIMGroupName(name string) bool { return name != "" && len(name) <= 128 }

func writeSCIMGroupAudit(ctx context.Context, q *db.Queries, directory db.Directory, group db.DirectoryGroup, action string) error {
	space, err := q.GetSpace(ctx, db.GetSpaceParams{ID: directory.SpaceID})
	if err != nil {
		return err
	}
	return audit.WriteDirectoryEvent(ctx, q, audit.SecurityEvent{PolicyVersion: space.PolicyVersion, ActorType: "directory", ActorID: directory.ID, Action: action, Outcome: "success", Resource: audit.Resource{Type: "directory_group", ID: group.ID, SpaceID: directory.SpaceID, GroupID: group.GroupID}})
}
