package authorization

import (
	"bytes"
	"context"
	"errors"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/plystra/auth/internal/apierr"
	"github.com/plystra/auth/internal/authz/delta"
	"github.com/plystra/auth/internal/authz/engine"
	"github.com/plystra/auth/internal/db"
	"github.com/plystra/auth/internal/stepup"
)

const DirectoryGroupGrantOperation = "directory_groups.grants.create"

func DirectoryGroupGrantRequest(spaceID, directoryID, directoryGroupID string, in GrantInput) map[string]string {
	scope := in.Scope
	if scope == "" {
		scope = "space"
	}
	return map[string]string{
		"operation": DirectoryGroupGrantOperation, "space_id": spaceID, "directory_id": directoryID,
		"directory_group_id": directoryGroupID, "role_id": in.RoleID, "scope": scope,
		"anchor_space_id": in.AnchorSpaceID, "anchor_group_id": in.AnchorGroupID,
	}
}

func (s *Service) CreateDirectoryGroupGrant(ctx context.Context, actorID, spaceID, directoryID, directoryGroupID string, in GrantInput) (Grant, error) {
	if directoryID == "" || directoryGroupID == "" || in.RoleID == "" || len(in.Permissions) != 0 {
		return Grant{}, apierr.New("VALIDATION_FAILED", "a directory group grant requires a directory, group and role")
	}
	return s.createGroupGrant(ctx, actorID, spaceID, "", DirectoryGroupGrantRequest(spaceID, directoryID, directoryGroupID, in), in)
}

func directoryGrantGroupTx(ctx context.Context, q *db.Queries, request map[string]string) (string, error) {
	directory, err := q.GetDirectory(ctx, db.GetDirectoryParams{ID: request["directory_id"]})
	if errors.Is(err, pgx.ErrNoRows) || err == nil && (directory.Status != "active" || directory.SpaceID != request["space_id"]) {
		return "", apierr.New("NOT_FOUND", "the active directory group was not found")
	}
	if err != nil {
		return "", err
	}
	group, err := q.GetDirectoryGroupByID(ctx, db.GetDirectoryGroupByIDParams{DirectoryID: directory.ID, ID: request["directory_group_id"]})
	if errors.Is(err, pgx.ErrNoRows) {
		return "", apierr.New("NOT_FOUND", "the active directory group was not found")
	}
	return group.GroupID, err
}

func (s *Service) authorizeDirectoryGroupGrantTx(ctx context.Context, q *db.Queries, actorID string, request map[string]string) error {
	digest, err := stepup.DigestValue(request)
	if err != nil {
		return err
	}
	spaceID := request["space_id"]
	ctx = BindGovernanceApproval(ctx, DirectoryGroupGrantOperation, spaceID, digest)
	decision, err := s.checkGovernanceTx(ctx, q, CheckRequest{MemberID: actorID, Permission: "auth.connections:manage", ResourceSpace: spaceID})
	if err != nil {
		return err
	}
	if decision.Effect != engine.Allow {
		return apierr.New(decision.Code, "The authorization engine denied directory grant configuration.")
	}
	actor, err := q.GetMemberForAuthorization(ctx, db.GetMemberForAuthorizationParams{ID: actorID})
	if err != nil || actor.Type == "agent" {
		return err
	}
	proof, ok := stepup.RequirementFromContext(ctx)
	if !ok || proof.Operation != DirectoryGroupGrantOperation || !bytes.Equal(proof.Digest, digest) {
		return apierr.New("STEP_UP_REQUIRED", "complete step-up for this directory group grant")
	}
	issued, err := q.GetSession(ctx, db.GetSessionParams{ID: proof.SessionID})
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return err
	}
	if issued.UserID == "" || issued.UserID != HumanActorUserID(ctx, actorID) || issued.MemberID.Valid && issued.MemberID.String != actorID {
		return apierr.New("STEP_UP_REQUIRED", "complete step-up for this directory group grant")
	}
	return nil
}

func directoryGroupSnapshotTx(ctx context.Context, q *db.Queries, spaceID, groupID string) (delta.Snapshot, error) {
	// Model a future directory member using only the group's inherited grants.
	// Existing members may already have independent grants that mask this delta.
	rows, err := q.ListMemberAssignments(ctx, db.ListMemberAssignmentsParams{CohortGroupID: pgtype.Text{String: groupID, Valid: true}})
	if err != nil {
		return delta.Snapshot{}, err
	}
	assignments, _, err := assignmentsFromRows(ctx, q, rows, groupID, spaceID)
	if err != nil {
		return delta.Snapshot{}, err
	}
	return permissionSnapshot(assignments, groupID, delta.Node{Kind: delta.Group, ID: groupID}, "human"), nil
}

func (s *Service) coverDirectoryGroupDeltaTx(ctx context.Context, q *db.Queries, actorID, spaceID, groupID string, before delta.Snapshot) error {
	after, err := directoryGroupSnapshotTx(ctx, q, spaceID, groupID)
	if err != nil {
		return err
	}
	graph, err := grantDeltaGraphTx(ctx, q, before, after)
	if err != nil {
		return err
	}
	change, err := delta.Evaluate(before, after, graph)
	if err != nil {
		return err
	}
	return s.coverPositiveGrantDeltaTx(ctx, q, change, actorID, groupID, "human", spaceID)
}
