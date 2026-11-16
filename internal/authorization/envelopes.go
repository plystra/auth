package authorization

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"
	"github.com/plystra/auth/internal/authz/delta"
	"github.com/plystra/auth/internal/db"
)

type envelopeFacts struct {
	q          *db.Queries
	spaceCache map[string]bool
	groupCache map[string]bool
}

func newEnvelopeFacts(q *db.Queries) *envelopeFacts {
	return &envelopeFacts{q: q, spaceCache: map[string]bool{}, groupCache: map[string]bool{}}
}

func (f *envelopeFacts) permitsAssignment(ctx context.Context, row db.ListMemberAssignmentsRow, memberSpaceID string) (bool, error) {
	for _, spaceID := range []string{memberSpaceID, row.SpaceID} {
		allowed, err := f.space(ctx, spaceID, row.PermissionKey)
		if err != nil || !allowed {
			return allowed, err
		}
	}
	if row.GranteeGroupID.Valid {
		allowed, err := f.group(ctx, row.GranteeGroupID.String, row.SpaceID, row.PermissionKey)
		if err != nil || !allowed {
			return allowed, err
		}
	}
	if row.AnchorSpaceID.Valid {
		allowed, err := f.space(ctx, row.AnchorSpaceID.String, row.PermissionKey)
		if err != nil || !allowed {
			return allowed, err
		}
	}
	if row.AnchorGroupID.Valid {
		anchorSpace, err := f.q.GetGroupSpaceForAuthorization(ctx, db.GetGroupSpaceForAuthorizationParams{ID: row.AnchorGroupID.String})
		if errors.Is(err, pgx.ErrNoRows) {
			return false, nil
		}
		if err != nil {
			return false, err
		}
		return f.group(ctx, row.AnchorGroupID.String, anchorSpace, row.PermissionKey)
	}
	return true, nil
}

func (f *envelopeFacts) space(ctx context.Context, spaceID, permission string) (bool, error) {
	key := spaceID + "\x00" + permission
	if allowed, ok := f.spaceCache[key]; ok {
		return allowed, nil
	}
	ancestors, err := spaceAncestorsQueries(ctx, f.q, spaceID)
	if err != nil {
		if errors.Is(err, errSpaceInactive) {
			return false, nil
		}
		return false, err
	}
	chain := append([]string{spaceID}, ancestors...)
	allowed := true
	for i := len(chain) - 1; i >= 0; i-- {
		_, err := f.q.GetSpace(ctx, db.GetSpaceParams{ID: chain[i]})
		if errors.Is(err, pgx.ErrNoRows) {
			return false, nil
		}
		if err != nil {
			return false, err
		}
		mode, err := f.q.GetSpaceEnvelopePermission(ctx, db.GetSpaceEnvelopePermissionParams{SpaceID: chain[i], PermissionKey: permission})
		if errors.Is(err, pgx.ErrNoRows) {
			continue
		}
		if err != nil {
			return false, err
		}
		allowed = allowed && mode.Valid
	}
	f.spaceCache[key] = allowed
	return allowed, nil
}

func (f *envelopeFacts) group(ctx context.Context, groupID, spaceID, permission string) (bool, error) {
	key := groupID + "\x00" + permission
	if allowed, ok := f.groupCache[key]; ok {
		return allowed, nil
	}
	allowed, err := f.space(ctx, spaceID, permission)
	if err != nil || !allowed {
		return allowed, err
	}
	ancestors, err := groupAncestorsQueries(ctx, f.q, groupID, spaceID)
	if err != nil {
		if errors.Is(err, errGroupInactive) {
			return false, nil
		}
		return false, err
	}
	chain := append([]string{groupID}, ancestors...)
	for i := len(chain) - 1; i >= 0; i-- {
		group, err := f.q.GetGroupInSpace(ctx, db.GetGroupInSpaceParams{ID: chain[i], SpaceID: spaceID})
		if errors.Is(err, pgx.ErrNoRows) {
			return false, nil
		}
		if err != nil {
			return false, err
		}
		if group.Status != "active" {
			return false, nil
		}
		mode, err := f.q.GetGroupEnvelopePermission(ctx, db.GetGroupEnvelopePermissionParams{GroupID: chain[i], PermissionKey: permission})
		if errors.Is(err, pgx.ErrNoRows) {
			continue
		}
		if err != nil {
			return false, err
		}
		if !mode.Valid {
			f.groupCache[key] = false
			return false, nil
		}
	}
	f.groupCache[key] = true
	return true, nil
}

func (f *envelopeFacts) grantMode(ctx context.Context, node delta.Node, spaceID, permission string, delegable bool) (int, error) {
	base := 1
	if delegable {
		base = 3
	}
	ancestors, err := spaceAncestorsQueries(ctx, f.q, spaceID)
	if err != nil {
		return 0, err
	}
	for _, id := range append([]string{spaceID}, ancestors...) {
		mode, err := f.q.GetSpaceEnvelopePermission(ctx, db.GetSpaceEnvelopePermissionParams{SpaceID: id, PermissionKey: permission})
		if errors.Is(err, pgx.ErrNoRows) {
			continue
		}
		if err != nil {
			return 0, err
		}
		base = min(base, envelopeModeRank(mode.String))
	}
	if node.Kind == delta.Space {
		return base, nil
	}
	if node.Kind != delta.Group {
		return 0, nil
	}
	groupAncestors, err := groupAncestorsQueries(ctx, f.q, node.ID, spaceID)
	if err != nil {
		return 0, err
	}
	for _, id := range append([]string{node.ID}, groupAncestors...) {
		mode, err := f.q.GetGroupEnvelopePermission(ctx, db.GetGroupEnvelopePermissionParams{GroupID: id, PermissionKey: permission})
		if errors.Is(err, pgx.ErrNoRows) {
			continue
		}
		if err != nil {
			return 0, err
		}
		base = min(base, envelopeModeRank(mode.String))
	}
	return base, nil
}

func envelopeModeRank(mode string) int {
	switch mode {
	case "use":
		return 1
	case "assign":
		return 2
	case "delegate":
		return 3
	default:
		return 0
	}
}
