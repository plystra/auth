package member

import (
	"context"
	"errors"
	"sort"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/plystra/auth/internal/db"
)

// LockChainsTx uses one lock order for authorization writes, Agent creation,
// and subtree revocation. A creator holds every owner so a concurrent ancestor
// revocation cannot miss a child committed after its subtree query began.
func LockChainsTx(ctx context.Context, q *db.Queries, memberIDs ...string) error {
	ids := make(map[string]struct{}, len(memberIDs))
	pending := make([]string, 0, len(memberIDs))
	for _, id := range memberIDs {
		if strings.TrimSpace(id) == "" {
			continue
		}
		if _, ok := ids[id]; !ok {
			ids[id] = struct{}{}
			pending = append(pending, id)
		}
	}
	for len(pending) > 0 {
		id := pending[0]
		pending = pending[1:]
		agent, err := q.GetAgentMember(ctx, db.GetAgentMemberParams{MemberID: id})
		if errors.Is(err, pgx.ErrNoRows) {
			continue
		}
		if err != nil {
			return err
		}
		if !agent.OwnerMemberID.Valid || strings.TrimSpace(agent.OwnerMemberID.String) == "" {
			continue
		}
		ownerID := agent.OwnerMemberID.String
		if _, ok := ids[ownerID]; !ok {
			ids[ownerID] = struct{}{}
			pending = append(pending, ownerID)
		}
	}
	ordered := make([]string, 0, len(ids))
	for id := range ids {
		ordered = append(ordered, id)
	}
	sort.Strings(ordered)
	for _, id := range ordered {
		if _, err := q.LockMemberForAuthorization(ctx, db.LockMemberForAuthorizationParams{ID: id}); err != nil && !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
	}
	return nil
}
