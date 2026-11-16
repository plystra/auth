package agent

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/plystra/auth/internal/db"
)

type OwnerIdentity struct {
	MemberID   string `json:"member_id"`
	MemberType string `json:"member_type"`
	SpaceID    string `json:"space_id"`
}

// Identity contains only public identity facts, never credential material.
type Identity struct {
	MemberID   string
	SpaceID    string
	ExpiresAt  time.Time
	OwnerChain []OwnerIdentity
}

// IntrospectionIdentity resolves the current persisted ownership chain. Owner
// activity and authority remain authorization facts, evaluated by authz.check;
// an active credential does not confer the right to act on any resource.
func (s *Service) IntrospectionIdentity(ctx context.Context, memberID string) (Identity, bool, error) {
	q := s.Store.Queries()
	row, err := q.GetAgentMember(ctx, db.GetAgentMemberParams{MemberID: memberID})
	if errors.Is(err, pgx.ErrNoRows) {
		return Identity{}, false, nil
	}
	if err != nil {
		return Identity{}, false, err
	}
	if row.Status != "active" || row.GroupStatus != "active" || !row.ExpiresAt.Valid || !row.ExpiresAt.Time.After(time.Now().UTC()) {
		return Identity{}, false, nil
	}
	identity := Identity{MemberID: row.ID, SpaceID: row.SpaceID, ExpiresAt: row.ExpiresAt.Time}
	ownerID := row.OwnerMemberID.String
	seen := map[string]bool{row.ID: true}
	// Match the defensive bound used when signing the nested act claim. Stored
	// cycles or incomplete relationships must not produce a partial identity.
	for range 64 {
		if ownerID == "" || seen[ownerID] {
			return Identity{}, false, nil
		}
		seen[ownerID] = true
		owner, err := q.GetMemberForAgentOwner(ctx, db.GetMemberForAgentOwnerParams{MemberID: ownerID})
		if errors.Is(err, pgx.ErrNoRows) {
			return Identity{}, false, nil
		}
		if err != nil {
			return Identity{}, false, err
		}
		if owner.SpaceID != row.SpaceID || (owner.Type != "human" && owner.Type != "agent" && owner.Type != "application") {
			return Identity{}, false, nil
		}
		identity.OwnerChain = append(identity.OwnerChain, OwnerIdentity{MemberID: owner.ID, MemberType: owner.Type, SpaceID: owner.SpaceID})
		if owner.Type != "agent" {
			return identity, true, nil
		}
		parent, err := q.GetAgentMember(ctx, db.GetAgentMemberParams{MemberID: owner.ID})
		if errors.Is(err, pgx.ErrNoRows) {
			return Identity{}, false, nil
		}
		if err != nil {
			return Identity{}, false, err
		}
		ownerID = parent.OwnerMemberID.String
	}
	return Identity{}, false, nil
}
