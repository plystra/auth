package authorization

import (
	"context"
	"errors"
	"slices"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/plystra/auth/internal/authz/engine"
	"github.com/plystra/auth/internal/db"
)

// ValidateTokenScopes checks that each requested credential restriction has a
// usable resource within the member's current authority. It does not authorize
// execution: every protected operation still needs Check on its actual resource.
func (s *Service) ValidateTokenScopes(ctx context.Context, memberID string, permissions []string) (bool, error) {
	allowed := false
	err := s.Store.InTx(ctx, func(q *db.Queries) error {
		var err error
		allowed, err = s.ValidateTokenScopesTx(ctx, q, memberID, permissions)
		return err
	})
	return allowed, err
}

// ValidateTokenScopesTx evaluates current authority in the credential issuance
// transaction. The caller holds the member and owner-chain lifecycle locks.
func (s *Service) ValidateTokenScopesTx(ctx context.Context, q *db.Queries, memberID string, permissions []string) (bool, error) {
	member, err := q.GetMemberForAuthorization(ctx, db.GetMemberForAuthorizationParams{ID: memberID})
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	type target struct{ space, group string }
	targets := []target{{space: member.SpaceID}}
	seenTargets := map[target]bool{targets[0]: true}
	seenMembers := map[string]bool{}
	current := memberID
	for depth := 0; current != ""; depth++ {
		if seenMembers[current] || depth > s.maxDelegationDepth() {
			return false, nil
		}
		seenMembers[current] = true
		assignments, err := q.ListMemberAssignments(ctx, db.ListMemberAssignmentsParams{MemberID: pgtype.Text{String: current, Valid: true}})
		if err != nil {
			return false, err
		}
		for _, assignment := range assignments {
			if !slices.Contains(permissions, assignment.PermissionKey) {
				continue
			}
			candidate := target{space: member.SpaceID}
			switch assignment.Scope {
			case "space", "space_tree":
				candidate.space = assignment.AnchorSpaceID.String
			case "group", "group_tree":
				candidate.group = assignment.AnchorGroupID.String
				candidate.space, err = q.GetGroupSpaceForAuthorization(ctx, db.GetGroupSpaceForAuthorizationParams{ID: candidate.group})
				if errors.Is(err, pgx.ErrNoRows) {
					continue
				}
				if err != nil {
					return false, err
				}
			}
			if !seenTargets[candidate] {
				seenTargets[candidate] = true
				targets = append(targets, candidate)
			}
		}
		agent, err := q.GetAgentMember(ctx, db.GetAgentMemberParams{MemberID: current})
		if errors.Is(err, pgx.ErrNoRows) {
			break
		}
		if err != nil {
			return false, err
		}
		current = agent.OwnerMemberID.String
	}
	// Scope intersections change only at persisted Space/group boundaries.
	// Include every owner's boundaries: a broad child grant can be usable
	// only inside a narrower owner grant. These candidates never grant access;
	// CheckTx still enforces directory, envelopes, ancestry and approval.
	for _, permission := range permissions {
		usable := false
		for _, candidate := range targets {
			decision, err := s.CheckTx(ctx, q, CheckRequest{
				MemberID: memberID, Permission: permission,
				ResourceSpace: candidate.space, ResourceGroup: candidate.group,
				// Self authority includes resources of the acting member and
				// resolves upward through the persisted ownership chain.
				ResourceOwner: memberID,
			})
			if err != nil {
				return false, err
			}
			if decision.Effect == engine.Allow {
				usable = true
				break
			}
		}
		if !usable {
			return false, nil
		}
	}
	return true, nil
}
