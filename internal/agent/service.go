package agent

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/plystra/auth/internal/apierr"
	"github.com/plystra/auth/internal/audit"
	"github.com/plystra/auth/internal/db"
	"github.com/plystra/auth/internal/ids"
	"github.com/plystra/auth/internal/store"
)

const maxLifetime = 90 * 24 * time.Hour
const oauthRefreshLifetime = 30 * 24 * time.Hour

type Service struct {
	Store              *store.Store
	MaxDelegationDepth int
	HMACKeys           [][]byte
	hmacOnce           sync.Once
	ephemeralHMACKey   []byte
}

const defaultMaxDelegationDepth = 8

func (s *Service) maxDelegationDepth() int {
	if s != nil && s.MaxDelegationDepth > 0 {
		return s.MaxDelegationDepth
	}
	return defaultMaxDelegationDepth
}

type Agent struct {
	ID              string    `json:"id"`
	SpaceID         string    `json:"space_id"`
	Name            string    `json:"name"`
	Type            string    `json:"type"`
	Status          string    `json:"status"`
	HomeGroupID     string    `json:"home_group_id"`
	OwnerMemberID   string    `json:"owner_member_id"`
	CreatedByUserID string    `json:"created_by_user_id,omitempty"`
	CreatedByMember string    `json:"created_by_member_id"`
	Source          string    `json:"source"`
	ExpiresAt       time.Time `json:"expires_at"`
	Version         int64     `json:"version"`
}

type CreateInput struct {
	OwnerMemberID string
	CreatedByUser string
	Name          string
	ExpiresAt     time.Time
	Source        string
}

type Credential struct {
	ID          string
	MemberID    string
	SpaceID     string
	Kind        string
	Prefix      string
	SecretHash  []byte
	FamilyID    string
	ExpiresAt   time.Time
	Revoked     bool
	MemberState string
	HomeGroupID string
}

type agentsGroup struct {
	ID            string
	OwnerMemberID pgtype.Text
}

func (s *Service) Create(ctx context.Context, in CreateInput) (Agent, string, error) {
	in.Name = strings.TrimSpace(in.Name)
	if in.Name == "" || len(in.Name) > 128 {
		return Agent{}, "", apierr.New("VALIDATION_FAILED", "agent name is invalid")
	}
	if in.Source == "" {
		in.Source = "manual"
	}
	if in.Source != "manual" && in.Source != "oauth" && in.Source != "delegation" {
		return Agent{}, "", apierr.New("VALIDATION_FAILED", "agent source is invalid")
	}
	if in.ExpiresAt.IsZero() {
		in.ExpiresAt = time.Now().UTC().Add(30 * 24 * time.Hour)
	}
	now := time.Now().UTC()
	if !in.ExpiresAt.After(now) || in.ExpiresAt.After(now.Add(maxLifetime)) {
		return Agent{}, "", apierr.New("VALIDATION_FAILED", "agent expiry must be within 90 days")
	}
	raw, prefix, hash, err := s.generateCredential()
	if err != nil {
		return Agent{}, "", err
	}
	var out Agent
	err = s.Store.InTx(ctx, func(q *db.Queries) error {
		owner, err := q.GetMemberForAgentOwner(ctx, db.GetMemberForAgentOwnerParams{MemberID: in.OwnerMemberID})
		if err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return apierr.New("SUBJECT_NOT_FOUND", "owner member was not found")
			}
			return err
		}
		if owner.Status != "active" || (owner.ExpiresAt.Valid && !owner.ExpiresAt.Time.After(now)) {
			return apierr.New("OWNER_INACTIVE", "owner member is not active")
		}
		if owner.Type != "human" && owner.Type != "agent" && owner.Type != "application" {
			return apierr.New("VALIDATION_FAILED", "owner member type is invalid")
		}
		if err := s.validateDelegationDepthTx(ctx, q, owner.ID); err != nil {
			return err
		}
		parentID := pgtype.Text{}
		if owner.Type == "agent" {
			if !owner.HomeGroupID.Valid {
				return apierr.New("OWNER_INACTIVE", "agent owner has no home group")
			}
			parentID = owner.HomeGroupID
			if owner.ExpiresAt.Valid && in.ExpiresAt.After(owner.ExpiresAt.Time) {
				return apierr.New("VALIDATION_FAILED", "agent expiry cannot exceed owner expiry")
			}
		}
		group, err := s.ensureGroupTx(ctx, q, owner, parentID)
		if err != nil {
			return err
		}
		createdByUser := pgtype.Text{String: in.CreatedByUser, Valid: in.CreatedByUser != ""}
		member, err := q.CreateAgentMember(ctx, db.CreateAgentMemberParams{
			ID: string(ids.New[ids.MemberID]("mem")), SpaceID: owner.SpaceID, Name: in.Name,
			HomeGroupID: pgtype.Text{String: group.ID, Valid: true}, CreatedByUserID: createdByUser,
			CreatedByMemberID: pgtype.Text{String: in.OwnerMemberID, Valid: true}, Source: pgtype.Text{String: in.Source, Valid: true}, ExpiresAt: pgTime(in.ExpiresAt),
		})
		if err != nil {
			return normalize(err)
		}
		if err := q.AddAgentToGroup(ctx, db.AddAgentToGroupParams{GroupID: group.ID, MemberID: member.ID}); err != nil {
			return err
		}
		cred, err := q.CreateAgentCredential(ctx, db.CreateAgentCredentialParams{ID: string(ids.New[ids.ID]("crd")), MemberID: member.ID, Prefix: prefix, SecretHash: hash, ExpiresAt: pgTime(in.ExpiresAt)})
		if err != nil {
			return normalize(err)
		}
		if err := audit.Write(ctx, q, "member", in.OwnerMemberID, "agent.create", member.ID, "success"); err != nil {
			return err
		}
		out = Agent{ID: member.ID, SpaceID: member.SpaceID, Name: member.Name, Type: member.Type, Status: member.Status, HomeGroupID: member.HomeGroupID.String, CreatedByMember: member.CreatedByMemberID.String, Source: member.Source.String, ExpiresAt: member.ExpiresAt.Time, Version: member.Version}
		if member.CreatedByUserID.Valid {
			out.CreatedByUserID = member.CreatedByUserID.String
		}
		if group.OwnerMemberID.Valid {
			out.OwnerMemberID = group.OwnerMemberID.String
		}
		_ = cred
		return nil
	})
	if err != nil {
		return Agent{}, "", err
	}
	return out, raw, nil
}

func (s *Service) validateDelegationDepthTx(ctx context.Context, q *db.Queries, ownerMemberID string) error {
	depth := 1 // the Agent being created is the first delegation level
	current := ownerMemberID
	seen := map[string]struct{}{}
	for {
		if _, ok := seen[current]; ok {
			return apierr.New("OWNER_INACTIVE", "the Agent owner chain contains a cycle")
		}
		seen[current] = struct{}{}
		owner, err := q.GetMemberForAgentOwner(ctx, db.GetMemberForAgentOwnerParams{MemberID: current})
		if errors.Is(err, pgx.ErrNoRows) {
			return apierr.New("OWNER_INACTIVE", "the Agent owner member was not found")
		}
		if err != nil {
			return err
		}
		if owner.Status != "active" {
			return apierr.New("OWNER_INACTIVE", "the Agent owner member is not active")
		}
		if owner.Type != "agent" {
			return nil
		}
		if depth >= s.maxDelegationDepth() {
			return apierr.New("VALIDATION_FAILED", "Agent delegation depth exceeds the configured maximum")
		}
		agent, err := q.GetAgentMember(ctx, db.GetAgentMemberParams{MemberID: current})
		if errors.Is(err, pgx.ErrNoRows) {
			return apierr.New("OWNER_INACTIVE", "the Agent owner record was not found")
		}
		if err != nil {
			return err
		}
		if !agent.OwnerMemberID.Valid || strings.TrimSpace(agent.OwnerMemberID.String) == "" {
			return apierr.New("OWNER_INACTIVE", "the Agent owner is missing")
		}
		current = agent.OwnerMemberID.String
		depth++
	}
}

func (s *Service) ensureGroupTx(ctx context.Context, q *db.Queries, owner db.GetMemberForAgentOwnerRow, parentID pgtype.Text) (agentsGroup, error) {
	if existing, err := q.GetAgentsGroupByOwner(ctx, db.GetAgentsGroupByOwnerParams{OwnerMemberID: pgtype.Text{String: owner.ID, Valid: true}}); err == nil {
		if existing.Status != "active" {
			return agentsGroup{}, apierr.New("CONFLICT", "owner agent group is not active")
		}
		return agentsGroup{ID: existing.ID, OwnerMemberID: existing.OwnerMemberID}, nil
	} else if !errors.Is(err, pgx.ErrNoRows) {
		return agentsGroup{}, err
	}
	created, err := q.CreateAgentsGroup(ctx, db.CreateAgentsGroupParams{
		ID: string(ids.New[ids.GroupID]("grp")), SpaceID: owner.SpaceID,
		Name: "agents-" + owner.ID, ParentID: parentID,
		OwnerMemberID: pgtype.Text{String: owner.ID, Valid: true},
	})
	if err != nil {
		return agentsGroup{}, err
	}
	return agentsGroup{ID: created.ID, OwnerMemberID: created.OwnerMemberID}, nil
}

func (s *Service) List(ctx context.Context, ownerMemberID string) ([]Agent, error) {
	group, err := s.Store.Queries().GetAgentsGroupByOwner(ctx, db.GetAgentsGroupByOwnerParams{OwnerMemberID: pgtype.Text{String: ownerMemberID, Valid: true}})
	if errors.Is(err, pgx.ErrNoRows) {
		return []Agent{}, nil
	}
	if err != nil {
		return nil, err
	}
	rows, err := s.Store.Queries().ListAgentsForGroup(ctx, db.ListAgentsForGroupParams{GroupID: group.ID})
	if err != nil {
		return nil, err
	}
	out := make([]Agent, 0, len(rows))
	for _, row := range rows {
		out = append(out, agentFromList(row, group.OwnerMemberID.String))
	}
	return out, nil
}

func (s *Service) Owner(ctx context.Context, memberID string) (string, error) {
	row, err := s.Store.Queries().GetAgentMember(ctx, db.GetAgentMemberParams{MemberID: memberID})
	if errors.Is(err, pgx.ErrNoRows) {
		return "", apierr.New("SUBJECT_NOT_FOUND", "agent was not found")
	}
	if err != nil {
		return "", err
	}
	if !row.OwnerMemberID.Valid || row.OwnerMemberID.String == "" {
		return "", apierr.New("OWNER_INACTIVE", "agent owner is missing")
	}
	return row.OwnerMemberID.String, nil
}

// CanManage reports whether actor is the Agent itself or an owner ancestor in
// the immutable "my agents" group tree.
func (s *Service) CanManage(ctx context.Context, actorMemberID, agentMemberID string) (bool, error) {
	return s.Store.Queries().CanManageAgent(ctx, db.CanManageAgentParams{OwnerMemberID: actorMemberID, TargetMemberID: agentMemberID})
}

func (s *Service) Get(ctx context.Context, memberID string) (Agent, error) {
	row, err := s.Store.Queries().GetAgentMember(ctx, db.GetAgentMemberParams{MemberID: memberID})
	if errors.Is(err, pgx.ErrNoRows) {
		return Agent{}, apierr.New("NOT_FOUND", "agent was not found")
	}
	if err != nil {
		return Agent{}, err
	}
	if !row.OwnerMemberID.Valid {
		return Agent{}, apierr.New("OWNER_INACTIVE", "agent owner is missing")
	}
	out := Agent{ID: row.ID, SpaceID: row.SpaceID, Name: row.Name, Type: row.Type, Status: row.Status, HomeGroupID: row.HomeGroupID.String, OwnerMemberID: row.OwnerMemberID.String, CreatedByMember: row.CreatedByMemberID.String, Source: row.Source.String, ExpiresAt: row.ExpiresAt.Time, Version: row.Version}
	if row.CreatedByUserID.Valid {
		out.CreatedByUserID = row.CreatedByUserID.String
	}
	return out, nil
}

func (s *Service) Rotate(ctx context.Context, ownerMemberID, memberID string) (string, error) {
	raw, prefix, hash, err := s.generateCredential()
	if err != nil {
		return "", err
	}
	var expires time.Time
	err = s.Store.InTx(ctx, func(q *db.Queries) error {
		row, err := q.GetAgentMember(ctx, db.GetAgentMemberParams{MemberID: memberID})
		if err != nil {
			return apierr.New("NOT_FOUND", "agent was not found")
		}
		if canManage, err := q.CanManageAgent(ctx, db.CanManageAgentParams{OwnerMemberID: ownerMemberID, TargetMemberID: memberID}); err != nil {
			return err
		} else if !canManage {
			return apierr.New("PERMISSION_DENIED", "agent is outside the current member's agent tree")
		}
		if row.Status != "active" || row.GroupStatus != "active" {
			return apierr.New("CONFLICT", "agent is not active")
		}
		expires = row.ExpiresAt.Time
		if err := q.RevokeAgentCredentials(ctx, db.RevokeAgentCredentialsParams{MemberID: memberID}); err != nil {
			return err
		}
		_, err = q.CreateAgentCredential(ctx, db.CreateAgentCredentialParams{ID: string(ids.New[ids.ID]("crd")), MemberID: memberID, Prefix: prefix, SecretHash: hash, ExpiresAt: pgTime(expires)})
		if err != nil {
			return normalize(err)
		}
		return audit.Write(ctx, q, "member", ownerMemberID, "agent.credential.rotate", memberID, "success")
	})
	if err != nil {
		return "", err
	}
	return raw, nil
}

// CreateOAuthRefreshCredential creates the opaque, one-time credential used
// by an OAuth-authorized Agent. The credential is stored as an HMAC digest and
// is never returned again after this call.
func (s *Service) CreateOAuthRefreshCredential(ctx context.Context, memberID string, expiresAt time.Time) (string, error) {
	now := time.Now().UTC()
	if expiresAt.IsZero() {
		expiresAt = now.Add(oauthRefreshLifetime)
	}
	if !expiresAt.After(now) {
		return "", apierr.New("VALIDATION_FAILED", "OAuth refresh credential expiry must be in the future")
	}
	raw, prefix, hash, err := s.generateOAuthRefreshCredential()
	if err != nil {
		return "", err
	}
	family := ids.New[ids.RefreshFamilyID]("rtf")
	err = s.Store.InTx(ctx, func(q *db.Queries) error {
		member, err := q.GetAgentMember(ctx, db.GetAgentMemberParams{MemberID: memberID})
		if errors.Is(err, pgx.ErrNoRows) {
			return apierr.New("NOT_FOUND", "agent was not found")
		}
		if err != nil {
			return err
		}
		if member.Status != "active" || member.GroupStatus != "active" {
			return apierr.New("CONFLICT", "agent is not active")
		}
		if member.ExpiresAt.Valid && !member.ExpiresAt.Time.After(now) {
			return apierr.New("CONFLICT", "agent is expired")
		}
		if member.ExpiresAt.Valid && expiresAt.After(member.ExpiresAt.Time) {
			expiresAt = member.ExpiresAt.Time
		}
		if !expiresAt.After(now) {
			return apierr.New("VALIDATION_FAILED", "OAuth refresh credential expiry exceeds the agent lifetime")
		}
		if _, err := q.CreateOAuthRefreshCredential(ctx, db.CreateOAuthRefreshCredentialParams{
			ID: string(ids.New[ids.ID]("crd")), MemberID: memberID, Prefix: prefix,
			SecretHash: hash, FamilyID: pgtype.Text{String: string(family), Valid: true}, ExpiresAt: pgTime(expiresAt),
		}); err != nil {
			return normalize(err)
		}
		return audit.Write(ctx, q, "member", memberID, "agent.oauth_refresh.create", memberID, "success")
	})
	if err != nil {
		return "", err
	}
	return raw, nil
}

// RotateOAuthRefresh atomically consumes an OAuth refresh credential and
// creates its successor. A replay revokes the entire credential family.
func (s *Service) RotateOAuthRefresh(ctx context.Context, raw string) (Credential, string, error) {
	raw = strings.TrimSpace(raw)
	if !strings.HasPrefix(raw, "ply_rt_") || raw == "" {
		return Credential{}, "", apierr.New("invalid_grant", "OAuth refresh token is invalid")
	}
	now := time.Now().UTC()
	next, prefix, hash, err := s.generateOAuthRefreshCredential()
	if err != nil {
		return Credential{}, "", err
	}
	family := ""
	var out Credential
	replayed := false
	err = s.Store.InTx(ctx, func(q *db.Queries) error {
		var row db.LockOAuthRefreshCredentialByHashRow
		found := false
		for _, candidate := range s.credentialHMACKeys() {
			mac := hmac.New(sha256.New, candidate)
			_, _ = mac.Write([]byte(raw))
			row, err = q.LockOAuthRefreshCredentialByHash(ctx, db.LockOAuthRefreshCredentialByHashParams{SecretHash: mac.Sum(nil)})
			if err == nil {
				found = true
				break
			}
			if !errors.Is(err, pgx.ErrNoRows) {
				return err
			}
		}
		if !found {
			return apierr.New("invalid_grant", "OAuth refresh token is invalid")
		}
		if row.FamilyID.Valid {
			family = row.FamilyID.String
		}
		if row.LastUsedAt.Valid {
			replayed = true
			if family != "" {
				if err := q.RevokeAgentCredentialFamily(ctx, db.RevokeAgentCredentialFamilyParams{FamilyID: pgtype.Text{String: family, Valid: true}}); err != nil {
					return err
				}
			}
			return audit.WriteWithPriority(ctx, q, "member", row.MemberID, "agent.oauth_refresh.replay", row.MemberID, "failure", "high")
		}
		if row.RevokedAt.Valid || !row.ExpiresAt.Time.After(now) || row.MemberStatus != "active" {
			if family != "" {
				if err := q.RevokeAgentCredentialFamily(ctx, db.RevokeAgentCredentialFamilyParams{FamilyID: pgtype.Text{String: family, Valid: true}}); err != nil {
					return err
				}
			}
			return apierr.New("invalid_grant", "OAuth refresh token is invalid")
		}
		if _, err := q.MarkAgentCredentialUsed(ctx, db.MarkAgentCredentialUsedParams{ID: row.ID}); err != nil {
			return err
		}
		expiresAt := now.Add(oauthRefreshLifetime)
		if row.ExpiresAt.Time.Before(expiresAt) {
			expiresAt = row.ExpiresAt.Time
		}
		member, err := q.GetAgentMember(ctx, db.GetAgentMemberParams{MemberID: row.MemberID})
		if err != nil {
			return err
		}
		if member.ExpiresAt.Valid && member.ExpiresAt.Time.Before(expiresAt) {
			expiresAt = member.ExpiresAt.Time
		}
		if !expiresAt.After(now) {
			return apierr.New("invalid_grant", "OAuth refresh token is expired")
		}
		if _, err := q.CreateOAuthRefreshCredential(ctx, db.CreateOAuthRefreshCredentialParams{
			ID: string(ids.New[ids.ID]("crd")), MemberID: row.MemberID, Prefix: prefix,
			SecretHash: hash, FamilyID: pgtype.Text{String: family, Valid: family != ""}, ExpiresAt: pgTime(expiresAt),
		}); err != nil {
			return normalize(err)
		}
		out = Credential{ID: row.ID, MemberID: row.MemberID, SpaceID: row.SpaceID, Kind: row.Kind, Prefix: row.Prefix, SecretHash: row.SecretHash, FamilyID: family, ExpiresAt: expiresAt, MemberState: row.MemberStatus, HomeGroupID: row.HomeGroupID.String}
		return audit.Write(ctx, q, "member", row.MemberID, "agent.oauth_refresh", row.MemberID, "success")
	})
	if err != nil {
		return Credential{}, "", err
	}
	if replayed {
		return Credential{}, "", apierr.New("invalid_grant", "OAuth refresh token replayed")
	}
	return out, next, nil
}

func (s *Service) Stop(ctx context.Context, ownerMemberID, memberID string) error {
	return s.mutate(ctx, ownerMemberID, memberID, "stop", func(q *db.Queries, groupID string) error {
		return q.StopAgentSubtree(ctx, db.StopAgentSubtreeParams{GroupID: groupID})
	})
}

func (s *Service) Delete(ctx context.Context, ownerMemberID, memberID string) error {
	return s.mutate(ctx, ownerMemberID, memberID, "delete", func(q *db.Queries, groupID string) error {
		if err := q.DeleteAgentSubtree(ctx, db.DeleteAgentSubtreeParams{GroupID: groupID}); err != nil {
			return err
		}
		if err := q.RevokeAgentGrantsInGroupSubtree(ctx, db.RevokeAgentGrantsInGroupSubtreeParams{GroupID: groupID}); err != nil {
			return err
		}
		if err := q.RevokeGroupGrantsInGroupSubtree(ctx, db.RevokeGroupGrantsInGroupSubtreeParams{GroupID: groupID}); err != nil {
			return err
		}
		return q.RemoveAgentGroupSubtree(ctx, db.RemoveAgentGroupSubtreeParams{GroupID: groupID})
	})
}

// ExpireAgents turns every expired active Agent into a tombstone. Each root is
// handled in one transaction with its descendant members, groups, credentials,
// and audit event so an interrupted cleanup cannot leave a partially live
// delegation subtree.
func (s *Service) ExpireAgents(ctx context.Context) (int, error) {
	count := 0
	err := s.Store.InTx(ctx, func(q *db.Queries) error {
		roots, err := q.ListExpiredAgentRoots(ctx)
		if err != nil {
			return err
		}
		for _, root := range roots {
			member, err := q.GetAgentMember(ctx, db.GetAgentMemberParams{MemberID: root.ID})
			if errors.Is(err, pgx.ErrNoRows) {
				continue
			}
			if err != nil {
				return err
			}
			if member.Status != "active" || !member.ExpiresAt.Valid || member.ExpiresAt.Time.After(time.Now().UTC()) {
				continue
			}
			if !member.HomeGroupID.Valid {
				return apierr.New("OWNER_INACTIVE", "expired Agent has no home group")
			}
			groupID := member.HomeGroupID.String
			if err := q.DeleteAgentSubtree(ctx, db.DeleteAgentSubtreeParams{GroupID: groupID}); err != nil {
				return err
			}
			if err := q.RevokeAgentGrantsInGroupSubtree(ctx, db.RevokeAgentGrantsInGroupSubtreeParams{GroupID: groupID}); err != nil {
				return err
			}
			if err := q.RevokeGroupGrantsInGroupSubtree(ctx, db.RevokeGroupGrantsInGroupSubtreeParams{GroupID: groupID}); err != nil {
				return err
			}
			if err := q.RemoveAgentGroupSubtree(ctx, db.RemoveAgentGroupSubtreeParams{GroupID: groupID}); err != nil {
				return err
			}
			if err := q.RevokeAgentCredentialsInGroupSubtree(ctx, db.RevokeAgentCredentialsInGroupSubtreeParams{GroupID: groupID}); err != nil {
				return err
			}
			if err := audit.Write(ctx, q, "system", "", "agent.expire", member.ID, "success"); err != nil {
				return err
			}
			count++
		}
		return nil
	})
	return count, err
}

func (s *Service) mutate(ctx context.Context, ownerMemberID, memberID, action string, fn func(*db.Queries, string) error) error {
	return s.Store.InTx(ctx, func(q *db.Queries) error {
		row, err := q.GetAgentMember(ctx, db.GetAgentMemberParams{MemberID: memberID})
		if err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return apierr.New("NOT_FOUND", "agent was not found")
			}
			return err
		}
		if canManage, err := q.CanManageAgent(ctx, db.CanManageAgentParams{OwnerMemberID: ownerMemberID, TargetMemberID: memberID}); err != nil {
			return err
		} else if !canManage {
			return apierr.New("PERMISSION_DENIED", "agent is outside the current member's agent tree")
		}
		if !row.HomeGroupID.Valid {
			return apierr.New("CONFLICT", "agent home group is missing")
		}
		if err := fn(q, row.HomeGroupID.String); err != nil {
			return err
		}
		if err := q.RevokeAgentCredentialsInGroupSubtree(ctx, db.RevokeAgentCredentialsInGroupSubtreeParams{GroupID: row.HomeGroupID.String}); err != nil {
			return err
		}
		return audit.Write(ctx, q, "member", ownerMemberID, "agent."+action, memberID, "success")
	})
}

func (s *Service) AuthenticateKey(ctx context.Context, raw string) (Credential, error) {
	parts := strings.SplitN(strings.TrimSpace(raw), ".", 2)
	if len(parts) != 2 || !strings.HasPrefix(parts[0], "ply_ag_") || parts[1] == "" {
		return Credential{}, apierr.New("UNAUTHENTICATED", "agent credential is invalid")
	}
	row, err := s.Store.Queries().GetAgentCredentialByPrefix(ctx, db.GetAgentCredentialByPrefixParams{Prefix: parts[0]})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return Credential{}, apierr.New("UNAUTHENTICATED", "agent credential is invalid")
		}
		return Credential{}, err
	}
	if !s.matchesCredentialHash(parts[1], row.SecretHash) || row.RevokedAt.Valid || !row.ExpiresAt.Time.After(time.Now().UTC()) || row.MemberStatus != "active" {
		return Credential{}, apierr.New("UNAUTHENTICATED", "agent credential is invalid")
	}
	if err := s.Store.InTx(ctx, func(q *db.Queries) error {
		return q.TouchAgentCredential(ctx, db.TouchAgentCredentialParams{ID: row.ID})
	}); err != nil {
		return Credential{}, err
	}
	if row.Kind != "key" {
		return Credential{}, apierr.New("UNAUTHENTICATED", "agent credential is invalid")
	}
	return Credential{ID: row.ID, MemberID: row.MemberID, SpaceID: row.SpaceID, Kind: row.Kind, Prefix: row.Prefix, SecretHash: row.SecretHash, ExpiresAt: row.ExpiresAt.Time, MemberState: row.MemberStatus, HomeGroupID: row.HomeGroupID.String}, nil
}

func (s *Service) generateCredential() (string, string, []byte, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", "", nil, err
	}
	raw := base64.RawURLEncoding.EncodeToString(b)
	prefix := "ply_ag_" + raw[:12]
	return prefix + "." + raw, prefix, s.hashCredential(raw), nil
}

func (s *Service) generateOAuthRefreshCredential() (string, string, []byte, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", "", nil, err
	}
	entropy := base64.RawURLEncoding.EncodeToString(b)
	prefix := "ply_rt_" + entropy[:12]
	raw := prefix + "." + entropy
	return raw, prefix, s.hashCredential(raw), nil
}

func (s *Service) matchesCredentialHash(raw string, want []byte) bool {
	for _, key := range s.credentialHMACKeys() {
		mac := hmac.New(sha256.New, key)
		_, _ = mac.Write([]byte(raw))
		if subtle.ConstantTimeCompare(mac.Sum(nil), want) == 1 {
			return true
		}
	}
	return false
}

func (s *Service) hashCredential(raw string) []byte {
	keys := s.credentialHMACKeys()
	mac := hmac.New(sha256.New, keys[0])
	_, _ = mac.Write([]byte(raw))
	return mac.Sum(nil)
}

func (s *Service) credentialHMACKeys() [][]byte {
	if len(s.HMACKeys) > 0 {
		return s.HMACKeys
	}
	// Tests and embedded callers may construct Service as a zero-value helper.
	// Production wiring always supplies the deployment session HMAC key ring.
	s.hmacOnce.Do(func() {
		s.ephemeralHMACKey = make([]byte, 32)
		if _, err := rand.Read(s.ephemeralHMACKey); err != nil {
			panic("generate ephemeral Agent credential HMAC key: " + err.Error())
		}
	})
	return [][]byte{s.ephemeralHMACKey}
}

func pgTime(t time.Time) pgtype.Timestamptz { return pgtype.Timestamptz{Time: t, Valid: true} }

func agentFromList(row db.ListAgentsForGroupRow, ownerID string) Agent {
	out := Agent{ID: row.ID, SpaceID: row.SpaceID, Name: row.Name, Type: row.Type, Status: row.Status, OwnerMemberID: ownerID, HomeGroupID: row.HomeGroupID.String, CreatedByMember: row.CreatedByMemberID.String, Source: row.Source.String, ExpiresAt: row.ExpiresAt.Time, Version: row.Version}
	if row.CreatedByUserID.Valid {
		out.CreatedByUserID = row.CreatedByUserID.String
	}
	return out
}

func normalize(err error) error {
	if err == nil {
		return nil
	}
	if strings.Contains(strings.ToLower(err.Error()), "duplicate") || strings.Contains(strings.ToLower(err.Error()), "unique") {
		return apierr.New("CONFLICT", "the agent already exists")
	}
	return err
}
