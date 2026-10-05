package agent

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"strings"
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

type Service struct{ Store *store.Store }

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
	Prefix      string
	SecretHash  []byte
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
	raw, prefix, hash, err := generateCredential()
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
	raw, prefix, hash, err := generateCredential()
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
		return q.RemoveAgentGroupSubtree(ctx, db.RemoveAgentGroupSubtreeParams{GroupID: groupID})
	})
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
		if err := q.RevokeAgentCredentials(ctx, db.RevokeAgentCredentialsParams{MemberID: memberID}); err != nil {
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
	sum := sha256.Sum256([]byte(parts[1]))
	if !equal(sum[:], row.SecretHash) || row.RevokedAt.Valid || !row.ExpiresAt.Time.After(time.Now().UTC()) || row.MemberStatus != "active" {
		return Credential{}, apierr.New("UNAUTHENTICATED", "agent credential is invalid")
	}
	if err := s.Store.InTx(ctx, func(q *db.Queries) error {
		return q.TouchAgentCredential(ctx, db.TouchAgentCredentialParams{ID: row.ID})
	}); err != nil {
		return Credential{}, err
	}
	return Credential{ID: row.ID, MemberID: row.MemberID, SpaceID: row.SpaceID, Prefix: row.Prefix, SecretHash: row.SecretHash, ExpiresAt: row.ExpiresAt.Time, MemberState: row.MemberStatus, HomeGroupID: row.HomeGroupID.String}, nil
}

func generateCredential() (string, string, []byte, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", "", nil, err
	}
	raw := base64.RawURLEncoding.EncodeToString(b)
	prefix := "ply_ag_" + raw[:12]
	sum := sha256.Sum256([]byte(raw))
	return prefix + "." + raw, prefix, sum[:], nil
}

func equal(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	var v byte
	for i := range a {
		v |= a[i] ^ b[i]
	}
	return v == 0
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
