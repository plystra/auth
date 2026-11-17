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
	"github.com/plystra/auth/internal/member"
	"github.com/plystra/auth/internal/stepup"
	"github.com/plystra/auth/internal/store"
)

const maxLifetime = 90 * 24 * time.Hour
const oauthRefreshLifetime = 30 * 24 * time.Hour

type Service struct {
	Store              *store.Store
	StepUp             stepup.Consumer
	MaxDelegationDepth int
	HMACKeys           [][]byte
	RefreshTTL         func(context.Context) (time.Duration, error)
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
	OAuthClientID   string    `json:"oauth_client_id,omitempty"`
	ExpiresAt       time.Time `json:"expires_at"`
	Version         int64     `json:"version"`
}

type CreateInput struct {
	OwnerMemberID string
	CreatedByUser string
	Name          string
	ExpiresAt     time.Time
	Source        string
	OAuthClientID string
}

type Credential struct {
	ID            string
	MemberID      string
	SpaceID       string
	OAuthClientID string
	Kind          string
	Prefix        string
	SecretHash    []byte
	FamilyID      string
	ExpiresAt     time.Time
	Revoked       bool
	MemberState   string
	HomeGroupID   string
}

type agentsGroup struct {
	ID            string
	OwnerMemberID pgtype.Text
}

// Create provisions trusted fixtures. Runtime management uses CreateManaged;
// lint forbids this primitive in production callers.
func (s *Service) Create(ctx context.Context, in CreateInput) (Agent, string, error) {
	return s.create(ctx, in, true, nil)
}

// CreateOAuth creates an OAuth Agent without provisioning a direct Agent key.
// OAuth Agents authenticate with their one-time refresh credential instead; a
// hidden key would create an untracked credential that the consent flow never
// returns to the caller.
func (s *Service) CreateOAuth(ctx context.Context, in CreateInput) (Agent, error) {
	out, _, err := s.create(ctx, in, false, nil)
	return out, err
}

// CreateOAuthTx participates in the caller's consent transaction.
func (s *Service) CreateOAuthTx(ctx context.Context, q *db.Queries, in CreateInput) (Agent, error) {
	return s.createTx(ctx, q, in, false, "", nil, nil)
}

func (s *Service) create(ctx context.Context, in CreateInput, issueCredential bool, authority MutationAuthorizer) (Agent, string, error) {
	var raw, prefix string
	var hash []byte
	var err error
	if issueCredential {
		raw, prefix, hash, err = s.generateCredential()
		if err != nil {
			return Agent{}, "", err
		}
	}
	var out Agent
	err = s.Store.InTx(ctx, func(q *db.Queries) error {
		out, err = s.createTx(ctx, q, in, issueCredential, prefix, hash, authority)
		return err
	})
	if err != nil {
		return Agent{}, "", err
	}
	return out, raw, nil
}

func (s *Service) createTx(ctx context.Context, q *db.Queries, in CreateInput, issueCredential bool, prefix string, hash []byte, authority MutationAuthorizer) (Agent, error) {
	var out Agent
	err := func() error {
		if err := member.LockChainsTx(ctx, q, in.OwnerMemberID); err != nil {
			return err
		}
		owner, err := q.GetMemberForAgentOwner(ctx, db.GetMemberForAgentOwnerParams{MemberID: in.OwnerMemberID})
		if err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return apierr.New("SUBJECT_NOT_FOUND", "owner member was not found")
			}
			return err
		}
		if authority != nil {
			if err := authority.AuthorizeAgentMutationTx(ctx, q, in.OwnerMemberID, in.OwnerMemberID, "auth.agents:create"); err != nil {
				return err
			}
		}
		in.Name = strings.TrimSpace(in.Name)
		if in.Name == "" || len(in.Name) > 128 {
			return apierr.New("VALIDATION_FAILED", "agent name is invalid")
		}
		if in.Source == "" {
			in.Source = "manual"
		}
		if in.Source != "manual" && in.Source != "oauth" && in.Source != "delegation" {
			return apierr.New("VALIDATION_FAILED", "agent source is invalid")
		}
		now := time.Now().UTC()
		if in.ExpiresAt.IsZero() {
			in.ExpiresAt = now.Add(30 * 24 * time.Hour)
		}
		if !in.ExpiresAt.After(now) || in.ExpiresAt.After(now.Add(maxLifetime)) {
			return apierr.New("VALIDATION_FAILED", "agent expiry must be within 90 days")
		}
		if owner.Status != "active" || (owner.ExpiresAt.Valid && !owner.ExpiresAt.Time.After(now)) {
			return apierr.New("OWNER_INACTIVE", "owner member is not active")
		}
		if owner.Type != "human" && owner.Type != "agent" && owner.Type != "application" {
			return apierr.New("VALIDATION_FAILED", "owner member type is invalid")
		}
		if _, required := stepup.RequirementFromContext(ctx); required {
			if s.StepUp == nil {
				return apierr.New("UNAVAILABLE", "step-up authentication is unavailable")
			}
			if err := s.StepUp.ConsumeStepUpTx(ctx, q); err != nil {
				return err
			}
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
			CreatedByMemberID: pgtype.Text{String: in.OwnerMemberID, Valid: true}, Source: pgtype.Text{String: in.Source, Valid: true}, OauthClientID: pgtype.Text{String: in.OAuthClientID, Valid: in.OAuthClientID != ""}, ExpiresAt: pgTime(in.ExpiresAt),
		})
		if err != nil {
			return normalize(err)
		}
		if err := q.AddAgentToGroup(ctx, db.AddAgentToGroupParams{GroupID: group.ID, MemberID: member.ID}); err != nil {
			return err
		}
		if issueCredential {
			if _, err := q.CreateAgentCredential(ctx, db.CreateAgentCredentialParams{ID: string(ids.New[ids.ID]("crd")), MemberID: member.ID, Prefix: prefix, SecretHash: hash, ExpiresAt: pgTime(in.ExpiresAt)}); err != nil {
				return normalize(err)
			}
		}
		if err := audit.WriteSecurityEvent(ctx, q, audit.SecurityEvent{
			ActorType: "member", ActorID: in.OwnerMemberID, Action: "agent.create", Outcome: "success",
			MemberID: member.ID, UserID: in.CreatedByUser,
		}); err != nil {
			return err
		}
		version, err := q.GetMemberVersion(ctx, db.GetMemberVersionParams{MemberID: member.ID})
		if err != nil {
			return err
		}
		out = Agent{ID: member.ID, SpaceID: member.SpaceID, Name: member.Name, Type: member.Type, Status: member.Status, HomeGroupID: member.HomeGroupID.String, CreatedByMember: member.CreatedByMemberID.String, Source: member.Source.String, ExpiresAt: member.ExpiresAt.Time, Version: version}
		if member.OauthClientID.Valid {
			out.OAuthClientID = member.OauthClientID.String
		}
		if member.CreatedByUserID.Valid {
			out.CreatedByUserID = member.CreatedByUserID.String
		}
		if group.OwnerMemberID.Valid {
			out.OwnerMemberID = group.OwnerMemberID.String
		}
		return nil
	}()
	if err != nil {
		return Agent{}, err
	}
	return out, nil
}

// OAuthAgent returns the active OAuth Agent previously authorized by an owner
// for the same client. A client gets one Agent per owner member.
func (s *Service) OAuthAgent(ctx context.Context, ownerMemberID, clientID string) (Agent, error) {
	return s.OAuthAgentTx(ctx, s.Store.Queries(), ownerMemberID, clientID)
}

func (s *Service) OAuthAgentTx(ctx context.Context, q *db.Queries, ownerMemberID, clientID string) (Agent, error) {
	row, err := q.GetOAuthAgentForOwnerClient(ctx, db.GetOAuthAgentForOwnerClientParams{OwnerMemberID: pgtype.Text{String: ownerMemberID, Valid: true}, OauthClientID: pgtype.Text{String: clientID, Valid: true}})
	if errors.Is(err, pgx.ErrNoRows) {
		return Agent{}, apierr.New("NOT_FOUND", "OAuth Agent was not found")
	}
	if err != nil {
		return Agent{}, err
	}
	out := Agent{ID: row.ID, SpaceID: row.SpaceID, Name: row.Name, Type: row.Type, Status: row.Status, HomeGroupID: row.HomeGroupID.String, CreatedByMember: row.CreatedByMemberID.String, Source: row.Source.String, ExpiresAt: row.ExpiresAt.Time, Version: row.Version}
	if row.OwnerMemberID.Valid {
		out.OwnerMemberID = row.OwnerMemberID.String
	}
	if row.CreatedByUserID.Valid {
		out.CreatedByUserID = row.CreatedByUserID.String
	}
	if row.OauthClientID.Valid {
		out.OAuthClientID = row.OauthClientID.String
	}
	return out, nil
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
	return s.rotate(ctx, ownerMemberID, "", memberID, nil)
}

// RotateForUser allows an active user bound to the Agent owner member to take
// over an Agent that was paused after its creating user's binding was revoked.
func (s *Service) RotateForUser(ctx context.Context, ownerMemberID, actorUserID, memberID string) (string, error) {
	return s.rotate(ctx, ownerMemberID, actorUserID, memberID, nil)
}

func (s *Service) rotate(ctx context.Context, ownerMemberID, actorUserID, memberID string, authority MutationAuthorizer) (string, error) {
	raw, prefix, hash, err := s.generateCredential()
	if err != nil {
		return "", err
	}
	var expires time.Time
	takeover := false
	err = s.Store.InTx(ctx, func(q *db.Queries) error {
		if err := member.LockChainsTx(ctx, q, ownerMemberID, memberID); err != nil {
			return err
		}
		row, err := q.GetAgentMember(ctx, db.GetAgentMemberParams{MemberID: memberID})
		if err != nil {
			return apierr.New("NOT_FOUND", "agent was not found")
		}
		if canManage, err := q.CanManageAgent(ctx, db.CanManageAgentParams{OwnerMemberID: ownerMemberID, TargetMemberID: memberID}); err != nil {
			return err
		} else if !canManage {
			return apierr.New("PERMISSION_DENIED", "agent is outside the current member's agent tree")
		}
		if authority != nil {
			if err := authority.AuthorizeAgentMutationTx(ctx, q, ownerMemberID, memberID, "auth.agents:create"); err != nil {
				return err
			}
		}
		if _, required := stepup.RequirementFromContext(ctx); required {
			if s.StepUp == nil {
				return apierr.New("UNAVAILABLE", "step-up authentication is unavailable")
			}
			if err := s.StepUp.ConsumeStepUpTx(ctx, q); err != nil {
				return err
			}
		}
		if row.GroupStatus != "active" {
			return apierr.New("CONFLICT", "agent is not active")
		}
		if row.Status != "active" {
			if err := member.RequireActiveApplicationTx(ctx, q, memberID); err != nil {
				return err
			}
			if row.Status != "suspended" || actorUserID == "" || (row.CreatedByUserID.Valid && row.CreatedByUserID.String == actorUserID) {
				return apierr.New("CONFLICT", "agent is not active")
			}
			actorBinding, bindingErr := q.GetUserMemberBinding(ctx, db.GetUserMemberBindingParams{UserID: actorUserID, MemberID: ownerMemberID})
			if errors.Is(bindingErr, pgx.ErrNoRows) {
				return apierr.New("PERMISSION_DENIED", "the takeover user is not actively bound to the agent owner")
			}
			if bindingErr != nil {
				return bindingErr
			}
			if actorBinding.Status != "active" || actorBinding.RevokedAt.Valid || (actorBinding.ExpiresAt.Valid && !actorBinding.ExpiresAt.Time.After(time.Now().UTC())) {
				return apierr.New("PERMISSION_DENIED", "the takeover user is not actively bound to the agent owner")
			}
			if row.CreatedByUserID.Valid {
				creatorBinding, creatorErr := q.GetUserMemberBinding(ctx, db.GetUserMemberBindingParams{UserID: row.CreatedByUserID.String, MemberID: ownerMemberID})
				creatorActive := creatorErr == nil && creatorBinding.Status == "active" && !creatorBinding.RevokedAt.Valid && (!creatorBinding.ExpiresAt.Valid || creatorBinding.ExpiresAt.Time.After(time.Now().UTC()))
				if creatorActive {
					return apierr.New("CONFLICT", "agent is not paused for binding takeover")
				}
			}
			if err := q.ResumeSuspendedAgent(ctx, db.ResumeSuspendedAgentParams{MemberID: memberID}); err != nil {
				return err
			}
			takeover = true
		}
		expires = row.ExpiresAt.Time
		if err := q.RevokeAgentCredentials(ctx, db.RevokeAgentCredentialsParams{MemberID: memberID}); err != nil {
			return err
		}
		_, err = q.CreateAgentCredential(ctx, db.CreateAgentCredentialParams{ID: string(ids.New[ids.ID]("crd")), MemberID: memberID, Prefix: prefix, SecretHash: hash, ExpiresAt: pgTime(expires)})
		if err != nil {
			return normalize(err)
		}
		action := "agent.credential.rotate"
		if takeover {
			action = "agent.credential.takeover"
		}
		return audit.WriteSecurityEvent(ctx, q, audit.SecurityEvent{
			ActorType: "member", ActorID: ownerMemberID, Action: action, Outcome: "success", MemberID: memberID, UserID: actorUserID,
		})
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
	refreshTTL, err := s.oauthRefreshTTL(ctx)
	if err != nil {
		return "", err
	}
	if expiresAt.IsZero() {
		expiresAt = now.Add(refreshTTL)
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
		if err := member.LockChainsTx(ctx, q, memberID); err != nil {
			return err
		}
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
		return audit.WriteSecurityEvent(ctx, q, audit.SecurityEvent{
			ActorType: "member", ActorID: memberID, Action: "agent.oauth_refresh.create", Outcome: "success", MemberID: memberID,
		})
	})
	if err != nil {
		return "", err
	}
	return raw, nil
}

// RotateOAuthRefresh atomically consumes an OAuth refresh credential and
// creates its successor. A replay revokes the entire credential family.
func (s *Service) RotateOAuthRefresh(ctx context.Context, raw string) (Credential, string, error) {
	return s.rotateOAuthRefresh(ctx, raw, "")
}

// RotateOAuthRefreshForClient performs the same atomic rotation while binding
// the credential to the authenticated OAuth client before consuming it.
func (s *Service) RotateOAuthRefreshForClient(ctx context.Context, raw, clientID string) (Credential, string, error) {
	return s.rotateOAuthRefresh(ctx, raw, clientID)
}

func (s *Service) rotateOAuthRefresh(ctx context.Context, raw, clientID string) (Credential, string, error) {
	raw = strings.TrimSpace(raw)
	if !strings.HasPrefix(raw, "ply_rt_") || raw == "" {
		return Credential{}, "", apierr.New("invalid_grant", "OAuth refresh token is invalid")
	}
	now := time.Now().UTC()
	refreshTTL, err := s.oauthRefreshTTL(ctx)
	if err != nil {
		return Credential{}, "", err
	}
	next, prefix, hash, err := s.generateOAuthRefreshCredential()
	if err != nil {
		return Credential{}, "", err
	}
	family := ""
	var out Credential
	replayed := false
	err = s.Store.InTx(ctx, func(q *db.Queries) error {
		row, err := s.lockOAuthRefreshCredentialTx(ctx, q, raw)
		if errors.Is(err, pgx.ErrNoRows) {
			return apierr.New("invalid_grant", "OAuth refresh token is invalid")
		}
		if err != nil {
			return err
		}
		if clientID != "" && row.OauthClientID.String != clientID {
			return apierr.New("invalid_client", "OAuth client authentication failed")
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
			return audit.WriteSecurityEvent(ctx, q, audit.SecurityEvent{
				ActorType: "member", ActorID: row.MemberID, Action: "agent.oauth_refresh.replay", Outcome: "failure", MemberID: row.MemberID,
				CredentialType: "oauth_refresh_token", Priority: "high",
			})
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
		expiresAt := now.Add(refreshTTL)
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
		out = Credential{ID: row.ID, MemberID: row.MemberID, SpaceID: row.SpaceID, OAuthClientID: row.OauthClientID.String, Kind: row.Kind, Prefix: row.Prefix, SecretHash: row.SecretHash, FamilyID: family, ExpiresAt: expiresAt, MemberState: row.MemberStatus, HomeGroupID: row.HomeGroupID.String}
		return audit.WriteSecurityEvent(ctx, q, audit.SecurityEvent{
			ActorType: "member", ActorID: row.MemberID, Action: "agent.oauth_refresh", Outcome: "success", MemberID: row.MemberID,
			CredentialType: "oauth_refresh_token",
		})
	})
	if err != nil {
		return Credential{}, "", err
	}
	if replayed {
		return Credential{}, "", apierr.New("invalid_grant", "OAuth refresh token replayed")
	}
	return out, next, nil
}

func (s *Service) oauthRefreshTTL(ctx context.Context) (time.Duration, error) {
	if s.RefreshTTL != nil {
		ttl, err := s.RefreshTTL(ctx)
		if err != nil {
			return 0, err
		}
		if ttl <= 0 {
			return 0, apierr.New("UNAVAILABLE", "OAuth refresh TTL is not configured")
		}
		return ttl, nil
	}
	return oauthRefreshLifetime, nil
}

// RevokeOAuthRefreshToken resolves and revokes the complete refresh-token
// family for an OAuth Agent. Unknown, malformed, expired, or already revoked
// tokens are deliberately reported as not found so the protocol endpoint can
// remain idempotent without revealing credential state. Family revocation and
// Agent suspension share one transaction so an audit failure cannot leave a
// partially revoked authorization.
func (s *Service) RevokeOAuthRefreshToken(ctx context.Context, raw string) (bool, error) {
	raw = strings.TrimSpace(raw)
	if !strings.HasPrefix(raw, "ply_rt_") || raw == "" {
		return false, nil
	}
	found := false
	err := s.Store.InTx(ctx, func(q *db.Queries) error {
		row, err := s.lockOAuthRefreshCredentialTx(ctx, q, raw)
		if errors.Is(err, pgx.ErrNoRows) {
			return nil
		}
		if err != nil {
			return err
		}
		found = true
		if row.FamilyID.Valid {
			if err := q.RevokeAgentCredentialFamily(ctx, db.RevokeAgentCredentialFamilyParams{FamilyID: row.FamilyID}); err != nil {
				return err
			}
		}
		return s.revokeOAuthTx(ctx, q, row.MemberID)
	})
	return found, err
}

func (s *Service) lockOAuthRefreshCredentialTx(ctx context.Context, q *db.Queries, raw string) (db.LockOAuthRefreshCredentialByHashRow, error) {
	for _, key := range s.credentialHMACKeys() {
		mac := hmac.New(sha256.New, key)
		_, _ = mac.Write([]byte(raw))
		hash := mac.Sum(nil)
		memberID, err := q.FindOAuthRefreshCredentialMember(ctx, db.FindOAuthRefreshCredentialMemberParams{SecretHash: hash})
		if errors.Is(err, pgx.ErrNoRows) {
			continue
		}
		if err != nil {
			return db.LockOAuthRefreshCredentialByHashRow{}, err
		}
		// Match creation and subtree revocation: members precede credentials.
		if err := member.LockChainsTx(ctx, q, memberID); err != nil {
			return db.LockOAuthRefreshCredentialByHashRow{}, err
		}
		return q.LockOAuthRefreshCredentialByHash(ctx, db.LockOAuthRefreshCredentialByHashParams{SecretHash: hash})
	}
	return db.LockOAuthRefreshCredentialByHashRow{}, pgx.ErrNoRows
}

// RevokeOAuth stops an OAuth Agent and every delegated descendant in one
// transaction. Existing JWT access tokens become inactive through the live
// member status checked by session introspection.
func (s *Service) RevokeOAuth(ctx context.Context, memberID string) error {
	return s.Store.InTx(ctx, func(q *db.Queries) error {
		return s.revokeOAuthTx(ctx, q, memberID)
	})
}

func (s *Service) revokeOAuthTx(ctx context.Context, q *db.Queries, memberID string) error {
	if err := member.LockChainsTx(ctx, q, memberID); err != nil {
		return err
	}
	row, err := q.GetAgentMember(ctx, db.GetAgentMemberParams{MemberID: memberID})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	if !row.Source.Valid || row.Source.String != "oauth" {
		return nil
	}
	if err := member.SetAgentSubtreeStatusTx(ctx, q, memberID, "suspended"); err != nil {
		return err
	}
	return audit.WriteSecurityEvent(ctx, q, audit.SecurityEvent{
		ActorType: "member", ActorID: memberID, Action: "agent.oauth.revoke", Outcome: "success", MemberID: memberID,
	})
}

func (s *Service) Stop(ctx context.Context, ownerMemberID, memberID string) error {
	return s.mutate(ctx, ownerMemberID, memberID, "stop", "suspended", nil, "")
}

func (s *Service) Delete(ctx context.Context, ownerMemberID, memberID string) error {
	return s.mutate(ctx, ownerMemberID, memberID, "delete", "removed", nil, "")
}

// ExpireAgents tombstones expired Agents and their descendants together with
// groups, credentials, and audit events in one transaction.
func (s *Service) ExpireAgents(ctx context.Context) (int, error) {
	count := 0
	err := s.Store.InTx(ctx, func(q *db.Queries) error {
		roots, err := q.ListExpiredAgentRoots(ctx)
		if err != nil {
			return err
		}
		rootIDs := make([]string, len(roots))
		for i, root := range roots {
			rootIDs[i] = root.ID
		}
		if err := member.LockChainsTx(ctx, q, rootIDs...); err != nil {
			return err
		}
		for _, root := range roots {
			ag, err := q.GetAgentMember(ctx, db.GetAgentMemberParams{MemberID: root.ID})
			if errors.Is(err, pgx.ErrNoRows) {
				continue
			}
			if err != nil {
				return err
			}
			if ag.Status != "active" || !ag.ExpiresAt.Valid || ag.ExpiresAt.Time.After(time.Now().UTC()) {
				continue
			}
			if !ag.HomeGroupID.Valid {
				return apierr.New("OWNER_INACTIVE", "expired Agent has no home group")
			}
			if err := member.SetAgentSubtreeStatusTx(ctx, q, ag.ID, "removed"); err != nil {
				return err
			}
			if err := audit.WriteSecurityEvent(ctx, q, audit.SecurityEvent{
				ActorType: "system", Action: "agent.expire", Outcome: "success", MemberID: ag.ID,
			}); err != nil {
				return err
			}
			count++
		}
		return nil
	})
	return count, err
}

func (s *Service) mutate(ctx context.Context, ownerMemberID, memberID, action, status string, authority MutationAuthorizer, permission string) error {
	return s.Store.InTx(ctx, func(q *db.Queries) error {
		if err := member.LockChainsTx(ctx, q, ownerMemberID, memberID); err != nil {
			return err
		}
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
		if authority != nil {
			if err := authority.AuthorizeAgentMutationTx(ctx, q, ownerMemberID, memberID, permission); err != nil {
				return err
			}
		}
		if err := member.SetAgentSubtreeStatusTx(ctx, q, memberID, status); err != nil {
			return err
		}
		return audit.WriteSecurityEvent(ctx, q, audit.SecurityEvent{
			ActorType: "member", ActorID: ownerMemberID, Action: "agent." + action, Outcome: "success", MemberID: memberID,
		})
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

// ValidateActive checks the live Agent and its "my agents" group before a
// protocol operation delegates authority to the Agent. Ordinary credential
// authentication intentionally keeps its historical semantics so callers
// that need to report authorization facts can do so through the engine.
func (s *Service) ValidateActive(ctx context.Context, memberID string) error {
	member, err := s.Store.Queries().GetAgentMember(ctx, db.GetAgentMemberParams{MemberID: memberID})
	if errors.Is(err, pgx.ErrNoRows) || err != nil || member.Status != "active" || member.GroupStatus != "active" || (member.ExpiresAt.Valid && !member.ExpiresAt.Time.After(time.Now().UTC())) {
		return apierr.New("UNAUTHENTICATED", "agent credential is invalid")
	}
	return nil
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
