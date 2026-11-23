package session

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"slices"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/plystra/auth/internal/apierr"
	"github.com/plystra/auth/internal/audit"
	"github.com/plystra/auth/internal/db"
	"github.com/plystra/auth/internal/factor"
	"github.com/plystra/auth/internal/ids"
	"github.com/plystra/auth/internal/member"
	"github.com/plystra/auth/internal/security"
	"github.com/plystra/auth/internal/store"
)

type Settings struct{ AccessTTL, RefreshTTL, RefreshIdleTTL time.Duration }
type Service struct {
	Store    *store.Store
	Signer   *security.Signer
	Factors  *factor.Service
	HMACKeys [][]byte
	Settings func(context.Context) (Settings, error)
}
type Tokens struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int64  `json:"expires_in"`
	RefreshToken string `json:"refresh_token"`
	SessionID    string `json:"session_id"`
}

type DeviceSession struct {
	ID             string    `json:"id"`
	MemberID       string    `json:"member_id,omitempty"`
	CreatedAt      time.Time `json:"created_at"`
	LastSeenAt     time.Time `json:"last_seen_at"`
	ExpiresAt      time.Time `json:"expires_at"`
	IP             string    `json:"ip,omitempty"`
	UserAgent      string    `json:"user_agent,omitempty"`
	AuthTime       time.Time `json:"auth_time"`
	AssuranceLevel int16     `json:"assurance_level"`
	AuthMethods    []string  `json:"amr"`
}

func (s *Service) hashToken(token string) []byte {
	mac := hmac.New(sha256.New, s.HMACKeys[0])
	_, _ = mac.Write([]byte(token))
	return mac.Sum(nil)
}
func (s *Service) tokenHashes(token string) [][]byte {
	out := make([][]byte, 0, len(s.HMACKeys))
	for _, key := range s.HMACKeys {
		mac := hmac.New(sha256.New, key)
		_, _ = mac.Write([]byte(token))
		out = append(out, mac.Sum(nil))
	}
	return out
}
func randomToken(prefix string) (string, error) {
	b := make([]byte, 32)
	if _, e := rand.Read(b); e != nil {
		return "", e
	}
	return prefix + base64.RawURLEncoding.EncodeToString(b), nil
}
func (s *Service) Create(ctx context.Context, userID string, ip net.IP, userAgent string, assurance int) (Tokens, error) {
	return s.CreateForMember(ctx, userID, "", ip, userAgent, assurance)
}

func (s *Service) CreateForMember(ctx context.Context, userID, memberID string, ip net.IP, userAgent string, assurance int) (Tokens, error) {
	return s.CreateForMemberWithMethods(ctx, userID, memberID, ip, userAgent, assurance, []string{"pwd"})
}

func (s *Service) CreateForMemberWithMethods(ctx context.Context, userID, memberID string, ip net.IP, userAgent string, assurance int, methods []string) (Tokens, error) {
	st, err := s.Settings(ctx)
	if err != nil {
		return Tokens{}, err
	}
	var tokens Tokens
	err = s.Store.InTx(ctx, func(q *db.Queries) error {
		if _, err := q.LockUserForAuthorization(ctx, db.LockUserForAuthorizationParams{ID: userID}); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return apierr.New("invalid_grant", "the account is not active")
			}
			return err
		}
		var err error
		tokens, err = s.CreateForMemberWithMethodsTx(ctx, q, st, userID, memberID, ip, userAgent, assurance, methods)
		return err
	})
	if err != nil {
		return Tokens{}, err
	}
	return tokens, nil
}

// CreateForMemberWithMethodsTx signs and persists the session in the caller's transaction.
// Read the settings before opening the transaction and return the tokens only after commit.
func (s *Service) CreateForMemberWithMethodsTx(ctx context.Context, q *db.Queries, st Settings, userID, memberID string, ip net.IP, userAgent string, assurance int, methods []string) (Tokens, error) {
	if assurance < 1 || assurance > 3 || len(methods) == 0 {
		return Tokens{}, errors.New("invalid session authentication methods or assurance")
	}
	if st.AccessTTL <= 0 || st.RefreshTTL <= 0 {
		return Tokens{}, errors.New("invalid session settings")
	}
	if s.Signer == nil || len(s.HMACKeys) == 0 {
		return Tokens{}, errors.New("session credentials are unavailable")
	}
	methods = append([]string(nil), methods...)
	accessID, err := randomToken("jti_")
	if err != nil {
		return Tokens{}, err
	}
	refresh, err := randomToken("ply_rt_")
	if err != nil {
		return Tokens{}, err
	}
	sid := ids.New[ids.SessionID]("ses")
	family := ids.New[ids.RefreshFamilyID]("rtf")
	rid := ids.New[ids.RefreshTokenID]("rft")
	now := time.Now().UTC()
	exp := now.Add(st.RefreshTTL)
	active, err := activeUser(ctx, q, userID)
	if err != nil {
		return Tokens{}, err
	}
	if !active {
		return Tokens{}, apierr.New("invalid_grant", "the account is not active")
	}
	var persistedMember pgtype.Text
	spaceID := ""
	if memberID != "" {
		var permitted bool
		spaceID, permitted, err = boundMemberSpace(ctx, q, userID, memberID, now)
		if err != nil {
			return Tokens{}, err
		}
		if !permitted {
			return Tokens{}, apierr.New("PERMISSION_DENIED", "the selected member is not available to this user")
		}
		persistedMember = pgtype.Text{String: memberID, Valid: true}
	}
	var ssoMember pgtype.Text
	if slices.Contains(methods, "oidc") || slices.Contains(methods, "saml") {
		if !persistedMember.Valid {
			return Tokens{}, errors.New("enterprise SSO requires a member binding")
		}
		ssoMember = persistedMember
	}
	refreshHash := s.hashToken(refresh)
	row, err := q.CreateSession(ctx, db.CreateSessionParams{
		ID: string(sid), UserID: userID, MemberID: persistedMember, SsoMemberID: ssoMember,
		TokenHash: refreshHash, ExpiresAt: pgTime(exp), Ip: nullable(ipString(ip)), UserAgent: nullable(userAgent),
		AuthTime: pgTime(now), AssuranceLevel: nullableInt(int32(assurance)), AuthMethods: methods,
	})
	if err != nil {
		return Tokens{}, err
	}
	_, err = q.CreateRefreshToken(ctx, db.CreateRefreshTokenParams{
		ID: string(rid), SessionID: row.ID, FamilyID: string(family), TokenHash: refreshHash, ExpiresAt: pgTime(exp),
	})
	if err != nil {
		return Tokens{}, err
	}
	jwt, err := s.Signer.Sign(security.Claims{
		Issuer: s.Signer.Issuer(), Subject: userID, MemberID: memberID, SpaceID: spaceID,
		Audience: security.DefaultApplicationAudience, ExpiresAt: now.Add(st.AccessTTL).Unix(), IssuedAt: now.Unix(),
		JWTID: accessID, SessionID: row.ID, Assurance: assurance, AMR: methods, Type: "user",
	})
	if err != nil {
		return Tokens{}, err
	}
	return Tokens{AccessToken: jwt, TokenType: "Bearer", ExpiresIn: int64(st.AccessTTL / time.Second), RefreshToken: refresh, SessionID: row.ID}, nil
}
func (s *Service) Refresh(ctx context.Context, raw string) (Tokens, error) {
	return s.RefreshForMember(ctx, raw, "")
}

func (s *Service) RefreshForMember(ctx context.Context, raw, requestedMemberID string) (Tokens, error) {
	st, err := s.Settings(ctx)
	if err != nil {
		return Tokens{}, err
	}
	if st.AccessTTL <= 0 || st.RefreshTTL <= 0 || s.Signer == nil || len(s.HMACKeys) == 0 {
		return Tokens{}, errors.New("session issuance is unavailable")
	}
	next, err := randomToken("ply_rt_")
	if err != nil {
		return Tokens{}, err
	}
	jti, err := randomToken("jti_")
	if err != nil {
		return Tokens{}, err
	}
	var tokens Tokens
	rejected := false
	err = s.Store.InTx(ctx, func(q *db.Queries) error {
		hint, hash, err := s.refreshSessionHint(ctx, q, raw)
		if errors.Is(err, pgx.ErrNoRows) {
			return apierr.New("invalid_grant", "refresh token is invalid")
		}
		if err != nil {
			return err
		}
		// Match binding and session revocation order. The hint only selects the
		// lock set. All authorization uses fresh facts after the locks are held.
		if _, err := q.LockUserForAuthorization(ctx, db.LockUserForAuthorizationParams{ID: hint.UserID}); err != nil {
			return invalidRefreshOnMissing(err)
		}
		current, err := q.GetSession(ctx, db.GetSessionParams{ID: hint.SessionID})
		if err != nil {
			return invalidRefreshOnMissing(err)
		}
		if _, err := q.LockRefreshMembers(ctx, db.LockRefreshMembersParams{
			UserID: hint.UserID, MemberIds: []string{current.MemberID.String, current.SsoMemberID.String, requestedMemberID},
		}); err != nil {
			return err
		}
		sess, err := q.LockSessionForRefresh(ctx, db.LockSessionForRefreshParams{ID: hint.SessionID})
		if err != nil {
			return invalidRefreshOnMissing(err)
		}
		token, err := q.LockRefreshToken(ctx, db.LockRefreshTokenParams{TokenHash: hash})
		if err != nil {
			return invalidRefreshOnMissing(err)
		}
		if token.SessionID != sess.ID || sess.UserID != hint.UserID {
			return apierr.New("invalid_grant", "refresh token is invalid")
		}
		now := time.Now().UTC()
		replayed := token.UsedAt.Valid
		invalid := token.RevokedAt.Valid || replayed || !token.ExpiresAt.Time.After(now) ||
			(st.RefreshIdleTTL > 0 && !token.IssuedAt.Time.Add(st.RefreshIdleTTL).After(now)) ||
			sess.RevokedAt.Valid || !sess.ExpiresAt.Time.After(now)
		if invalid {
			if err := q.RevokeSession(ctx, db.RevokeSessionParams{ID: sess.ID}); err != nil {
				return err
			}
			if err := q.RevokeRefreshFamily(ctx, db.RevokeRefreshFamilyParams{FamilyID: token.FamilyID}); err != nil {
				return err
			}
			if replayed {
				if err = audit.WriteWithPriority(ctx, q, "public", "", "auth.session.refresh_replay", token.SessionID, "failure", "high"); err != nil {
					return err
				}
			}
			rejected = true
			return nil
		}
		active, err := activeUser(ctx, q, sess.UserID)
		if err != nil {
			return err
		}
		if !active {
			return apierr.New("invalid_grant", "the account is not active")
		}
		memberID := sess.MemberID.String
		spaceID, err := refreshBindingSpace(ctx, q, sess.UserID, memberID, sess.SsoMemberID.String, now)
		if err != nil {
			return err
		}
		if requestedMemberID != "" && requestedMemberID != memberID {
			var permitted bool
			spaceID, permitted, err = boundMemberSpace(ctx, q, sess.UserID, requestedMemberID, now)
			if err != nil {
				return err
			}
			if !permitted {
				return apierr.New("PERMISSION_DENIED", "the selected member is not available to this user")
			}
			memberID = requestedMemberID
		}
		if _, err := q.MarkRefreshUsed(ctx, db.MarkRefreshUsedParams{ID: token.ID}); err != nil {
			return invalidRefreshOnMissing(err)
		}
		if memberID != "" {
			if err := q.SetSessionMember(ctx, db.SetSessionMemberParams{ID: sess.ID, UserID: sess.UserID, MemberID: pgtype.Text{String: memberID, Valid: true}}); err != nil {
				return err
			}
		}
		_, err = q.CreateRefreshToken(ctx, db.CreateRefreshTokenParams{
			ID: string(ids.New[ids.RefreshTokenID]("rft")), SessionID: sess.ID, FamilyID: token.FamilyID,
			TokenHash: s.hashToken(next), ExpiresAt: pgTime(now.Add(st.RefreshTTL)),
		})
		if err != nil {
			return err
		}
		jwt, err := s.Signer.Sign(security.Claims{
			Issuer: s.Signer.Issuer(), Subject: sess.UserID, MemberID: memberID, SpaceID: spaceID,
			Audience: security.DefaultApplicationAudience, ExpiresAt: now.Add(st.AccessTTL).Unix(), IssuedAt: now.Unix(),
			JWTID: jti, SessionID: sess.ID, Assurance: int(sess.AssuranceLevel), AMR: sess.AuthMethods, Type: "user",
		})
		if err != nil {
			return err
		}
		tokens = Tokens{AccessToken: jwt, TokenType: "Bearer", ExpiresIn: int64(st.AccessTTL / time.Second), RefreshToken: next, SessionID: sess.ID}
		return audit.Write(ctx, q, "user", sess.UserID, "auth.session.refresh", sess.ID, "success")
	})
	if err != nil {
		return Tokens{}, err
	}
	if rejected {
		return Tokens{}, apierr.New("invalid_grant", "refresh token has been revoked")
	}
	return tokens, nil
}

func (s *Service) refreshSessionHint(ctx context.Context, q *db.Queries, raw string) (db.GetRefreshSessionHintRow, []byte, error) {
	for _, hash := range s.tokenHashes(raw) {
		hint, err := q.GetRefreshSessionHint(ctx, db.GetRefreshSessionHintParams{TokenHash: hash})
		if !errors.Is(err, pgx.ErrNoRows) {
			return hint, hash, err
		}
	}
	return db.GetRefreshSessionHintRow{}, nil, pgx.ErrNoRows
}

func invalidRefreshOnMissing(err error) error {
	if errors.Is(err, pgx.ErrNoRows) {
		return apierr.New("invalid_grant", "refresh token is invalid")
	}
	return err
}

func refreshBindingSpace(ctx context.Context, q *db.Queries, userID, memberID, ssoMemberID string, now time.Time) (string, error) {
	if ssoMemberID != "" && ssoMemberID != memberID {
		_, permitted, err := boundMemberSpace(ctx, q, userID, ssoMemberID, now)
		if err != nil {
			return "", err
		}
		if !permitted {
			return "", apierr.New("invalid_grant", "the original SSO binding is no longer active")
		}
	}
	if memberID == "" {
		return "", nil
	}
	spaceID, permitted, err := boundMemberSpace(ctx, q, userID, memberID, now)
	if err != nil {
		return "", err
	}
	if !permitted {
		return "", apierr.New("PERMISSION_DENIED", "the session member binding is no longer active")
	}
	return spaceID, nil
}

// CreateAgentAccess exchanges a one-time agent credential validation for a
// short-lived access token. Agent sessions are intentionally stateless: live
// member and owner-chain status is checked during introspection/authz checks.
func (s *Service) CreateAgentAccess(ctx context.Context, memberID, spaceID, audience string) (Tokens, error) {
	return s.createAgentAccess(ctx, memberID, spaceID, audience, "", nil, 0)
}

// CreateAgentAccessTx includes issuance and its audit in the caller's credential
// transaction. The caller must not return the token before that transaction commits.
func (s *Service) CreateAgentAccessTx(ctx context.Context, q *db.Queries, memberID, spaceID, audience string) (Tokens, error) {
	if err := member.LockChainsTx(ctx, q, memberID); err != nil {
		return Tokens{}, err
	}
	return s.agentAccessTx(ctx, q, memberID, spaceID, audience, "", nil, 0)
}

// CreateAgentScopedAccessTx issues an explicitly restricted credential for the
// same Agent, without introducing a delegation hop or a new refresh family.
func (s *Service) CreateAgentScopedAccessTx(ctx context.Context, q *db.Queries, memberID, spaceID, audience string, scopes []string) (Tokens, error) {
	if len(scopes) == 0 {
		return Tokens{}, apierr.New("invalid_scope", "an explicit nonempty scope is required")
	}
	if err := member.LockChainsTx(ctx, q, memberID); err != nil {
		return Tokens{}, err
	}
	return s.agentAccessTx(ctx, q, memberID, spaceID, audience, "", scopes, 0)
}

// CreateAgentDelegatedAccess issues a token for an existing child Agent. The
// actor and optional upper expiry bound are carried from the parent token so a
// delegated token cannot outlive the delegation step that produced it.
func (s *Service) CreateAgentDelegatedAccess(ctx context.Context, memberID, spaceID, audience, actor string, scopes []string, notAfter int64) (Tokens, error) {
	return s.createAgentAccess(ctx, memberID, spaceID, audience, actor, scopes, notAfter)
}

// CreateAgentDelegatedAccessTx keeps delegated signing and audit in the same
// transaction as credential authentication and current authority validation.
func (s *Service) CreateAgentDelegatedAccessTx(ctx context.Context, q *db.Queries, memberID, spaceID, audience, actor string, scopes []string, notAfter int64) (Tokens, error) {
	if err := member.LockChainsTx(ctx, q, memberID, actor); err != nil {
		return Tokens{}, err
	}
	return s.agentAccessTx(ctx, q, memberID, spaceID, audience, actor, scopes, notAfter)
}

func (s *Service) createAgentAccess(ctx context.Context, memberID, spaceID, audience, actor string, scopes []string, notAfter int64) (Tokens, error) {
	var tokens Tokens
	err := s.Store.InTx(ctx, func(q *db.Queries) error {
		if err := member.LockChainsTx(ctx, q, memberID, actor); err != nil {
			return err
		}
		var err error
		tokens, err = s.agentAccessTx(ctx, q, memberID, spaceID, audience, actor, scopes, notAfter)
		return err
	})
	if err != nil {
		return Tokens{}, err
	}
	return tokens, nil
}

func (s *Service) agentAccessTx(ctx context.Context, q *db.Queries, memberID, spaceID, audience, actor string, scopes []string, notAfter int64) (Tokens, error) {
	agent, err := q.GetAgentMember(ctx, db.GetAgentMemberParams{MemberID: memberID})
	if errors.Is(err, pgx.ErrNoRows) {
		return Tokens{}, apierr.New("invalid_grant", "agent credential is invalid or expired")
	}
	if err != nil {
		return Tokens{}, err
	}
	if agent.SpaceID != spaceID || agent.Status != "active" || agent.GroupStatus != "active" || !agent.ExpiresAt.Valid || !agent.ExpiresAt.Time.After(time.Now().UTC()) {
		return Tokens{}, apierr.New("invalid_grant", "agent credential is invalid or expired")
	}
	if actor != "" && (!agent.OwnerMemberID.Valid || agent.OwnerMemberID.String != actor) {
		return Tokens{}, apierr.New("invalid_grant", "actor token is not delegated by the subject")
	}
	st, err := s.Settings(ctx)
	if err != nil {
		return Tokens{}, err
	}
	if st.AccessTTL <= 0 {
		return Tokens{}, errors.New("invalid session settings")
	}
	now := time.Now().UTC()
	expiresAt := now.Add(st.AccessTTL)
	if notAfter > 0 {
		parentExpiry := time.Unix(notAfter, 0)
		if parentExpiry.Before(expiresAt) {
			expiresAt = parentExpiry
		}
	}
	jti, err := randomToken("jti_")
	if err != nil {
		return Tokens{}, err
	}
	if strings.TrimSpace(audience) == "" {
		audience = security.DefaultApplicationAudience
	}
	ownerChain, expiresAt, err := s.agentOwnerClaimAt(ctx, q, memberID, map[string]struct{}{}, 0, now, expiresAt)
	if err != nil {
		return Tokens{}, err
	}
	if expiresAt.Unix() <= now.Unix() {
		return Tokens{}, apierr.New("invalid_grant", "delegated token would already be expired")
	}
	jwt, err := s.Signer.Sign(security.Claims{Issuer: s.Signer.Issuer(), Subject: memberID, MemberID: memberID, SpaceID: spaceID, Audience: audience, ExpiresAt: expiresAt.Unix(), IssuedAt: now.Unix(), JWTID: jti, Assurance: 1, AMR: []string{"agent_key"}, Actor: ownerChain, Scopes: scopes, Type: "agent", AgentTokenEpoch: agent.TokenEpoch})
	if err != nil {
		return Tokens{}, err
	}
	action, actorID := "agent.access.issue", memberID
	if actor != "" {
		action, actorID = "agent.token.exchange", actor
	}
	if err := audit.WriteSecurityEvent(ctx, q, audit.SecurityEvent{
		ActorType: "member", ActorID: actorID, Action: action, Outcome: "success", MemberID: memberID,
		Metadata: map[string]string{"expires_at": expiresAt.UTC().Format(time.RFC3339), "audience": audience, "scope": strings.Join(scopes, " ")},
	}); err != nil {
		return Tokens{}, err
	}
	return Tokens{AccessToken: jwt, TokenType: "Bearer", ExpiresIn: int64(expiresAt.Sub(now) / time.Second)}, nil
}

func (s *Service) agentOwnerClaimAt(ctx context.Context, q *db.Queries, memberID string, seen map[string]struct{}, depth int, now, expiresAt time.Time) (*security.ActorClaim, time.Time, error) {
	if depth >= 64 {
		return nil, time.Time{}, apierr.New("OWNER_INACTIVE", "the Agent owner chain exceeds the supported depth")
	}
	if _, ok := seen[memberID]; ok {
		return nil, time.Time{}, apierr.New("OWNER_INACTIVE", "the Agent owner chain contains a cycle")
	}
	seen[memberID] = struct{}{}
	agent, err := q.GetAgentMember(ctx, db.GetAgentMemberParams{MemberID: memberID})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, time.Time{}, apierr.New("OWNER_INACTIVE", "the Agent owner member was not found")
	}
	if err != nil {
		return nil, time.Time{}, err
	}
	if agent.Status != "active" || agent.GroupStatus != "active" || !agent.ExpiresAt.Valid || !agent.ExpiresAt.Time.After(now) {
		return nil, time.Time{}, apierr.New("OWNER_INACTIVE", "the Agent owner member is not active")
	}
	if agent.ExpiresAt.Time.Before(expiresAt) {
		expiresAt = agent.ExpiresAt.Time
	}
	if !agent.OwnerMemberID.Valid || strings.TrimSpace(agent.OwnerMemberID.String) == "" {
		return nil, time.Time{}, apierr.New("OWNER_INACTIVE", "the Agent owner is missing")
	}
	owner, err := q.GetMemberForAuthorization(ctx, db.GetMemberForAuthorizationParams{ID: agent.OwnerMemberID.String})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, time.Time{}, apierr.New("OWNER_INACTIVE", "the Agent owner member was not found")
	}
	if err != nil {
		return nil, time.Time{}, err
	}
	if owner.Status != "active" {
		return nil, time.Time{}, apierr.New("OWNER_INACTIVE", "the Agent owner member is not active")
	}
	claim := &security.ActorClaim{Subject: owner.ID, MemberID: owner.ID, Type: owner.Type}
	if owner.Type == "agent" {
		claim.Actor, expiresAt, err = s.agentOwnerClaimAt(ctx, q, owner.ID, seen, depth+1, now, expiresAt)
		if err != nil {
			return nil, time.Time{}, err
		}
	}
	return claim, expiresAt, nil
}
func (s *Service) Revoke(ctx context.Context, sid string) error {
	return s.Store.InTx(ctx, func(q *db.Queries) error {
		if err := q.RevokeSession(ctx, db.RevokeSessionParams{ID: sid}); err != nil {
			return err
		}
		return q.RevokeSessionRefreshTokens(ctx, db.RevokeSessionRefreshTokensParams{SessionID: sid})
	})
}

func (s *Service) ListUserSessions(ctx context.Context, userID string) ([]DeviceSession, error) {
	rows, err := s.Store.Queries().ListUserSessions(ctx, db.ListUserSessionsParams{UserID: userID})
	if err != nil {
		return nil, err
	}
	out := make([]DeviceSession, 0, len(rows))
	for _, row := range rows {
		item := DeviceSession{ID: row.ID, CreatedAt: row.CreatedAt.Time, LastSeenAt: row.LastSeenAt.Time, ExpiresAt: row.ExpiresAt.Time, AuthTime: row.AuthTime.Time, AssuranceLevel: row.AssuranceLevel, AuthMethods: append([]string(nil), row.AuthMethods...)}
		if row.MemberID.Valid {
			item.MemberID = row.MemberID.String
		}
		if row.Ip.Valid {
			item.IP = row.Ip.String
		}
		if row.UserAgent.Valid {
			item.UserAgent = row.UserAgent.String
		}
		out = append(out, item)
	}
	return out, nil
}

func (s *Service) RevokeUserSession(ctx context.Context, userID, sessionID string) error {
	return s.Store.InTx(ctx, func(q *db.Queries) error {
		row, err := q.GetSession(ctx, db.GetSessionParams{ID: sessionID})
		if errors.Is(err, pgx.ErrNoRows) || err == nil && row.UserID != userID {
			return apierr.New("NOT_FOUND", "session was not found")
		}
		if err != nil {
			return err
		}
		if err := q.RevokeUserSession(ctx, db.RevokeUserSessionParams{ID: sessionID, UserID: userID}); err != nil {
			return err
		}
		return q.RevokeSessionRefreshTokens(ctx, db.RevokeSessionRefreshTokensParams{SessionID: sessionID})
	})
}

func (s *Service) RevokeAllUserSessions(ctx context.Context, userID string) error {
	return s.Store.InTx(ctx, func(q *db.Queries) error {
		if err := q.RevokeUserSessions(ctx, db.RevokeUserSessionsParams{UserID: userID}); err != nil {
			return err
		}
		return q.RevokeUserRefreshTokens(ctx, db.RevokeUserRefreshTokensParams{UserID: userID})
	})
}
func (s *Service) VerifyAccess(token string) (security.Claims, error) {
	return s.Signer.Verify(token, time.Now().UTC(), security.DefaultApplicationAudience)
}

// Introspect verifies the token cryptographically and then checks the current
// session and account state. A valid signature alone is insufficient because
// access tokens are intentionally short lived but session revocation is meant
// to take effect immediately for online callers.
func (s *Service) Introspect(ctx context.Context, token, audience string) (security.Claims, bool, error) {
	return s.IntrospectTx(ctx, s.Store.Queries(), token, audience)
}

// IntrospectTx reads live identity through the supplied queries. Mutations must
// first lock the relevant member/owner chains to stabilize status and epochs.
func (s *Service) IntrospectTx(ctx context.Context, q *db.Queries, token, audience string) (security.Claims, bool, error) {
	claims, err := s.Signer.Verify(token, time.Now().UTC(), audience)
	if err != nil || (claims.Type != "user" && claims.Type != "access" && claims.Type != "agent") {
		return security.Claims{}, false, nil
	}
	if claims.Type == "agent" {
		return s.introspectAgent(ctx, q, claims)
	}
	if claims.SessionID == "" {
		return security.Claims{}, false, nil
	}
	sess, err := q.GetSession(ctx, db.GetSessionParams{ID: claims.SessionID})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return security.Claims{}, false, nil
		}
		return security.Claims{}, false, err
	}
	if sess.UserID != claims.Subject || sess.RevokedAt.Valid || !sess.ExpiresAt.Valid || !sess.ExpiresAt.Time.After(time.Now().UTC()) {
		return security.Claims{}, false, nil
	}
	user, err := q.GetUserByID(ctx, db.GetUserByIDParams{ID: claims.Subject})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return security.Claims{}, false, nil
		}
		return security.Claims{}, false, err
	}
	if user.DisabledAt.Valid || user.Status != "active" {
		return security.Claims{}, false, nil
	}
	if claims.MemberID != sess.MemberID.String {
		return security.Claims{}, false, nil
	}
	if sess.SsoMemberID.Valid && sess.SsoMemberID.String != claims.MemberID {
		_, permitted, err := boundMemberSpace(ctx, q, claims.Subject, sess.SsoMemberID.String, time.Now().UTC())
		if err != nil || !permitted {
			return security.Claims{}, false, err
		}
	}
	if claims.MemberID != "" {
		spaceID, permitted, err := boundMemberSpace(ctx, q, claims.Subject, claims.MemberID, time.Now().UTC())
		if err != nil {
			return security.Claims{}, false, err
		}
		if !permitted || claims.SpaceID != spaceID {
			return security.Claims{}, false, nil
		}
	} else if claims.SpaceID != "" {
		return security.Claims{}, false, nil
	}
	return claims, true, nil
}

func activeUser(ctx context.Context, q *db.Queries, userID string) (bool, error) {
	user, err := q.GetUserByID(ctx, db.GetUserByIDParams{ID: userID})
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return user.Status == "active" && !user.DisabledAt.Valid, nil
}

func boundMemberSpace(ctx context.Context, q *db.Queries, userID, memberID string, now time.Time) (string, bool, error) {
	binding, err := q.GetUserMemberBinding(ctx, db.GetUserMemberBindingParams{UserID: userID, MemberID: memberID})
	if errors.Is(err, pgx.ErrNoRows) {
		return "", false, nil
	}
	if err != nil {
		return "", false, err
	}
	if binding.Status != "active" || binding.RevokedAt.Valid || (binding.ExpiresAt.Valid && !binding.ExpiresAt.Time.After(now)) {
		return "", false, nil
	}
	member, err := q.GetMemberForAuthorization(ctx, db.GetMemberForAuthorizationParams{ID: memberID})
	if errors.Is(err, pgx.ErrNoRows) {
		return "", false, nil
	}
	if err != nil {
		return "", false, err
	}
	return member.SpaceID, member.Status == "active" && member.Type == "human", nil
}

func (s *Service) introspectAgent(ctx context.Context, q *db.Queries, claims security.Claims) (security.Claims, bool, error) {
	if claims.Subject == "" {
		return security.Claims{}, false, nil
	}
	now := time.Now().UTC()
	row, err := q.GetAgentMember(ctx, db.GetAgentMemberParams{MemberID: claims.Subject})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return security.Claims{}, false, nil
		}
		return security.Claims{}, false, err
	}
	if claims.AgentTokenEpoch != row.TokenEpoch || (claims.SpaceID != "" && claims.SpaceID != row.SpaceID) || row.Status != "active" || row.GroupStatus != "active" || (row.ExpiresAt.Valid && !row.ExpiresAt.Time.After(now)) {
		return security.Claims{}, false, nil
	}
	// Owner-chain validity is an authorization fact. Keeping the token
	// authenticated lets the shared engine return OWNER_INACTIVE or
	// OWNER_ENVELOPE_EXCLUDED instead of collapsing the result to UNAUTHENTICATED.
	return claims, true, nil
}
func pgTime(t time.Time) pgtype.Timestamptz { return pgtype.Timestamptz{Time: t, Valid: true} }
func nullable(v string) pgtype.Text         { return pgtype.Text{String: v, Valid: v != ""} }
func nullableInt(v int32) pgtype.Int2       { return pgtype.Int2{Int16: int16(v), Valid: true} }
func ipString(ip net.IP) string {
	if ip == nil {
		return ""
	}
	return ip.String()
}

var _ = fmt.Sprintf
