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
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/plystra/auth/internal/apierr"
	"github.com/plystra/auth/internal/db"
	"github.com/plystra/auth/internal/ids"
	"github.com/plystra/auth/internal/security"
	"github.com/plystra/auth/internal/store"
)

type Settings struct{ AccessTTL, RefreshTTL, RefreshIdleTTL time.Duration }
type Service struct {
	Store    *store.Store
	Signer   *security.Signer
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
	st, err := s.Settings(ctx)
	if err != nil {
		return Tokens{}, err
	}
	if st.AccessTTL <= 0 || st.RefreshTTL <= 0 {
		return Tokens{}, errors.New("invalid session settings")
	}
	accessID, e := randomToken("jti_")
	if e != nil {
		return Tokens{}, e
	}
	refresh, e := randomToken("rfr_")
	if e != nil {
		return Tokens{}, e
	}
	sid := ids.New[ids.SessionID]("ses")
	family := ids.New[ids.RefreshFamilyID]("rtf")
	rid := ids.New[ids.RefreshTokenID]("rft")
	now := time.Now().UTC()
	exp := now.Add(st.RefreshTTL)
	var sessionID string
	err = s.Store.InTx(ctx, func(q *db.Queries) error {
		row, e := q.CreateSession(ctx, db.CreateSessionParams{ID: string(sid), UserID: userID, TokenHash: s.hashToken(refresh), ExpiresAt: pgTime(exp), Ip: nullable(ipString(ip)), UserAgent: nullable(userAgent), AuthTime: pgTime(now), AssuranceLevel: nullableInt(int32(assurance))})
		if e != nil {
			return e
		}
		sessionID = row.ID
		_, e = q.CreateRefreshToken(ctx, db.CreateRefreshTokenParams{ID: string(rid), SessionID: row.ID, FamilyID: string(family), TokenHash: s.hashToken(refresh), ExpiresAt: pgTime(exp)})
		return e
	})
	if err != nil {
		return Tokens{}, err
	}
	jwt, err := s.Signer.Sign(security.Claims{Issuer: s.Signer.Issuer(), Subject: userID, MemberID: memberID, Audience: security.DefaultApplicationAudience, ExpiresAt: now.Add(st.AccessTTL).Unix(), IssuedAt: now.Unix(), JWTID: accessID, SessionID: sessionID, Assurance: assurance, Type: "user"})
	if err != nil {
		return Tokens{}, err
	}
	return Tokens{AccessToken: jwt, TokenType: "Bearer", ExpiresIn: int64(st.AccessTTL / time.Second), RefreshToken: refresh, SessionID: sessionID}, nil
}
func (s *Service) Refresh(ctx context.Context, raw string) (Tokens, error) {
	st, err := s.Settings(ctx)
	if err != nil {
		return Tokens{}, err
	}
	next, err := randomToken("rfr_")
	if err != nil {
		return Tokens{}, err
	}
	now := time.Now().UTC()
	sid, uid, family := "", "", ""
	assurance := 1
	err = s.Store.InTx(ctx, func(q *db.Queries) error {
		var token db.RefreshToken
		found := false
		for _, hash := range s.tokenHashes(raw) {
			token, err = q.LockRefreshToken(ctx, db.LockRefreshTokenParams{TokenHash: hash})
			if err == nil {
				found = true
				break
			}
			if !errors.Is(err, pgx.ErrNoRows) {
				return err
			}
		}
		if !found {
			return apierr.New("invalid_grant", "refresh token is invalid")
		}
		if token.RevokedAt.Valid || token.UsedAt.Valid || token.ExpiresAt.Time.Before(now) || (st.RefreshIdleTTL > 0 && token.IssuedAt.Time.Add(st.RefreshIdleTTL).Before(now)) {
			if err = q.RevokeRefreshFamily(ctx, db.RevokeRefreshFamilyParams{FamilyID: token.FamilyID}); err != nil {
				return err
			}
			if err = q.RevokeSession(ctx, db.RevokeSessionParams{ID: token.SessionID}); err != nil {
				return err
			}
			return apierr.New("invalid_grant", "refresh token has been revoked")
		}
		if err = q.MarkRefreshUsed(ctx, db.MarkRefreshUsedParams{ID: token.ID}); err != nil {
			return err
		}
		sid, family = token.SessionID, token.FamilyID
		sess, err := q.GetSession(ctx, db.GetSessionParams{ID: sid})
		if err != nil {
			return err
		}
		uid, assurance = sess.UserID, int(sess.AssuranceLevel)
		_, err = q.CreateRefreshToken(ctx, db.CreateRefreshTokenParams{ID: string(ids.New[ids.RefreshTokenID]("rft")), SessionID: sid, FamilyID: family, TokenHash: s.hashToken(next), ExpiresAt: pgTime(now.Add(st.RefreshTTL))})
		return err
	})
	if err != nil {
		return Tokens{}, err
	}
	jti, _ := randomToken("jti_")
	jwt, err := s.Signer.Sign(security.Claims{Issuer: s.Signer.Issuer(), Subject: uid, Audience: security.DefaultApplicationAudience, ExpiresAt: now.Add(st.AccessTTL).Unix(), IssuedAt: now.Unix(), JWTID: jti, SessionID: sid, Assurance: assurance, Type: "user"})
	if err != nil {
		return Tokens{}, err
	}
	return Tokens{AccessToken: jwt, TokenType: "Bearer", ExpiresIn: int64(st.AccessTTL / time.Second), RefreshToken: next, SessionID: sid}, nil
}

// CreateAgentAccess exchanges a one-time agent credential validation for a
// short-lived access token. Agent sessions are intentionally stateless: live
// member and owner-chain status is checked during introspection/authz checks.
func (s *Service) CreateAgentAccess(ctx context.Context, memberID, spaceID, audience string) (Tokens, error) {
	st, err := s.Settings(ctx)
	if err != nil {
		return Tokens{}, err
	}
	if st.AccessTTL <= 0 {
		return Tokens{}, errors.New("invalid session settings")
	}
	now := time.Now().UTC()
	jti, err := randomToken("jti_")
	if err != nil {
		return Tokens{}, err
	}
	if strings.TrimSpace(audience) == "" {
		audience = security.DefaultApplicationAudience
	}
	jwt, err := s.Signer.Sign(security.Claims{Issuer: s.Signer.Issuer(), Subject: memberID, MemberID: memberID, SpaceID: spaceID, Audience: audience, ExpiresAt: now.Add(st.AccessTTL).Unix(), IssuedAt: now.Unix(), JWTID: jti, Assurance: 1, Type: "agent"})
	if err != nil {
		return Tokens{}, err
	}
	return Tokens{AccessToken: jwt, TokenType: "Bearer", ExpiresIn: int64(st.AccessTTL / time.Second)}, nil
}
func (s *Service) Revoke(ctx context.Context, sid string) error {
	return s.Store.InTx(ctx, func(q *db.Queries) error {
		if err := q.RevokeSession(ctx, db.RevokeSessionParams{ID: sid}); err != nil {
			return err
		}
		return q.RevokeSessionRefreshTokens(ctx, db.RevokeSessionRefreshTokensParams{SessionID: sid})
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
	claims, err := s.Signer.Verify(token, time.Now().UTC(), audience)
	if err != nil || (claims.Type != "user" && claims.Type != "access" && claims.Type != "agent") {
		return security.Claims{}, false, nil
	}
	if claims.Type == "agent" {
		return s.introspectAgent(ctx, claims)
	}
	if claims.SessionID == "" {
		return security.Claims{}, false, nil
	}
	sess, err := s.Store.Queries().GetSession(ctx, db.GetSessionParams{ID: claims.SessionID})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return security.Claims{}, false, nil
		}
		return security.Claims{}, false, err
	}
	if sess.UserID != claims.Subject || sess.RevokedAt.Valid || !sess.ExpiresAt.Valid || !sess.ExpiresAt.Time.After(time.Now().UTC()) {
		return security.Claims{}, false, nil
	}
	user, err := s.Store.Queries().GetUserByID(ctx, db.GetUserByIDParams{ID: claims.Subject})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return security.Claims{}, false, nil
		}
		return security.Claims{}, false, err
	}
	if user.DisabledAt.Valid || user.Status != "active" {
		return security.Claims{}, false, nil
	}
	return claims, true, nil
}

func (s *Service) introspectAgent(ctx context.Context, claims security.Claims) (security.Claims, bool, error) {
	if claims.Subject == "" {
		return security.Claims{}, false, nil
	}
	now := time.Now().UTC()
	memberID := claims.Subject
	for depth := 0; depth < 8; depth++ {
		row, err := s.Store.Queries().GetAgentMember(ctx, db.GetAgentMemberParams{MemberID: memberID})
		if err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return security.Claims{}, false, nil
			}
			return security.Claims{}, false, err
		}
		if (claims.SpaceID != "" && claims.SpaceID != row.SpaceID) || row.Status != "active" || row.GroupStatus != "active" || (row.ExpiresAt.Valid && !row.ExpiresAt.Time.After(now)) {
			return security.Claims{}, false, nil
		}
		if !row.OwnerMemberID.Valid || row.OwnerMemberID.String == "" {
			return security.Claims{}, false, nil
		}
		owner, err := s.Store.Queries().GetMemberForAgentOwner(ctx, db.GetMemberForAgentOwnerParams{MemberID: row.OwnerMemberID.String})
		if err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return security.Claims{}, false, nil
			}
			return security.Claims{}, false, err
		}
		if owner.Status != "active" || (owner.ExpiresAt.Valid && !owner.ExpiresAt.Time.After(now)) {
			return security.Claims{}, false, nil
		}
		if owner.Type != "agent" {
			return claims, true, nil
		}
		memberID = owner.ID
	}
	return security.Claims{}, false, nil
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
