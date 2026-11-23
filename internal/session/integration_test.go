package session

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/plystra/auth/internal/agent"
	"github.com/plystra/auth/internal/apierr"
	"github.com/plystra/auth/internal/authorization"
	"github.com/plystra/auth/internal/security"
	"github.com/plystra/auth/internal/store"
	"github.com/plystra/auth/internal/testdb"
)

var sessionDB *testdb.Harness

func TestMain(m *testing.M) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	var err error
	sessionDB, err = testdb.Start(ctx)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	code := m.Run()
	if err := sessionDB.Close(context.Background()); err != nil && code == 0 {
		fmt.Fprintln(os.Stderr, err)
		code = 1
	}
	os.Exit(code)
}

func TestRefreshTokenUsesPlystraPrefixEntropyHashingAndHMACKeyRotation(t *testing.T) {
	ctx := context.Background()
	database, err := sessionDB.Clone(ctx)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = database.Close(context.Background()) })
	st, err := store.Open(ctx, database.URL)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(st.Close)
	if _, err := st.Pool.Exec(ctx, `
		INSERT INTO users (id, email, email_normalized, password_hash, status)
		VALUES ('usr_refresh_test', 'refresh@example.test', 'refresh@example.test', 'test-password-hash', 'active')
	`); err != nil {
		t.Fatal(err)
	}
	signer, err := security.GenerateSigner("https://auth.test")
	if err != nil {
		t.Fatal(err)
	}
	settings := func(context.Context) (Settings, error) {
		return Settings{AccessTTL: time.Minute, RefreshTTL: time.Hour, RefreshIdleTTL: 30 * time.Minute}, nil
	}
	oldKey := []byte(strings.Repeat("o", 32))
	newKey := []byte(strings.Repeat("n", 32))
	legacy := &Service{Store: st, Signer: signer, HMACKeys: [][]byte{oldKey}, Settings: settings}
	rotating := &Service{Store: st, Signer: signer, HMACKeys: [][]byte{newKey, oldKey}, Settings: settings}
	issued, err := legacy.Create(ctx, "usr_refresh_test", nil, "", 1)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(issued.RefreshToken, "ply_rt_") {
		t.Fatalf("refresh token prefix = %q, want ply_rt_", issued.RefreshToken)
	}
	rawEntropy, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(issued.RefreshToken, "ply_rt_"))
	if err != nil {
		t.Fatal(err)
	}
	if len(rawEntropy) != 32 {
		t.Fatalf("refresh token entropy = %d bytes, want 32", len(rawEntropy))
	}
	var stored []byte
	if err := st.Pool.QueryRow(ctx, `SELECT token_hash FROM refresh_tokens WHERE session_id = $1`, issued.SessionID).Scan(&stored); err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(stored, []byte(issued.RefreshToken)) || !bytes.Equal(stored, hmacSHA256(oldKey, issued.RefreshToken)) {
		t.Fatal("refresh token was not stored as an HMAC hash")
	}
	t.Run("signing failure preserves the original credential", func(t *testing.T) {
		unavailable := *rotating
		unavailable.Signer = &security.Signer{}
		if tokens, err := unavailable.Refresh(ctx, issued.RefreshToken); !errors.Is(err, security.ErrNoActiveSigningKey) || tokens != (Tokens{}) {
			t.Fatal("signing failure did not fail refresh without credentials")
		}
	})
	rotated, err := rotating.Refresh(ctx, issued.RefreshToken)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(rotated.RefreshToken, "ply_rt_") {
		t.Fatalf("rotated refresh token prefix = %q, want ply_rt_", rotated.RefreshToken)
	}
	var rotatedHash []byte
	if err := st.Pool.QueryRow(ctx, `SELECT token_hash FROM refresh_tokens WHERE session_id = $1 AND used_at IS NULL`, issued.SessionID).Scan(&rotatedHash); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(rotatedHash, hmacSHA256(newKey, rotated.RefreshToken)) {
		t.Fatal("rotated refresh token was not hashed with the current HMAC key")
	}
	var successfulRefreshAudits int
	if err := st.Pool.QueryRow(ctx, `SELECT count(*) FROM audit_logs WHERE action = 'auth.session.refresh' AND actor_id = 'usr_refresh_test'`).Scan(&successfulRefreshAudits); err != nil {
		t.Fatal(err)
	}
	if successfulRefreshAudits != 1 {
		t.Fatalf("successful refresh audit count = %d, want 1", successfulRefreshAudits)
	}
	if _, err := rotating.Refresh(ctx, issued.RefreshToken); err == nil {
		t.Fatal("replayed refresh token was accepted")
	} else {
		var public *apierr.Error
		if !errors.As(err, &public) || public.Code != "invalid_grant" {
			t.Fatalf("replayed refresh error = %v, want invalid_grant", err)
		}
	}
	var active int
	if err := st.Pool.QueryRow(ctx, `SELECT count(*) FROM refresh_tokens WHERE session_id = $1 AND revoked_at IS NULL`, issued.SessionID).Scan(&active); err != nil {
		t.Fatal(err)
	}
	if active != 0 {
		t.Fatalf("replayed refresh left %d active family tokens", active)
	}
	var replayAudits int
	if err := st.Pool.QueryRow(ctx, `
		SELECT count(*) FROM audit_logs
		WHERE action = 'auth.session.refresh_replay' AND metadata->>'priority' = 'high'
	`).Scan(&replayAudits); err != nil {
		t.Fatal(err)
	}
	if replayAudits != 1 {
		t.Fatalf("replay audit count = %d, want 1", replayAudits)
	}
	var leakedAuditTokens int
	if err := st.Pool.QueryRow(ctx, `
		SELECT count(*) FROM audit_logs
		WHERE metadata::text LIKE '%' || $1 || '%' OR metadata::text LIKE '%' || $2 || '%'
	`, issued.RefreshToken, rotated.RefreshToken).Scan(&leakedAuditTokens); err != nil {
		t.Fatal(err)
	}
	if leakedAuditTokens != 0 {
		t.Fatal("refresh token appeared in audit metadata")
	}
	if _, stillActive, err := rotating.Introspect(ctx, rotated.AccessToken, security.DefaultApplicationAudience); err != nil {
		t.Fatal(err)
	} else if stillActive {
		t.Fatal("replayed refresh token did not revoke the session")
	}

	concurrent, err := legacy.Create(ctx, "usr_refresh_test", nil, "", 1)
	if err != nil {
		t.Fatal(err)
	}
	start := make(chan struct{})
	results := make(chan error, 2)
	for i := 0; i < 2; i++ {
		go func() {
			<-start
			_, refreshErr := rotating.Refresh(ctx, concurrent.RefreshToken)
			results <- refreshErr
		}()
	}
	close(start)
	successes := 0
	failures := 0
	for i := 0; i < 2; i++ {
		if err := <-results; err == nil {
			successes++
		} else {
			failures++
			var public *apierr.Error
			if !errors.As(err, &public) || public.Code != "invalid_grant" {
				t.Fatalf("concurrent refresh error = %v, want invalid_grant", err)
			}
		}
	}
	if successes != 1 || failures != 1 {
		t.Fatalf("concurrent refresh results: successes=%d failures=%d, want one each", successes, failures)
	}
	var concurrentActive int
	if err := st.Pool.QueryRow(ctx, `SELECT count(*) FROM refresh_tokens WHERE session_id = $1 AND revoked_at IS NULL`, concurrent.SessionID).Scan(&concurrentActive); err != nil {
		t.Fatal(err)
	}
	if concurrentActive != 0 {
		t.Fatalf("concurrent refresh replay left %d active tokens", concurrentActive)
	}
}

func TestRefreshCanSwitchBoundMemberAndUpdatesAccessClaims(t *testing.T) {
	ctx := context.Background()
	database, err := sessionDB.Clone(ctx)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = database.Close(context.Background()) })
	st, err := store.Open(ctx, database.URL)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(st.Close)
	if _, err := st.Pool.Exec(ctx, `
		INSERT INTO users (id, email, email_normalized, password_hash, status)
		VALUES ('usr_switch_test', 'switch@example.test', 'switch@example.test', 'test-password-hash', 'active');
		INSERT INTO members (id, space_id, name, kind, type, binding_policy, status)
		VALUES
			('mem_switch_a', 'spc_01h00000000000000000000000', 'Switch A', 'user', 'human', 'single', 'active'),
			('mem_switch_b', 'spc_01h00000000000000000000000', 'Switch B', 'user', 'human', 'single', 'active');
		INSERT INTO user_members (user_id, member_id, status)
		VALUES ('usr_switch_test', 'mem_switch_a', 'active'), ('usr_switch_test', 'mem_switch_b', 'active');
	`); err != nil {
		t.Fatal(err)
	}
	signer, err := security.GenerateSigner("https://auth.test")
	if err != nil {
		t.Fatal(err)
	}
	sessions := &Service{
		Store:    st,
		Signer:   signer,
		HMACKeys: [][]byte{[]byte(strings.Repeat("s", 32))},
		Settings: func(context.Context) (Settings, error) {
			return Settings{AccessTTL: time.Minute, RefreshTTL: time.Hour, RefreshIdleTTL: 30 * time.Minute}, nil
		},
	}
	if _, err := sessions.CreateForMember(ctx, "usr_switch_test", "mem_switch_missing", nil, "", 1); err == nil {
		t.Fatal("session creation accepted an unbound member")
	} else {
		var public *apierr.Error
		if !errors.As(err, &public) || public.Code != "PERMISSION_DENIED" {
			t.Fatalf("unbound session creation error = %v, want PERMISSION_DENIED", err)
		}
	}
	issued, err := sessions.CreateForMember(ctx, "usr_switch_test", "mem_switch_a", nil, "", 1)
	if err != nil {
		t.Fatal(err)
	}
	initial, err := signer.Verify(issued.AccessToken, time.Now().UTC(), security.DefaultApplicationAudience)
	if err != nil {
		t.Fatal(err)
	}
	if initial.Issuer != signer.Issuer() || initial.Audience != security.DefaultApplicationAudience || initial.Subject != "usr_switch_test" || initial.SessionID != issued.SessionID || initial.Type != "user" || len(initial.AMR) != 1 || initial.AMR[0] != "pwd" || initial.JWTID == "" || initial.IssuedAt == 0 || initial.ExpiresAt <= initial.IssuedAt || len(initial.Scopes) != 0 {
		t.Fatalf("initial access claims = %+v, want identity-only ES256 claims with pwd amr", initial)
	}
	if issued.ExpiresIn != 60 || initial.ExpiresAt-initial.IssuedAt != 60 {
		t.Fatalf("initial access lifetime = expires_in=%d claim_ttl=%d, want 60 seconds", issued.ExpiresIn, initial.ExpiresAt-initial.IssuedAt)
	}
	if initial.MemberID != "mem_switch_a" || initial.SpaceID != "spc_01h00000000000000000000000" || len(initial.AMR) != 1 || initial.AMR[0] != "pwd" {
		t.Fatalf("initial access claims = %+v, want member A, default Space and pwd amr", initial)
	}
	if _, err := sessions.RefreshForMember(ctx, issued.RefreshToken, "mem_switch_missing"); err == nil {
		t.Fatal("refresh accepted an unbound member")
	} else {
		var public *apierr.Error
		if !errors.As(err, &public) || public.Code != "PERMISSION_DENIED" {
			t.Fatalf("unbound member error = %v, want PERMISSION_DENIED", err)
		}
	}
	switched, err := sessions.RefreshForMember(ctx, issued.RefreshToken, "mem_switch_b")
	if err != nil {
		t.Fatal(err)
	}
	claims, err := signer.Verify(switched.AccessToken, time.Now().UTC(), security.DefaultApplicationAudience)
	if err != nil {
		t.Fatal(err)
	}
	if claims.MemberID != "mem_switch_b" || claims.SpaceID != "spc_01h00000000000000000000000" {
		t.Fatalf("switched access claims = %+v, want member B and default Space", claims)
	}
	continued, err := sessions.Refresh(ctx, switched.RefreshToken)
	if err != nil {
		t.Fatal(err)
	}
	claims, err = signer.Verify(continued.AccessToken, time.Now().UTC(), security.DefaultApplicationAudience)
	if err != nil {
		t.Fatal(err)
	}
	if claims.MemberID != "mem_switch_b" || claims.SpaceID != "spc_01h00000000000000000000000" {
		t.Fatalf("continued access claims = %+v, want member B and default Space", claims)
	}
	if _, active, err := sessions.Introspect(ctx, continued.AccessToken, security.DefaultApplicationAudience); err != nil {
		t.Fatal(err)
	} else if !active {
		t.Fatal("active bound member token failed introspection")
	}
	if _, err := st.Pool.Exec(ctx, `UPDATE user_members SET status = 'revoked', revoked_at = now() WHERE user_id = 'usr_switch_test' AND member_id = 'mem_switch_b'`); err != nil {
		t.Fatal(err)
	}
	if _, active, err := sessions.Introspect(ctx, continued.AccessToken, security.DefaultApplicationAudience); err != nil {
		t.Fatal(err)
	} else if active {
		t.Fatal("revoked member binding remained active during introspection")
	}
	if _, err := sessions.Refresh(ctx, continued.RefreshToken); err == nil {
		t.Fatal("revoked member binding accepted a refresh")
	} else {
		var public *apierr.Error
		if !errors.As(err, &public) || public.Code != "PERMISSION_DENIED" {
			t.Fatalf("revoked binding refresh error = %v, want PERMISSION_DENIED", err)
		}
	}
}

func TestAgentAccessTokenContainsNestedOwnerChain(t *testing.T) {
	ctx := context.Background()
	database, err := sessionDB.Clone(ctx)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = database.Close(context.Background()) })
	st, err := store.Open(ctx, database.URL)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(st.Close)
	if _, err := st.Pool.Exec(ctx, `
		INSERT INTO users (id, email, email_normalized, password_hash, status)
		VALUES ('usr_agent_claims', 'agent-claims@example.test', 'agent-claims@example.test', 'test-password-hash', 'active')
	`); err != nil {
		t.Fatal(err)
	}
	authz := &authorization.Service{Store: st}
	space, owner, err := authz.CreateSpace(ctx, "usr_agent_claims", "Agent Claims Space", "agent-claims-space")
	if err != nil {
		t.Fatal(err)
	}
	agents := &agent.Service{Store: st}
	parent, _, err := agents.Create(ctx, agent.CreateInput{OwnerMemberID: owner.ID, Name: "claims-parent", ExpiresAt: time.Now().UTC().Add(2 * time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	child, _, err := agents.Create(ctx, agent.CreateInput{OwnerMemberID: parent.ID, Name: "claims-child", ExpiresAt: time.Now().UTC().Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	signer, err := security.GenerateSigner("https://auth.test")
	if err != nil {
		t.Fatal(err)
	}
	sessions := &Service{
		Store:    st,
		Signer:   signer,
		HMACKeys: [][]byte{[]byte(strings.Repeat("a", 32))},
		Settings: func(context.Context) (Settings, error) {
			return Settings{AccessTTL: time.Minute, RefreshTTL: time.Hour, RefreshIdleTTL: 30 * time.Minute}, nil
		},
	}
	assertInvalidAgentAccess := func(spaceID, reason string) {
		t.Helper()
		_, err := sessions.CreateAgentAccess(ctx, child.ID, spaceID, security.DefaultApplicationAudience)
		if err == nil {
			t.Fatalf("%s Agent received an access token", reason)
		}
		var public *apierr.Error
		if !errors.As(err, &public) || public.Code != "invalid_grant" {
			t.Fatalf("%s Agent access = %v, want invalid_grant", reason, err)
		}
	}
	assertInvalidAgentAccess("spc_wrong", "mismatched Space")
	tokens, err := sessions.CreateAgentAccess(ctx, child.ID, space.ID, security.DefaultApplicationAudience)
	if err != nil {
		t.Fatal(err)
	}
	claims, err := signer.Verify(tokens.AccessToken, time.Now().UTC(), security.DefaultApplicationAudience)
	if err != nil {
		t.Fatal(err)
	}
	if claims.Type != "agent" || claims.Subject != child.ID || claims.MemberID != child.ID {
		t.Fatalf("Agent access claims = %+v, want typ agent with child sub/mid", claims)
	}
	t.Run("TokenEpochRejectsMissingOrWrongGeneration", func(t *testing.T) {
		for _, epoch := range []int64{0, claims.AgentTokenEpoch + 1} {
			altered := claims
			altered.AgentTokenEpoch = epoch
			token, err := signer.Sign(altered)
			if err != nil {
				t.Fatal(err)
			}
			if _, active, err := sessions.Introspect(ctx, token, security.DefaultApplicationAudience); err != nil || active {
				t.Fatalf("incorrect Agent token generation: active=%v error=%v", active, err)
			}
		}
	})
	if _, err := st.Pool.Exec(ctx, `UPDATE members SET version = version + 1 WHERE id = $1`, child.ID); err != nil {
		t.Fatal(err)
	}
	if _, active, err := sessions.Introspect(ctx, tokens.AccessToken, security.DefaultApplicationAudience); err != nil || !active {
		t.Fatalf("authority version change invalidated the Agent identity: active=%v error=%v", active, err)
	}
	if claims.Actor == nil || claims.Actor.Subject != parent.ID || claims.Actor.MemberID != parent.ID || claims.Actor.Type != "agent" {
		t.Fatalf("Agent actor claim = %+v, want parent Agent", claims.Actor)
	}
	if claims.Actor.Actor == nil || claims.Actor.Actor.Subject != owner.ID || claims.Actor.Actor.MemberID != owner.ID || claims.Actor.Actor.Type != "human" || claims.Actor.Actor.Actor != nil {
		t.Fatalf("nested Agent owner claim = %+v, want terminal human owner", claims.Actor.Actor)
	}
	if _, err := st.Pool.Exec(ctx, `UPDATE members SET status = 'suspended' WHERE id = $1`, child.ID); err != nil {
		t.Fatal(err)
	}
	assertInvalidAgentAccess(space.ID, "suspended")
	if _, err := st.Pool.Exec(ctx, `UPDATE members SET status = 'active' WHERE id = $1`, child.ID); err != nil {
		t.Fatal(err)
	}
	t.Run("RevokedTokensDoNotRevive", func(t *testing.T) {
		if _, active, err := sessions.Introspect(ctx, tokens.AccessToken, security.DefaultApplicationAudience); err != nil || active {
			t.Fatalf("resume revalidated a pre-suspension token: active=%v error=%v", active, err)
		}
		fresh, err := sessions.CreateAgentAccess(ctx, child.ID, space.ID, security.DefaultApplicationAudience)
		if err != nil {
			t.Fatal(err)
		}
		if _, active, err := sessions.Introspect(ctx, fresh.AccessToken, security.DefaultApplicationAudience); err != nil || !active {
			t.Fatalf("fresh token after resume is not valid: active=%v error=%v", active, err)
		}
	})
	if _, err := st.Pool.Exec(ctx, `UPDATE groups SET status = 'suspended' WHERE id = $1`, child.HomeGroupID); err != nil {
		t.Fatal(err)
	}
	assertInvalidAgentAccess(space.ID, "suspended home group")
	if _, err := st.Pool.Exec(ctx, `UPDATE groups SET status = 'active' WHERE id = $1`, child.HomeGroupID); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Pool.Exec(ctx, `UPDATE members SET expires_at = now() - interval '1 second' WHERE id = $1`, child.ID); err != nil {
		t.Fatal(err)
	}
	assertInvalidAgentAccess(space.ID, "expired")
}

func TestAgentAccessTokenExpiryIsBoundedByDelegation(t *testing.T) {
	ctx := context.Background()
	database, err := sessionDB.Clone(ctx)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = database.Close(context.Background()) })
	st, err := store.Open(ctx, database.URL)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(st.Close)
	if _, err := st.Pool.Exec(ctx, `INSERT INTO users (id, email, email_normalized, password_hash, status)
		VALUES ('usr_agent_expiry', 'agent-expiry@example.test', 'agent-expiry@example.test', 'test-password-hash', 'active')`); err != nil {
		t.Fatal(err)
	}
	authz := &authorization.Service{Store: st}
	space, owner, err := authz.CreateSpace(ctx, "usr_agent_expiry", "Agent Expiry Space", "agent-expiry-space")
	if err != nil {
		t.Fatal(err)
	}
	agents := &agent.Service{Store: st}
	now := time.Now().UTC().Truncate(time.Second)
	parent, _, err := agents.Create(ctx, agent.CreateInput{OwnerMemberID: owner.ID, Name: "expiry-parent", ExpiresAt: now.Add(2 * time.Minute)})
	if err != nil {
		t.Fatal(err)
	}
	child, _, err := agents.Create(ctx, agent.CreateInput{OwnerMemberID: parent.ID, Name: "expiry-child", ExpiresAt: now.Add(time.Minute)})
	if err != nil {
		t.Fatal(err)
	}
	signer, err := security.GenerateSigner("https://auth.test")
	if err != nil {
		t.Fatal(err)
	}
	sessions := &Service{Store: st, Signer: signer, Settings: func(context.Context) (Settings, error) {
		return Settings{AccessTTL: 5 * time.Minute}, nil
	}}
	assertExpiry := func(tokens Tokens, err error, want time.Time) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
		claims, err := signer.Verify(tokens.AccessToken, time.Now().UTC(), "app_expiry")
		if err != nil {
			t.Fatal(err)
		}
		if claims.ExpiresAt != want.Unix() || tokens.ExpiresIn > int64(time.Until(want)/time.Second)+1 {
			t.Fatalf("access expiry = %d, expires_in = %d; want bound %d", claims.ExpiresAt, tokens.ExpiresIn, want.Unix())
		}
	}
	tokens, err := sessions.CreateAgentAccess(ctx, child.ID, space.ID, "app_expiry")
	assertExpiry(tokens, err, child.ExpiresAt)
	delegationExpiry := now.Add(40 * time.Second)
	tokens, err = sessions.CreateAgentDelegatedAccess(ctx, child.ID, space.ID, "app_expiry", parent.ID, []string{"invoice:read"}, delegationExpiry.Unix())
	assertExpiry(tokens, err, delegationExpiry)
	t.Run("DelegatorMustBeDirectOwner", func(t *testing.T) {
		for _, actor := range []string{owner.ID, "mem_other"} {
			denied, err := sessions.CreateAgentDelegatedAccess(ctx, child.ID, space.ID, "app_expiry", actor, []string{"invoice:read"}, delegationExpiry.Unix())
			var public *apierr.Error
			if !errors.As(err, &public) || public.Code != "invalid_grant" || denied.AccessToken != "" {
				t.Fatalf("invalid delegator received a token: error=%v", err)
			}
		}
	})
	t.Run("OptionalUpperBoundUsesAgentLifetime", func(t *testing.T) {
		tokens, err := sessions.CreateAgentDelegatedAccess(ctx, child.ID, space.ID, "app_expiry", parent.ID, []string{"invoice:read"}, 0)
		assertExpiry(tokens, err, child.ExpiresAt)
	})
	assertOwnerInactive := func(reason string) {
		t.Helper()
		_, err := sessions.CreateAgentAccess(ctx, child.ID, space.ID, "app_expiry")
		var public *apierr.Error
		if !errors.As(err, &public) || public.Code != "OWNER_INACTIVE" {
			t.Fatalf("%s: child access error = %v, want OWNER_INACTIVE", reason, err)
		}
	}
	for _, inactive := range []struct {
		name, query, id string
	}{
		{"suspended Agent owner", `UPDATE members SET status = $1 WHERE id = $2`, parent.ID},
		{"suspended owner group", `UPDATE groups SET status = $1 WHERE id = $2`, parent.HomeGroupID},
		{"suspended human owner", `UPDATE members SET status = $1 WHERE id = $2`, owner.ID},
	} {
		if _, err := st.Pool.Exec(ctx, inactive.query, "suspended", inactive.id); err != nil {
			t.Fatal(err)
		}
		assertOwnerInactive(inactive.name)
		if _, err := st.Pool.Exec(ctx, inactive.query, "active", inactive.id); err != nil {
			t.Fatal(err)
		}
	}
	ownerExpiry := now.Add(20 * time.Second)
	if _, err := st.Pool.Exec(ctx, `UPDATE members SET expires_at = $1 WHERE id = $2`, ownerExpiry, parent.ID); err != nil {
		t.Fatal(err)
	}
	tokens, err = sessions.CreateAgentAccess(ctx, child.ID, space.ID, "app_expiry")
	assertExpiry(tokens, err, ownerExpiry)
	if _, err := st.Pool.Exec(ctx, `UPDATE members SET expires_at = now() - interval '1 second' WHERE id = $1`, parent.ID); err != nil {
		t.Fatal(err)
	}
	assertOwnerInactive("expired Agent owner")
}

func hmacSHA256(key []byte, value string) []byte {
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write([]byte(value))
	return mac.Sum(nil)
}
