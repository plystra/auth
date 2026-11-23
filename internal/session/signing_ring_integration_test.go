package session

import (
	"context"
	"crypto/rand"
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/plystra/auth/internal/apierr"
	"github.com/plystra/auth/internal/db"
	"github.com/plystra/auth/internal/security"
	"github.com/plystra/auth/internal/store"
)

func TestSessionIssuanceAndIntrospectionUseRequestSigningKeys(t *testing.T) {
	ctx := t.Context()
	database, err := sessionDB.Clone(ctx)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = database.Close(context.Background()) })
	st, err := store.Open(ctx, database.AppURL)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(st.Close)
	const issuer = "https://issuer.example.test"
	const user = "usr_signing_session"
	if _, err := st.Pool.Exec(ctx, `INSERT INTO users (id,email,email_normalized,password_hash,status)
		VALUES ($1, 'account@example.test', 'account@example.test', 'test-hash', 'active')`, user); err != nil {
		t.Fatal(err)
	}
	seed, err := security.GenerateSigner(issuer)
	if err != nil {
		t.Fatal(err)
	}
	var wrappingKey, sessionKey [32]byte
	if _, err := rand.Read(wrappingKey[:]); err != nil {
		t.Fatal(err)
	}
	if _, err := rand.Read(sessionKey[:]); err != nil {
		t.Fatal(err)
	}
	svc := &Service{
		Store: st, HMACKeys: [][]byte{sessionKey[:]},
		LoadSigner: func(ctx context.Context, q *db.Queries) (*security.Signer, error) {
			return store.LoadSigningKeys(ctx, q, issuer, wrappingKey[:])
		},
		Settings: func(context.Context) (Settings, error) {
			return Settings{AccessTTL: time.Minute, RefreshTTL: time.Hour, RefreshIdleTTL: time.Hour}, nil
		},
	}
	create := func(ctx context.Context) (Tokens, error) {
		return svc.CreateForMemberWithMethods(ctx, user, "", nil, "", 1, []string{"pwd"})
	}
	requireUnavailable := func(t *testing.T, err error) {
		t.Helper()
		var public *apierr.Error
		if !errors.As(err, &public) || public.GetStatus() != http.StatusServiceUnavailable || public.Code != "temporarily_unavailable" {
			t.Fatal("expected a temporary signing key failure")
		}
	}
	checkStored := func(t *testing.T, wantKeys, wantSessions, wantRefresh int) {
		t.Helper()
		var keys, sessions, refresh int
		if err := st.Pool.QueryRow(ctx, `SELECT (SELECT count(*) FROM signing_keys),
			(SELECT count(*) FROM sessions), (SELECT count(*) FROM refresh_tokens)`).Scan(&keys, &sessions, &refresh); err != nil {
			t.Fatal(err)
		}
		if keys != wantKeys || sessions != wantSessions || refresh != wantRefresh {
			t.Fatalf("committed keys/sessions/refresh = %d/%d/%d, want %d/%d/%d", keys, sessions, refresh, wantKeys, wantSessions, wantRefresh)
		}
	}
	t.Run("uncommitted ring is visible only in its request transaction", func(t *testing.T) {
		request, err := st.BeginIdempotency(ctx)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = request.Rollback(context.Background()) })
		requestCtx := request.Context(ctx)
		if _, err := st.InitializeSigningKeys(requestCtx, seed, wrappingKey[:]); err != nil {
			t.Fatal(err)
		}
		issued, err := create(requestCtx)
		if err != nil {
			t.Fatal(err)
		}
		claims, active, err := svc.Introspect(requestCtx, issued.AccessToken, security.DefaultApplicationAudience)
		if err != nil || !active || claims.Subject != user || claims.SessionID != issued.SessionID {
			t.Fatal("introspection did not see its own uncommitted key and session", err)
		}
		_, active, err = svc.Introspect(ctx, issued.AccessToken, security.DefaultApplicationAudience)
		requireUnavailable(t, err)
		if active {
			t.Fatal("uncommitted key was usable outside the request")
		}
		checkStored(t, 0, 0, 0)
		if err := request.Rollback(ctx); err != nil {
			t.Fatal(err)
		}
		checkStored(t, 0, 0, 0)
		_, err = svc.VerifyAccess(ctx, issued.AccessToken)
		requireUnavailable(t, err)
	})
	t.Run("unavailable ring rolls back issuance and permits recovery", func(t *testing.T) {
		failed, err := create(ctx)
		requireUnavailable(t, err)
		if failed != (Tokens{}) {
			t.Fatal("session creation returned credentials without a usable ring")
		}
		checkStored(t, 0, 0, 0)
		if _, err := st.InitializeSigningKeys(ctx, seed, wrappingKey[:]); err != nil {
			t.Fatal(err)
		}
		issued, err := create(ctx)
		if err != nil {
			t.Fatal(err)
		}
		checkStored(t, 1, 1, 1)
		claims, active, err := svc.Introspect(ctx, issued.AccessToken, security.DefaultApplicationAudience)
		if err != nil || !active || claims.Subject != user || claims.SessionID != issued.SessionID {
			t.Fatal("recovered issuer did not create a usable session", err)
		}
		refreshed, err := svc.Refresh(ctx, issued.RefreshToken)
		if err != nil || refreshed.SessionID != issued.SessionID || refreshed.RefreshToken == "" || refreshed.RefreshToken == issued.RefreshToken {
			t.Fatal("recovered session could not rotate its refresh token", err)
		}
	})
}
