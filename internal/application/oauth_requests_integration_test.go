package application

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"testing"
	"time"

	"github.com/plystra/auth/internal/db"
	"github.com/plystra/auth/internal/secret"
)

func TestOAuthAuthorizationRequestIsHashedExpiringAndSingleUse(t *testing.T) {
	ctx := context.Background()
	st := newKeyStore(t)
	svc := &Service{Store: st}
	input := OAuthAuthorizationRequestInput{
		ApplicationID: "app_key_test", RedirectURI: "https://client.example.test/callback",
		CodeChallenge: "s256-challenge", Scopes: []string{"invoice:read"},
		State: "opaque-state", Nonce: "opaque-nonce", Resource: "app_key_test",
	}
	handle, expiresAt, err := svc.CreateOAuthAuthorizationRequest(ctx, input)
	if err != nil {
		t.Fatal(err)
	}
	if !expiresAt.After(time.Now().Add(4*time.Minute)) || expiresAt.After(time.Now().Add(5*time.Minute)) {
		t.Fatalf("authorization request expiry = %s, want within five minutes", expiresAt)
	}
	var storedHash []byte
	var id string
	if err := st.Pool.QueryRow(ctx, `SELECT id, request_hash FROM oauth_authorization_requests WHERE application_id = $1`, input.ApplicationID).Scan(&id, &storedHash); err != nil {
		t.Fatal(err)
	}
	wantHash := sha256.Sum256([]byte(handle.Value()))
	if !bytes.Equal(storedHash, wantHash[:]) || bytes.Contains(storedHash, []byte(handle.Value())) || len(id) < 4 || id[:4] != "arq_" {
		t.Fatal("authorization request was not stored with a typed internal ID and hashed public handle")
	}
	if _, err := st.Pool.Exec(ctx, `INSERT INTO oauth_authorization_requests
		(id, request_hash, application_id, redirect_uri, code_challenge, scope, state, nonce, resource, expires_at)
		VALUES ('wrong_prefix', $1, $2, $3, $4, 'invoice:read', 'state', 'nonce', $5, now() + interval '5 minutes')`,
		wantHash[:], input.ApplicationID, input.RedirectURI, input.CodeChallenge, input.Resource); err == nil {
		t.Fatal("authorization request table accepted an invalid ID prefix")
	}
	rollback := errors.New("rollback test")
	if err := st.InTx(ctx, func(q *db.Queries) error {
		request, err := svc.LockOAuthAuthorizationRequestTx(ctx, q, handle)
		if err != nil || request.ApplicationID != input.ApplicationID || request.RedirectURI != input.RedirectURI || len(request.Scopes) != 1 || request.Scopes[0] != "invoice:read" {
			t.Fatalf("locked authorization request = %+v err=%v", request, err)
		}
		if err := svc.FinishOAuthAuthorizationRequestTx(ctx, q, request.ID, "approved"); err != nil {
			return err
		}
		return rollback
	}); !errors.Is(err, rollback) {
		t.Fatalf("rollback test = %v", err)
	}
	if err := st.InTx(ctx, func(q *db.Queries) error {
		request, err := svc.LockOAuthAuthorizationRequestTx(ctx, q, handle)
		if err != nil {
			return err
		}
		return svc.FinishOAuthAuthorizationRequestTx(ctx, q, request.ID, "approved")
	}); err != nil {
		t.Fatalf("consuming request after rollback: %v", err)
	}
	if err := st.InTx(ctx, func(q *db.Queries) error {
		_, err := svc.LockOAuthAuthorizationRequestTx(ctx, q, handle)
		return err
	}); err == nil {
		t.Fatal("consumed authorization request could be reused")
	}
	if err := st.InTx(ctx, func(q *db.Queries) error {
		_, err := svc.LockOAuthAuthorizationRequestTx(ctx, q, secret.New("wrong_prefix"))
		return err
	}); err == nil {
		t.Fatal("invalid authorization request handle was accepted")
	}
	expiredHandle, _, err := svc.CreateOAuthAuthorizationRequest(ctx, input)
	if err != nil {
		t.Fatal(err)
	}
	expiredHash := sha256.Sum256([]byte(expiredHandle.Value()))
	if _, err := st.Pool.Exec(ctx, `UPDATE oauth_authorization_requests SET expires_at = now() - interval '1 second' WHERE request_hash = $1`, expiredHash[:]); err != nil {
		t.Fatal(err)
	}
	if err := st.InTx(ctx, func(q *db.Queries) error {
		_, err := svc.LockOAuthAuthorizationRequestTx(ctx, q, expiredHandle)
		return err
	}); err == nil {
		t.Fatal("expired authorization request was accepted")
	}
}
