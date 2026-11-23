package store_test

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/plystra/auth/internal/security"
	"github.com/plystra/auth/internal/store"
)

func TestSigningKeyBootstrapIsSharedAndFailsClosed(t *testing.T) {
	ctx := t.Context()
	database, err := rateLimitDB.Clone(ctx)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = database.Close(context.Background()) })
	app, err := store.Open(ctx, database.AppURL)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(app.Close)
	const issuer = "https://issuer.example.test"
	wrappingKey := bytes.Repeat([]byte{11}, 32)
	makeSeed := func(issuer string) *security.Signer {
		t.Helper()
		signer, err := security.GenerateSigner(issuer)
		if err != nil {
			t.Fatal(err)
		}
		return signer
	}
	seed1, seed2 := makeSeed(issuer), makeSeed(issuer)
	type result struct {
		signer *security.Signer
		err    error
	}
	start := make(chan struct{})
	results := make(chan result, 2)
	for _, seed := range []*security.Signer{seed1, seed2} {
		go func() {
			<-start
			signer, err := app.InitializeSigningKeys(ctx, seed, wrappingKey)
			results <- result{signer, err}
		}()
	}
	close(start)
	first, second := <-results, <-results
	if first.err != nil || second.err != nil {
		t.Fatalf("concurrent startup failed: %v, %v", first.err, second.err)
	}
	now := time.Now()
	raw, err := first.signer.Sign(security.Claims{
		Issuer: issuer, Subject: "usr_key_bootstrap", Audience: "app_key_bootstrap",
		IssuedAt: now.Unix(), ExpiresAt: now.Add(time.Minute).Unix(), Type: "user",
	})
	if err != nil {
		t.Fatal("sign using the persisted key", err)
	}
	assertVerifies := func(signer *security.Signer) {
		t.Helper()
		claims, err := signer.Verify(raw, now, "app_key_bootstrap")
		if err != nil || claims.Subject != "usr_key_bootstrap" {
			t.Fatal("issuer could not verify the original token")
		}
	}
	assertVerifies(second.signer)
	restarted, err := app.InitializeSigningKeys(ctx, makeSeed(issuer), wrappingKey)
	if err != nil {
		t.Fatal("reload persisted key", err)
	}
	assertVerifies(restarted)
	rows, err := app.Queries().ListSigningKeys(ctx)
	if err != nil || len(rows) != 1 || rows[0].Status != "active" {
		t.Fatal("expected exactly one persisted active key")
	}

	if _, err := app.InitializeSigningKeys(ctx, seed1, bytes.Repeat([]byte{22}, 32)); err == nil {
		t.Fatal("wrong encryption key was accepted")
	}
	if _, err := app.InitializeSigningKeys(ctx, makeSeed("https://other.example.test"), wrappingKey); err == nil {
		t.Fatal("a different issuer was accepted")
	}
	for _, statement := range []string{
		"UPDATE signing_keys SET status = 'retiring'",
		"DELETE FROM signing_keys",
		`INSERT INTO signing_keys (kid, issuer, private_key_ciphertext, status)
			SELECT '0000000000000000', issuer, private_key_ciphertext, 'retiring' FROM signing_keys`,
	} {
		_, err := app.Pool.Exec(ctx, statement)
		var pgErr *pgconn.PgError
		if !errors.As(err, &pgErr) || pgErr.Code != "42501" {
			t.Fatal("the application role was able to modify existing signing key state")
		}
	}
	owner, err := store.Open(ctx, database.OwnerURL)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(owner.Close)
	if _, err := owner.Pool.Exec(ctx, "UPDATE signing_keys SET private_key_ciphertext = set_byte(private_key_ciphertext, 0, (get_byte(private_key_ciphertext, 0) + 1) % 256)"); err != nil {
		t.Fatal("alter disposable stored key", err)
	}
	if _, err := app.InitializeSigningKeys(ctx, seed1, wrappingKey); err == nil {
		t.Fatal("corrupt key was ignored by falling back to the local seed")
	}
}
