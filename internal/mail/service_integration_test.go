package mail

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/plystra/auth/internal/db"
	"github.com/plystra/auth/internal/secret"
	"github.com/plystra/auth/internal/store"
	"github.com/plystra/auth/internal/testdb"
)

type sentMessage struct{ to, subject, body string }

type captureSender struct{ sent chan sentMessage }

func (s *captureSender) Send(_ context.Context, to, subject, body string) error {
	s.sent <- sentMessage{to: to, subject: subject, body: body}
	return nil
}

var mailDB *testdb.Harness

func TestMain(m *testing.M) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	var err error
	mailDB, err = testdb.Start(ctx)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	code := m.Run()
	if err := mailDB.Close(context.Background()); err != nil && code == 0 {
		fmt.Fprintln(os.Stderr, err)
		code = 1
	}
	os.Exit(code)
}

func TestVerificationMailIsEncryptedInRiverAndDelivered(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	database, err := mailDB.Clone(ctx)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = database.Close(context.Background()) })
	st, err := store.Open(ctx, database.AppURL)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(st.Close)
	sender := &captureSender{sent: make(chan sentMessage, 1)}
	svc, err := New(secret.New(strings.Repeat("d", 32)), st.Jobs, sender)
	if err != nil {
		t.Fatal(err)
	}
	const token = "ev_private-verification-token"
	if err := st.InTx(ctx, func(q *db.Queries) error {
		return svc.EnqueueVerificationTx(ctx, q, "recipient@example.test", secret.New(token), time.Now().Add(time.Hour))
	}); err != nil {
		t.Fatal(err)
	}
	var args []byte
	if err := st.Pool.QueryRow(ctx, `SELECT args FROM river_job WHERE kind = 'email_delivery'`).Scan(&args); err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(args, []byte(token)) || bytes.Contains(args, []byte("recipient@example.test")) {
		t.Fatal("River job stored verification material in plaintext")
	}
	var payload struct {
		Ciphertext []byte `json:"ciphertext"`
	}
	if err := json.Unmarshal(args, &payload); err != nil {
		t.Fatal(err)
	}
	if len(payload.Ciphertext) < 32 {
		t.Fatal("River job did not contain encrypted delivery material")
	}
	if err := st.Jobs.RegisterEmailDelivery(svc); err != nil {
		t.Fatal(err)
	}
	if err := st.Jobs.Start(ctx); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Jobs.Stop(context.Background()) })
	select {
	case got := <-sender.sent:
		if got.to != "recipient@example.test" || got.subject != "Verify your Plystra Auth email" || !strings.Contains(got.body, token) {
			t.Fatal("email delivery did not send the intended verification token")
		}
	case <-ctx.Done():
		t.Fatal("River did not deliver the verification email")
	}
	tampered := append([]byte(nil), payload.Ciphertext...)
	tampered[len(tampered)-1] ^= 1
	if err := svc.DeliverEmail(ctx, tampered); err == nil {
		t.Fatal("tampered delivery payload was accepted")
	}
}

func TestVerificationMailJobRollsBackWithBusinessTransaction(t *testing.T) {
	ctx := context.Background()
	database, err := mailDB.Clone(ctx)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = database.Close(context.Background()) })
	st, err := store.Open(ctx, database.AppURL)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(st.Close)
	svc, err := New(secret.New(strings.Repeat("d", 32)), st.Jobs, &captureSender{sent: make(chan sentMessage, 1)})
	if err != nil {
		t.Fatal(err)
	}
	err = st.InTx(ctx, func(q *db.Queries) error {
		if err := svc.EnqueueVerificationTx(ctx, q, "recipient@example.test", secret.New("ev_rollback"), time.Now().Add(time.Hour)); err != nil {
			return err
		}
		return errors.New("business transaction rejected")
	})
	if err == nil {
		t.Fatal("business transaction unexpectedly committed")
	}
	var count int
	if err := st.Pool.QueryRow(ctx, `SELECT count(*) FROM river_job WHERE kind = 'email_delivery'`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatal("email job survived business transaction rollback")
	}
}

func TestPasswordResetMailIsEncryptedAndDelivered(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	database, err := mailDB.Clone(ctx)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = database.Close(context.Background()) })
	st, err := store.Open(ctx, database.AppURL)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(st.Close)
	sender := &captureSender{sent: make(chan sentMessage, 1)}
	svc, err := New(secret.New(strings.Repeat("d", 32)), st.Jobs, sender)
	if err != nil {
		t.Fatal(err)
	}
	const token = "pr_private-reset-token"
	if err := st.InTx(ctx, func(q *db.Queries) error {
		return svc.EnqueuePasswordResetTx(ctx, q, "recipient@example.test", secret.New(token), time.Now().Add(time.Hour))
	}); err != nil {
		t.Fatal(err)
	}
	var args []byte
	if err := st.Pool.QueryRow(ctx, `SELECT args FROM river_job WHERE kind = 'email_delivery'`).Scan(&args); err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(args, []byte(token)) || bytes.Contains(args, []byte("recipient@example.test")) {
		t.Fatal("River job stored reset material in plaintext")
	}
	if err := st.Jobs.RegisterEmailDelivery(svc); err != nil {
		t.Fatal(err)
	}
	if err := st.Jobs.Start(ctx); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Jobs.Stop(context.Background()) })
	select {
	case got := <-sender.sent:
		if got.to != "recipient@example.test" || got.subject != "Reset your Plystra Auth password" || !strings.Contains(got.body, token) {
			t.Fatal("password reset delivery did not send the intended token")
		}
	case <-ctx.Done():
		t.Fatal("River did not deliver the password reset email")
	}
}
