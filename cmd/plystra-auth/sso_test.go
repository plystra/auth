package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/plystra/auth/internal/enterprise"
	"github.com/plystra/auth/internal/store"
	"github.com/plystra/auth/internal/testdb"
)

func TestSAMLSigningTrustCLIAlertsAndClearsAfterRenewal(t *testing.T) {
	ctx := t.Context()
	harness, err := testdb.Start(ctx)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = harness.Close(context.Background()) })
	database, err := harness.Clone(ctx)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = database.Close(context.Background()) })
	st, err := store.Open(ctx, database.AppURL)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(st.Close)
	t.Setenv("PLYSTRA_AUTH_DATABASE_URL", database.AppURL)
	t.Setenv("PLYSTRA_AUTH_DATA_KEY", "")
	t.Setenv("PLYSTRA_AUTH_SESSION_HMAC_KEYS", "")
	if _, err := st.Pool.Exec(ctx, `INSERT INTO spaces (id,name,slug) VALUES ('spc_certificates','Certificates','certificates')`); err != nil {
		t.Fatal(err)
	}
	add := func(id, provider, status, cert string) {
		t.Helper()
		if _, err := st.Pool.Exec(ctx, `INSERT INTO sso_connections
			(id, space_id, name, provider, status, issuer, client_id, redirect_uri, saml_idp_certificate)
			VALUES ($1, 'spc_certificates', $1, $2, $3, 'https://idp.fixture.test', 'fixture', 'https://auth.fixture.test/callback', $4)`,
			id, provider, status, cert); err != nil {
			t.Fatal(err)
		}
	}
	now := time.Now().UTC().Truncate(time.Second)
	testCert := func(serial int64, from, to time.Duration) string {
		t.Helper()
		pub, key, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		cert := &x509.Certificate{SerialNumber: big.NewInt(serial), NotBefore: now.Add(from), NotAfter: now.Add(to)}
		der, err := x509.CreateCertificate(rand.Reader, cert, cert, pub, key)
		if err != nil {
			t.Fatal(err)
		}
		return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	}
	old := testCert(1, -time.Hour, 24*time.Hour)
	overlap := testCert(2, 12*time.Hour, 1440*time.Hour)
	gap := testCert(3, 48*time.Hour, 1440*time.Hour)
	expired := testCert(4, -48*time.Hour, -time.Hour)
	healthy := overlap + expired + old
	for i := range 32 {
		add(fmt.Sprintf("con_a%02d", i), "saml", "active", healthy)
	}
	add("con_ignored_disabled", "saml", "disabled", expired)
	add("con_ignored_oidc", "oidc", "active", "not a SAML certificate")

	binary := filepath.Join(t.TempDir(), "plystra-auth.exe")
	build := exec.CommandContext(ctx, "go", "build", "-buildvcs=false", "-o", binary, ".")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build certificate check CLI: %v\n%s", err, out)
	}
	run := func(wantExit int, args ...string) enterprise.SAMLTrustReport {
		t.Helper()
		cmd := exec.CommandContext(ctx, binary, append([]string{"sso", "check-saml-certificates"}, args...)...)
		var diagnostics bytes.Buffer
		cmd.Stderr = &diagnostics
		output, err := cmd.Output()
		exit := 0
		if err != nil {
			var status *exec.ExitError
			if !errors.As(err, &status) {
				t.Fatal(err)
			}
			exit = status.ExitCode()
		}
		if exit != wantExit {
			t.Fatalf("certificate check exit = %d, want %d", exit, wantExit)
		}
		var report enterprise.SAMLTrustReport
		if wantExit == 1 {
			if len(output) != 0 {
				t.Fatal("failed check published a report")
			}
			return report
		}
		if err := json.Unmarshal(output, &report); err != nil ||
			diagnostics.Len() != 0 || strings.Contains(string(output), "CERTIFICATE") ||
			strings.Contains(string(output), "fixture.test") {
			t.Fatal("certificate check did not produce a sanitized JSON report")
		}
		return report
	}
	if report := run(0); report.CheckedConnections != 32 || report.Issues == nil ||
		len(report.Issues) != 0 || report.WarningUntil.Sub(report.CheckedAt) != 720*time.Hour {
		t.Fatalf("unexpected healthy report: %+v", report)
	}
	add("con_gap", "saml", "active", gap+old)
	add("con_missing", "saml", "active", expired+gap)
	add("con_unreadable", "saml", "active", "unreadable")
	report := run(2)
	until := now.Add(24 * time.Hour)
	want := []enterprise.SAMLTrustIssue{
		{ConnectionID: "con_gap", SpaceID: "spc_certificates", Status: "coverage_ending", CoverageUntil: &until},
		{ConnectionID: "con_missing", SpaceID: "spc_certificates", Status: "no_current_signer"},
		{ConnectionID: "con_unreadable", SpaceID: "spc_certificates", Status: "invalid_trust"},
	}
	if report.CheckedConnections != 35 || !reflect.DeepEqual(report.Issues, want) {
		t.Fatalf("unexpected expiry report: %+v", report)
	}
	if _, err := st.Pool.Exec(ctx, `UPDATE sso_connections SET saml_idp_certificate = $1
		WHERE id IN ('con_gap','con_missing','con_unreadable')`, healthy); err != nil {
		t.Fatal(err)
	}
	if report := run(0, "--within", "48h"); report.CheckedConnections != 35 || len(report.Issues) != 0 {
		t.Fatalf("renewed trust still reports an issue: %+v", report)
	}
	run(1, "--within", "0h")
	t.Setenv("PLYSTRA_AUTH_DATABASE_URL", "")
	run(1)
}
