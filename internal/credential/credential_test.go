package credential

import (
	"context"
	"strings"
	"testing"
)

func TestIndependentPlaneParsersRejectCrossPlaneCredentialPrefixes(t *testing.T) {
	tests := []struct {
		name  string
		parse func(context.Context, string) error
		raw   string
	}{
		{name: "principal application key", parse: (PrincipalParser{}).Parse, raw: "Bearer ply_sk_prefix.secret"},
		{name: "principal operator session", parse: (PrincipalParser{}).Parse, raw: "Bearer ply_ops_secret"},
		{name: "server agent key", parse: (ServerParser{}).Parse, raw: "Bearer ply_ag_prefix.secret"},
		{name: "ops application key", parse: (OpsParser{}).Parse, raw: "Bearer ply_sk_prefix.secret"},
		{name: "ops agent key", parse: (OpsParser{}).Parse, raw: "Bearer ply_ag_prefix.secret"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := test.parse(context.Background(), test.raw)
			if err == nil || !strings.Contains(err.Error(), "CREDENTIAL_PLANE_MISMATCH") {
				t.Fatalf("parse(%q) = %v, want CREDENTIAL_PLANE_MISMATCH", test.raw, err)
			}
		})
	}
}

func TestCredentialKindNeverReturnsSecret(t *testing.T) {
	value := "Bearer ply_sk_prefix.secret-value"
	if got := Kind(value); got != "application_api_key" {
		t.Fatalf("Kind() = %q, want application_api_key", got)
	}
	if strings.Contains(Kind(value), "secret-value") {
		t.Fatal("credential kind contains secret material")
	}
}
