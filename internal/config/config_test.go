package config

import (
	"encoding/base64"
	"strings"
	"testing"
)

func TestLoadRejectsEveryRequiredSettingWithItsName(t *testing.T) {
	validKey := strings.Repeat("k", 32)
	validDataKey := base64.StdEncoding.EncodeToString([]byte(strings.Repeat("d", 32)))
	validSigningKeyEncryptionKey := base64.StdEncoding.EncodeToString([]byte(strings.Repeat("e", 32)))
	for _, missing := range []string{
		"PLYSTRA_AUTH_DATABASE_URL",
		"PLYSTRA_AUTH_MIGRATION_DATABASE_URL",
		"PLYSTRA_AUTH_ISSUER",
		"PLYSTRA_AUTH_SESSION_HMAC_KEYS",
		"PLYSTRA_AUTH_DATA_KEY",
		"PLYSTRA_AUTH_SIGNING_KEY_ENCRYPTION_KEY",
	} {
		t.Run(missing, func(t *testing.T) {
			t.Setenv("PLYSTRA_AUTH_DATABASE_URL", "postgres://localhost/auth")
			t.Setenv("PLYSTRA_AUTH_MIGRATION_DATABASE_URL", "postgres://localhost/auth")
			t.Setenv("PLYSTRA_AUTH_ISSUER", "https://auth.test")
			t.Setenv("PLYSTRA_AUTH_SESSION_HMAC_KEYS", validKey)
			t.Setenv("PLYSTRA_AUTH_DATA_KEY", validDataKey)
			t.Setenv("PLYSTRA_AUTH_SIGNING_KEY_ENCRYPTION_KEY", validSigningKeyEncryptionKey)
			t.Setenv("PLYSTRA_AUTH_ENVIRONMENT", "development")
			t.Setenv(missing, "")

			_, err := Load()
			if err == nil || !strings.Contains(err.Error(), missing) {
				t.Fatalf("Load() error = %v, want missing variable %s", err, missing)
			}
		})
	}
}

func TestLoadRejectsProductionWithoutSigningKeyFile(t *testing.T) {
	t.Setenv("PLYSTRA_AUTH_DATABASE_URL", "postgres://localhost/auth")
	t.Setenv("PLYSTRA_AUTH_MIGRATION_DATABASE_URL", "postgres://localhost/auth")
	t.Setenv("PLYSTRA_AUTH_ISSUER", "https://auth.test")
	t.Setenv("PLYSTRA_AUTH_SESSION_HMAC_KEYS", strings.Repeat("k", 32))
	t.Setenv("PLYSTRA_AUTH_DATA_KEY", base64.StdEncoding.EncodeToString([]byte(strings.Repeat("d", 32))))
	t.Setenv("PLYSTRA_AUTH_SIGNING_KEY_ENCRYPTION_KEY", base64.StdEncoding.EncodeToString([]byte(strings.Repeat("e", 32))))
	t.Setenv("PLYSTRA_AUTH_ENVIRONMENT", "production")
	t.Setenv("PLYSTRA_AUTH_SIGNING_KEY_FILE", "")

	_, err := Load()
	if err == nil || !strings.Contains(err.Error(), "signing key file") {
		t.Fatalf("Load() error = %v, want production signing key error", err)
	}
}

func TestLoadRejectsInvalidSigningKeyEncryptionKey(t *testing.T) {
	t.Setenv("PLYSTRA_AUTH_DATABASE_URL", "postgres://localhost/auth")
	t.Setenv("PLYSTRA_AUTH_MIGRATION_DATABASE_URL", "postgres://localhost/auth")
	t.Setenv("PLYSTRA_AUTH_ISSUER", "https://auth.test")
	t.Setenv("PLYSTRA_AUTH_SESSION_HMAC_KEYS", strings.Repeat("k", 32))
	t.Setenv("PLYSTRA_AUTH_DATA_KEY", base64.StdEncoding.EncodeToString([]byte(strings.Repeat("d", 32))))
	t.Setenv("PLYSTRA_AUTH_SIGNING_KEY_ENCRYPTION_KEY", base64.StdEncoding.EncodeToString([]byte("too-short")))

	_, err := Load()
	if err == nil || !strings.Contains(err.Error(), "signing key encryption key") {
		t.Fatalf("Load() error = %v, want signing key encryption key validation", err)
	}
}

func TestLoadRejectsProductionWhenDatabaseRolesMatch(t *testing.T) {
	t.Setenv("PLYSTRA_AUTH_DATABASE_URL", "postgres://app:secret@localhost/auth")
	t.Setenv("PLYSTRA_AUTH_MIGRATION_DATABASE_URL", "postgres://app:secret@localhost/auth")
	t.Setenv("PLYSTRA_AUTH_ISSUER", "https://auth.test")
	t.Setenv("PLYSTRA_AUTH_SESSION_HMAC_KEYS", strings.Repeat("k", 32))
	t.Setenv("PLYSTRA_AUTH_DATA_KEY", base64.StdEncoding.EncodeToString([]byte(strings.Repeat("d", 32))))
	t.Setenv("PLYSTRA_AUTH_SIGNING_KEY_ENCRYPTION_KEY", base64.StdEncoding.EncodeToString([]byte(strings.Repeat("e", 32))))
	t.Setenv("PLYSTRA_AUTH_ENVIRONMENT", "production")
	t.Setenv("PLYSTRA_AUTH_SIGNING_KEY_FILE", "encrypted.pem")

	_, err := Load()
	if err == nil || !strings.Contains(err.Error(), "distinct application and migration roles") {
		t.Fatalf("Load() error = %v, want distinct database role validation", err)
	}
}

func TestLoadUsesConfiguredAgentDelegationDepth(t *testing.T) {
	t.Setenv("PLYSTRA_AUTH_DATABASE_URL", "postgres://localhost/auth")
	t.Setenv("PLYSTRA_AUTH_MIGRATION_DATABASE_URL", "postgres://localhost/auth")
	t.Setenv("PLYSTRA_AUTH_ISSUER", "https://auth.test")
	t.Setenv("PLYSTRA_AUTH_SESSION_HMAC_KEYS", strings.Repeat("k", 32))
	t.Setenv("PLYSTRA_AUTH_DATA_KEY", base64.StdEncoding.EncodeToString([]byte(strings.Repeat("d", 32))))
	t.Setenv("PLYSTRA_AUTH_SIGNING_KEY_ENCRYPTION_KEY", base64.StdEncoding.EncodeToString([]byte(strings.Repeat("e", 32))))
	t.Setenv("PLYSTRA_AUTH_AGENT_DELEGATION_MAX_DEPTH", "12")

	c, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if c.AgentDelegationMaxDepth != 12 {
		t.Fatalf("agent delegation max depth = %d, want 12", c.AgentDelegationMaxDepth)
	}
}

func TestLoadRejectsUnsafeAgentDelegationDepth(t *testing.T) {
	t.Setenv("PLYSTRA_AUTH_DATABASE_URL", "postgres://localhost/auth")
	t.Setenv("PLYSTRA_AUTH_MIGRATION_DATABASE_URL", "postgres://localhost/auth")
	t.Setenv("PLYSTRA_AUTH_ISSUER", "https://auth.test")
	t.Setenv("PLYSTRA_AUTH_SESSION_HMAC_KEYS", strings.Repeat("k", 32))
	t.Setenv("PLYSTRA_AUTH_DATA_KEY", base64.StdEncoding.EncodeToString([]byte(strings.Repeat("d", 32))))
	t.Setenv("PLYSTRA_AUTH_SIGNING_KEY_ENCRYPTION_KEY", base64.StdEncoding.EncodeToString([]byte(strings.Repeat("e", 32))))
	t.Setenv("PLYSTRA_AUTH_AGENT_DELEGATION_MAX_DEPTH", "65")

	_, err := Load()
	if err == nil || !strings.Contains(err.Error(), "agent delegation max depth") {
		t.Fatalf("Load() error = %v, want delegation depth validation", err)
	}
}
