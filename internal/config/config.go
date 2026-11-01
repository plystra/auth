package config

import (
	"encoding/base64"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/caarlos0/env/v11"
)

type Config struct {
	HTTPAddr                string        `env:"PLYSTRA_AUTH_HTTP_ADDR" envDefault:":8080"`
	ServerAddr              string        `env:"PLYSTRA_AUTH_SERVER_ADDR" envDefault:":8081"`
	OpsAddr                 string        `env:"PLYSTRA_AUTH_OPS_ADDR" envDefault:"127.0.0.1:8082"`
	DatabaseURL             string        `env:"PLYSTRA_AUTH_DATABASE_URL,required"`
	MigrationDatabaseURL    string        `env:"PLYSTRA_AUTH_MIGRATION_DATABASE_URL,required"`
	Issuer                  string        `env:"PLYSTRA_AUTH_ISSUER,required"`
	SessionHMACKeys         string        `env:"PLYSTRA_AUTH_SESSION_HMAC_KEYS,required"`
	DataKey                 string        `env:"PLYSTRA_AUTH_DATA_KEY,required"`
	SigningKeyFile          string        `env:"PLYSTRA_AUTH_SIGNING_KEY_FILE"`
	SigningKeyEncryptionKey string        `env:"PLYSTRA_AUTH_SIGNING_KEY_ENCRYPTION_KEY,required"`
	SMTPHost                string        `env:"PLYSTRA_AUTH_SMTP_HOST"`
	SMTPPort                int           `env:"PLYSTRA_AUTH_SMTP_PORT" envDefault:"587"`
	SMTPFrom                string        `env:"PLYSTRA_AUTH_SMTP_FROM"`
	SMTPUsername            string        `env:"PLYSTRA_AUTH_SMTP_USERNAME"`
	SMTPPassword            string        `env:"PLYSTRA_AUTH_SMTP_PASSWORD"`
	AgentDelegationMaxDepth int           `env:"PLYSTRA_AUTH_AGENT_DELEGATION_MAX_DEPTH" envDefault:"8"`
	ShutdownTimeout         time.Duration `env:"PLYSTRA_AUTH_SHUTDOWN_TIMEOUT" envDefault:"10s"`
	Environment             string        `env:"PLYSTRA_AUTH_ENVIRONMENT" envDefault:"development"`
}

func Load() (Config, error) {
	var c Config
	if err := env.Parse(&c); err != nil {
		return Config{}, fmt.Errorf("config: %w", err)
	}
	if err := c.Validate(); err != nil {
		return Config{}, err
	}
	return c, nil
}

func (c Config) Validate() error {
	if strings.TrimSpace(c.DatabaseURL) == "" {
		return errors.New("PLYSTRA_AUTH_DATABASE_URL is required")
	}
	if strings.TrimSpace(c.MigrationDatabaseURL) == "" {
		return errors.New("PLYSTRA_AUTH_MIGRATION_DATABASE_URL is required")
	}
	if strings.TrimSpace(c.Issuer) == "" {
		return errors.New("PLYSTRA_AUTH_ISSUER is required")
	}
	if strings.TrimSpace(c.SessionHMACKeys) == "" {
		return errors.New("PLYSTRA_AUTH_SESSION_HMAC_KEYS is required")
	}
	if strings.TrimSpace(c.DataKey) == "" {
		return errors.New("PLYSTRA_AUTH_DATA_KEY is required")
	}
	if strings.TrimSpace(c.SigningKeyEncryptionKey) == "" {
		return errors.New("PLYSTRA_AUTH_SIGNING_KEY_ENCRYPTION_KEY is required")
	}
	keys := strings.Split(c.SessionHMACKeys, ",")
	for i, key := range keys {
		if len([]byte(strings.TrimSpace(key))) < 32 {
			return fmt.Errorf("session HMAC key %d must be at least 32 bytes", i+1)
		}
	}
	data, err := base64.StdEncoding.DecodeString(c.DataKey)
	if err != nil || len(data) != 32 {
		return errors.New("data key must be base64 encoded 32 bytes")
	}
	signingKeyEncryptionKey, err := base64.StdEncoding.DecodeString(strings.TrimSpace(c.SigningKeyEncryptionKey))
	if err != nil || len(signingKeyEncryptionKey) != 32 {
		return errors.New("signing key encryption key must be base64 encoded 32 bytes")
	}
	if c.ShutdownTimeout <= 0 {
		return errors.New("shutdown timeout must be positive")
	}
	if c.AgentDelegationMaxDepth < 1 || c.AgentDelegationMaxDepth > 64 {
		return errors.New("agent delegation max depth must be between 1 and 64")
	}
	if c.SMTPPort < 1 || c.SMTPPort > 65535 {
		return errors.New("PLYSTRA_AUTH_SMTP_PORT must be between 1 and 65535")
	}
	if (c.SMTPHost == "") != (c.SMTPFrom == "") || (c.SMTPUsername == "") != (c.SMTPPassword == "") {
		return errors.New("SMTP host/from and username/password must be configured together")
	}
	if strings.EqualFold(c.Environment, "production") && strings.TrimSpace(c.SigningKeyFile) == "" {
		return errors.New("signing key file is required in production")
	}
	if strings.EqualFold(c.Environment, "production") {
		applicationURL, applicationErr := url.Parse(c.DatabaseURL)
		migrationURL, migrationErr := url.Parse(c.MigrationDatabaseURL)
		if applicationErr != nil || migrationErr != nil || applicationURL.User == nil || migrationURL.User == nil {
			return errors.New("production database URLs must identify distinct application and migration roles")
		}
		if applicationURL.User.Username() == migrationURL.User.Username() {
			return errors.New("production database URLs must use distinct application and migration roles")
		}
		if c.SMTPHost == "" {
			return errors.New("PLYSTRA_AUTH_SMTP_HOST and PLYSTRA_AUTH_SMTP_FROM are required in production")
		}
	}
	return nil
}
