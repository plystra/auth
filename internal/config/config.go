package config

import (
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/caarlos0/env/v11"
)

type Config struct {
	HTTPAddr        string        `env:"PLYSTRA_AUTH_HTTP_ADDR" envDefault:":8080"`
	ServerAddr      string        `env:"PLYSTRA_AUTH_SERVER_ADDR" envDefault:":8081"`
	OpsAddr         string        `env:"PLYSTRA_AUTH_OPS_ADDR" envDefault:"127.0.0.1:8082"`
	DatabaseURL     string        `env:"PLYSTRA_AUTH_DATABASE_URL,required"`
	Issuer          string        `env:"PLYSTRA_AUTH_ISSUER,required"`
	SessionHMACKeys string        `env:"PLYSTRA_AUTH_SESSION_HMAC_KEYS,required"`
	DataKey         string        `env:"PLYSTRA_AUTH_DATA_KEY,required"`
	SigningKeyFile  string        `env:"PLYSTRA_AUTH_SIGNING_KEY_FILE"`
	ShutdownTimeout time.Duration `env:"PLYSTRA_AUTH_SHUTDOWN_TIMEOUT" envDefault:"10s"`
	Environment     string        `env:"PLYSTRA_AUTH_ENVIRONMENT" envDefault:"development"`
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
	if strings.TrimSpace(c.DatabaseURL) == "" || strings.TrimSpace(c.Issuer) == "" {
		return errors.New("database URL and issuer are required")
	}
	keys := strings.Split(c.SessionHMACKeys, ",")
	if len(keys) == 0 {
		return errors.New("at least one session HMAC key is required")
	}
	for i, key := range keys {
		if len([]byte(strings.TrimSpace(key))) < 32 {
			return fmt.Errorf("session HMAC key %d must be at least 32 bytes", i+1)
		}
	}
	data, err := base64.StdEncoding.DecodeString(c.DataKey)
	if err != nil || len(data) != 32 {
		return errors.New("data key must be base64 encoded 32 bytes")
	}
	if c.ShutdownTimeout <= 0 {
		return errors.New("shutdown timeout must be positive")
	}
	if strings.EqualFold(c.Environment, "production") && strings.TrimSpace(c.SigningKeyFile) == "" {
		return errors.New("signing key file is required in production")
	}
	return nil
}
