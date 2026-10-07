package testdb

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/plystra/auth/internal/store"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
)

const DefaultPostgresImage = "postgres:17-alpine"

var validDatabaseName = regexp.MustCompile(`^[a-z][a-z0-9_]+$`)

type Harness struct {
	container *postgres.PostgresContainer
	adminURL  string
	ownerURL  string
	appURL    string
	template  string
	nextID    atomic.Uint64
}

type Database struct {
	URL      string
	OwnerURL string
	AppURL   string
	name     string
	adminURL string
}

func Start(ctx context.Context) (*Harness, error) {
	ensureDockerHost()
	image := strings.TrimSpace(os.Getenv("PLYSTRA_TEST_POSTGRES_IMAGE"))
	if image == "" {
		image = DefaultPostgresImage
	}
	container, err := postgres.Run(ctx, image,
		postgres.WithDatabase("postgres"),
		postgres.WithUsername("postgres"),
		postgres.WithPassword("postgres"),
	)
	if err != nil {
		return nil, fmt.Errorf("start postgres container: %w", err)
	}
	adminURL, err := container.ConnectionString(ctx, "sslmode=disable")
	if err != nil {
		_ = container.Terminate(ctx)
		return nil, fmt.Errorf("get postgres connection string: %w", err)
	}
	adminURL = databaseURL(adminURL, "postgres")
	if err := createRoles(ctx, adminURL); err != nil {
		_ = container.Terminate(ctx)
		return nil, err
	}
	templateName := fmt.Sprintf("auth_template_%d", os.Getpid())
	ownerURL := roleDatabaseURL(adminURL, "plystra_auth_owner", "test-owner-password")
	appURL := roleDatabaseURL(adminURL, "plystra_auth_app", "test-app-password")
	h := &Harness{container: container, adminURL: adminURL, ownerURL: ownerURL, appURL: appURL, template: templateName}
	if err := h.createDatabase(ctx, templateName, "postgres"); err != nil {
		_ = h.Close(ctx)
		return nil, err
	}
	if err := store.Migrate(ctx, databaseURL(ownerURL, templateName)); err != nil {
		_ = h.Close(ctx)
		return nil, fmt.Errorf("migrate postgres template: %w", err)
	}
	return h, nil
}

// testcontainers-go falls back to probing a rootless socket when Windows has
// no explicit Docker host. Docker Desktop exposes its Linux engine through
// the named pipe below, so select it only for that default case.
func ensureDockerHost() {
	if runtime.GOOS != "windows" || strings.TrimSpace(os.Getenv("DOCKER_HOST")) != "" || strings.TrimSpace(os.Getenv("DOCKER_CONTEXT")) != "" {
		return
	}
	_ = os.Setenv("DOCKER_HOST", "npipe:////./pipe/docker_engine")
}

func (h *Harness) Clone(ctx context.Context) (Database, error) {
	id := h.nextID.Add(1)
	name := fmt.Sprintf("auth_test_%d_%s", id, strconv.Itoa(os.Getpid()))
	if err := h.createDatabase(ctx, name, h.template); err != nil {
		return Database{}, err
	}
	return Database{
		URL:      databaseURL(h.adminURL, name),
		OwnerURL: databaseURL(h.ownerURL, name),
		AppURL:   databaseURL(h.appURL, name),
		name:     name,
		adminURL: h.adminURL,
	}, nil
}

func (d Database) Close(ctx context.Context) error {
	if d.name == "" {
		return nil
	}
	conn, err := pgx.Connect(ctx, d.adminURL)
	if err != nil {
		return err
	}
	defer func() { _ = conn.Close(ctx) }()
	_, err = conn.Exec(ctx, "DROP DATABASE "+quoteIdentifier(d.name))
	return err
}

func (h *Harness) Close(ctx context.Context) error {
	if h == nil {
		return nil
	}
	var firstErr error
	if h.template != "" {
		conn, err := pgx.Connect(ctx, h.adminURL)
		if err != nil {
			firstErr = err
		} else {
			_, dropErr := conn.Exec(ctx, "DROP DATABASE "+quoteIdentifier(h.template))
			_ = conn.Close(ctx)
			if dropErr != nil {
				firstErr = dropErr
			}
		}
	}
	if h.container != nil {
		if err := h.container.Terminate(ctx); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

func (h *Harness) createDatabase(ctx context.Context, name, template string) error {
	var conn *pgx.Conn
	var err error
	for attempt := 0; attempt < 10; attempt++ {
		conn, err = pgx.Connect(ctx, h.adminURL)
		if err == nil {
			break
		}
		if attempt == 9 {
			return fmt.Errorf("connect postgres admin database: %w", err)
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("connect postgres admin database: %w", ctx.Err())
		case <-time.After(500 * time.Millisecond):
		}
	}
	defer func() { _ = conn.Close(ctx) }()
	if !validDatabaseName.MatchString(name) || !validDatabaseName.MatchString(template) {
		return fmt.Errorf("invalid test database name")
	}
	_, err = conn.Exec(ctx, "CREATE DATABASE "+quoteIdentifier(name)+" TEMPLATE "+quoteIdentifier(template))
	if err != nil {
		return fmt.Errorf("create database %s: %w", name, err)
	}
	return nil
}

func createRoles(ctx context.Context, adminURL string) error {
	var conn *pgx.Conn
	var err error
	for attempt := 0; attempt < 10; attempt++ {
		conn, err = pgx.Connect(ctx, adminURL)
		if err == nil {
			break
		}
		if attempt == 9 {
			return fmt.Errorf("connect postgres admin database for roles: %w", err)
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("connect postgres admin database for roles: %w", ctx.Err())
		case <-time.After(500 * time.Millisecond):
		}
	}
	defer func() { _ = conn.Close(ctx) }()
	if _, err := conn.Exec(ctx, `
		DO $$
		BEGIN
			IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'plystra_auth_owner') THEN
				CREATE ROLE plystra_auth_owner LOGIN PASSWORD 'test-owner-password';
			ELSE
				ALTER ROLE plystra_auth_owner LOGIN PASSWORD 'test-owner-password';
			END IF;
			IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'plystra_auth_app') THEN
				CREATE ROLE plystra_auth_app LOGIN PASSWORD 'test-app-password';
			ELSE
				ALTER ROLE plystra_auth_app LOGIN PASSWORD 'test-app-password';
			END IF;
		END
		$$;
		GRANT USAGE, CREATE ON SCHEMA public TO plystra_auth_owner;
	`); err != nil {
		return fmt.Errorf("create postgres test roles: %w", err)
	}
	return nil
}

func databaseURL(raw, name string) string {
	u, err := url.Parse(raw)
	if err != nil {
		panic(err)
	}
	u.Path = "/" + name
	return u.String()
}

func roleDatabaseURL(raw, username, password string) string {
	u, err := url.Parse(raw)
	if err != nil {
		panic(err)
	}
	u.User = url.UserPassword(username, password)
	return u.String()
}

func quoteIdentifier(value string) string {
	return `"` + strings.ReplaceAll(value, `"`, `""`) + `"`
}
