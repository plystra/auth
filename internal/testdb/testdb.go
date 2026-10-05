package testdb

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"regexp"
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
	template  string
	nextID    atomic.Uint64
}

type Database struct {
	URL      string
	name     string
	adminURL string
}

func Start(ctx context.Context) (*Harness, error) {
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
	templateName := fmt.Sprintf("auth_template_%d", os.Getpid())
	h := &Harness{container: container, adminURL: databaseURL(adminURL, "postgres"), template: templateName}
	if err := h.createDatabase(ctx, templateName, "postgres"); err != nil {
		_ = h.Close(ctx)
		return nil, err
	}
	if err := store.Migrate(ctx, databaseURL(adminURL, templateName)); err != nil {
		_ = h.Close(ctx)
		return nil, fmt.Errorf("migrate postgres template: %w", err)
	}
	return h, nil
}

func (h *Harness) Clone(ctx context.Context) (Database, error) {
	id := h.nextID.Add(1)
	name := fmt.Sprintf("auth_test_%d_%s", id, strconv.Itoa(os.Getpid()))
	if err := h.createDatabase(ctx, name, h.template); err != nil {
		return Database{}, err
	}
	return Database{URL: databaseURL(h.adminURL, name), name: name, adminURL: h.adminURL}, nil
}

func (d Database) Close(ctx context.Context) error {
	if d.name == "" {
		return nil
	}
	conn, err := pgx.Connect(ctx, d.adminURL)
	if err != nil {
		return err
	}
	defer conn.Close(ctx)
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
	defer conn.Close(ctx)
	if !validDatabaseName.MatchString(name) || !validDatabaseName.MatchString(template) {
		return fmt.Errorf("invalid test database name")
	}
	_, err = conn.Exec(ctx, "CREATE DATABASE "+quoteIdentifier(name)+" TEMPLATE "+quoteIdentifier(template))
	if err != nil {
		return fmt.Errorf("create database %s: %w", name, err)
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

func quoteIdentifier(value string) string {
	return `"` + strings.ReplaceAll(value, `"`, `""`) + `"`
}
