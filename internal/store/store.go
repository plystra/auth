package store

import (
	"context"
	"database/sql"
	"fmt"
	"io/fs"
	"strconv"
	"strings"
	"time"

	"github.com/exaring/otelpgx"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/plystra/auth/internal/db"
	"github.com/plystra/auth/migrations"
	"github.com/pressly/goose/v3"
	"go.opentelemetry.io/otel"
)

type Store struct{ Pool *pgxpool.Pool }

func Open(ctx context.Context, databaseURL string) (*Store, error) {
	cfg, err := pgxpool.ParseConfig(databaseURL)
	if err != nil {
		return nil, fmt.Errorf("database config: %w", err)
	}
	cfg.MaxConnLifetime = 30 * time.Minute
	cfg.ConnConfig.Tracer = otelpgx.NewTracer(
		otelpgx.WithTracerProvider(otel.GetTracerProvider()),
		otelpgx.WithMeterProvider(otel.GetMeterProvider()),
	)
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("database: %w", err)
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("database ping: %w", err)
	}
	return &Store{Pool: pool}, nil
}
func (s *Store) Close() {
	if s != nil && s.Pool != nil {
		s.Pool.Close()
	}
}
func (s *Store) Queries() *db.Queries { return db.New(s.Pool) }
func (s *Store) InTx(ctx context.Context, fn func(*db.Queries) error) error {
	if request := requestTransaction(ctx); request != nil {
		if request.closed {
			return fmt.Errorf("request transaction is closed")
		}
		return request.inTx(ctx, fn)
	}
	// The store is the single permitted transaction boundary.
	tx, err := s.Pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return err
	}
	q := db.New(tx)
	if err := fn(q); err != nil {
		_ = tx.Rollback(ctx)
		return err
	}
	return tx.Commit(ctx)
}
func Migrate(ctx context.Context, databaseURL string) error {
	dbsql, err := sql.Open("pgx", databaseURL)
	if err != nil {
		return err
	}
	defer func() { _ = dbsql.Close() }()
	provider, err := goose.NewProvider(goose.DialectPostgres, dbsql, migrations.FS)
	if err != nil {
		return err
	}
	_, err = provider.Up(ctx)
	return err
}

// CheckMigrationVersion verifies that the database has applied the newest
// forward-only migration embedded in this binary.
func CheckMigrationVersion(ctx context.Context, pool *pgxpool.Pool) error {
	expected, err := LatestMigrationVersion()
	if err != nil {
		return err
	}
	var actual int64
	var applied bool
	if err := pool.QueryRow(ctx, `SELECT version_id, is_applied FROM goose_db_version ORDER BY id DESC LIMIT 1`).Scan(&actual, &applied); err != nil {
		return fmt.Errorf("read migration version: %w", err)
	}
	if !applied || actual != expected {
		return fmt.Errorf("database migration version %d is not current (want %d)", actual, expected)
	}
	return nil
}

func LatestMigrationVersion() (int64, error) {
	entries, err := fs.ReadDir(migrations.FS, ".")
	if err != nil {
		return 0, fmt.Errorf("read embedded migrations: %w", err)
	}
	var latest int64
	for _, entry := range entries {
		name := entry.Name()
		prefix, _, ok := strings.Cut(name, "_")
		if !ok {
			continue
		}
		version, parseErr := strconv.ParseInt(prefix, 10, 64)
		if parseErr != nil {
			return 0, fmt.Errorf("parse migration %q: %w", name, parseErr)
		}
		if version > latest {
			latest = version
		}
	}
	if latest == 0 {
		return 0, fmt.Errorf("no embedded migrations found")
	}
	return latest, nil
}
