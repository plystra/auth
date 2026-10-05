package store

import (
	"context"
	"database/sql"
	"embed"
	"fmt"
	"io/fs"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/plystra/auth/internal/db"
	"github.com/pressly/goose/v3"
)

//go:embed migrations/*.sql
var migrationFS embed.FS

type Store struct{ Pool *pgxpool.Pool }

func Open(ctx context.Context, databaseURL string) (*Store, error) {
	cfg, err := pgxpool.ParseConfig(databaseURL)
	if err != nil {
		return nil, fmt.Errorf("database config: %w", err)
	}
	cfg.MaxConnLifetime = 30 * time.Minute
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
	// The store is the single permitted transaction boundary.
	tx, err := s.Pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted}) //nolint:forbidigo
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
	sub, err := fs.Sub(migrationFS, "migrations")
	if err != nil {
		return err
	}
	provider, err := goose.NewProvider(goose.DialectPostgres, dbsql, sub)
	if err != nil {
		return err
	}
	_, err = provider.Up(ctx)
	return err
}
