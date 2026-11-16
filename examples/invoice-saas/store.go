package invoicesaas

import (
	"context"
	"database/sql"
	"embed"
	"errors"
	"io/fs"

	"github.com/jackc/pgx/v5/pgxpool"
	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/plystra/auth/examples/invoice-saas/internal/db"
	"github.com/pressly/goose/v3"
)

//go:embed migrations/*.sql
var migrations embed.FS

func Migrate(ctx context.Context, databaseURL string) error {
	conn, err := sql.Open("pgx", databaseURL)
	if err != nil {
		return errors.New("cannot open the Invoice SaaS migration database")
	}
	defer func() { _ = conn.Close() }()
	source, err := fs.Sub(migrations, "migrations")
	if err != nil {
		return errors.New("cannot load Invoice SaaS migrations")
	}
	provider, err := goose.NewProvider(goose.DialectPostgres, conn, source, goose.WithTableName("invoice_saas_migrations"))
	if err != nil {
		return errors.New("cannot initialize Invoice SaaS migrations")
	}
	if _, err := provider.Up(ctx); err != nil {
		return errors.New("cannot migrate the Invoice SaaS database")
	}
	return nil
}

type Store struct {
	pool    *pgxpool.Pool
	queries *db.Queries
}

func OpenStore(ctx context.Context, databaseURL string) (*Store, error) {
	pool, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		return nil, errors.New("cannot configure the Invoice SaaS database")
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, errors.New("cannot connect to the Invoice SaaS database")
	}
	return &Store{pool: pool, queries: db.New(pool)}, nil
}

func (s *Store) Close() { s.pool.Close() }

func (s *Store) Seed(ctx context.Context, id, spaceID, groupID string, amountCents int64, currency string) error {
	_, err := s.queries.CreateInvoice(ctx, db.CreateInvoiceParams{
		ID: id, SpaceID: spaceID, GroupID: groupID, AmountCents: amountCents, Currency: currency,
	})
	if err != nil {
		return errors.New("cannot seed the invoice; check its fields and use a new invoice ID")
	}
	return nil
}
