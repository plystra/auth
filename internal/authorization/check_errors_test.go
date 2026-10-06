package authorization

import (
	"context"
	"errors"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/plystra/auth/internal/db"
)

type failingAuthorizationDB struct {
	db.DBTX
	err error
}

func (f failingAuthorizationDB) QueryRow(context.Context, string, ...interface{}) pgx.Row {
	return failingAuthorizationRow{err: f.err}
}

type failingAuthorizationRow struct{ err error }

func (r failingAuthorizationRow) Scan(...interface{}) error { return r.err }

func TestOwnerFactQueryPropagatesDatabaseFailures(t *testing.T) {
	service := &Service{}
	failed := errors.New("owner query failed")
	request, err := service.ownerRequestQueries(context.Background(), db.New(failingAuthorizationDB{err: failed}), "mem_owner", CheckRequest{}, 0)
	if request != nil || !errors.Is(err, failed) {
		t.Fatalf("owner request = %v, %v; want database failure", request, err)
	}
	request, err = service.ownerRequestQueries(context.Background(), db.New(failingAuthorizationDB{err: pgx.ErrNoRows}), "mem_missing", CheckRequest{}, 0)
	if request != nil || err != nil {
		t.Fatalf("missing owner request = %v, %v; want inactive owner fact", request, err)
	}
}
