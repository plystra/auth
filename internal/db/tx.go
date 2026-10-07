package db

import "github.com/jackc/pgx/v5"

// Transaction returns the pgx transaction backing this query set. Store.InTx
// is the only constructor for transactional query sets; exposing the concrete
// transaction here lets infrastructure such as River enqueue work atomically
// with the business mutation.
func (q *Queries) Transaction() (pgx.Tx, bool) {
	tx, ok := q.db.(pgx.Tx)
	return tx, ok
}
