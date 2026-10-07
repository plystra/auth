package idempotency

import "context"

// Reservation describes the outcome of claiming an idempotency key.
// A replay is returned only after the caller has validated the credential
// which established the scope.
type Reservation struct {
	ID         string
	Replay     bool
	Conflict   bool
	InProgress bool
	StatusCode int
	Headers    map[string][]string
	Body       []byte
}

type Request struct {
	ScopeHash   string
	Method      string
	Path        string
	Key         string
	RequestHash []byte
}

type Response struct {
	StatusCode int
	Headers    map[string][]string
	Body       []byte
}

// Transaction is held by the HTTP layer for a request carrying an
// Idempotency-Key. Business writes and the idempotency record share this
// transaction and are committed together.
type Transaction interface {
	Context(context.Context) context.Context
	Reserve(context.Context, Request) (Reservation, error)
	Complete(context.Context, string, Response) error
	Commit(context.Context) error
	Rollback(context.Context) error
}

type TransactionManager interface {
	BeginIdempotency(context.Context) (Transaction, error)
}

// CredentialValidator runs before a replay can be returned. It must reject
// revoked or otherwise invalid credentials so a previously successful
// response cannot bypass the current authentication boundary.
type CredentialValidator func(context.Context, string, string) error
