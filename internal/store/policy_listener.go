package store

import (
	"context"
	"sync"
	"sync/atomic"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

const policyChannel = "auth_policy"

// PolicyListener owns the dedicated PostgreSQL connection used for policy
// invalidations. A reconnect is itself an invalidation because notifications
// may have been missed while the connection was down.
type PolicyListener struct {
	cancel context.CancelFunc
	done   chan struct{}

	pool          *pgxpool.Pool
	onInvalidate  func()
	invalidations atomic.Uint64

	mu         sync.Mutex
	conn       *pgx.Conn
	connCancel context.CancelFunc
}

func NewPolicyListener(parent context.Context, pool *pgxpool.Pool, onInvalidate func()) *PolicyListener {
	if parent == nil {
		parent = context.Background()
	}
	ctx, cancel := context.WithCancel(parent)
	l := &PolicyListener{
		cancel:       cancel,
		done:         make(chan struct{}),
		pool:         pool,
		onInvalidate: onInvalidate,
	}
	go l.run(ctx)
	return l
}

func (l *PolicyListener) run(ctx context.Context) {
	defer close(l.done)
	for {
		if ctx.Err() != nil {
			return
		}
		connCtx, cancelConn := context.WithCancel(ctx)
		conn, err := l.connect(connCtx)
		if err != nil {
			cancelConn()
			if !waitPolicyRetry(ctx) {
				return
			}
			continue
		}
		l.setConnection(conn, cancelConn)
		l.invalidate()

		for {
			_, err = conn.WaitForNotification(connCtx)
			if err != nil {
				break
			}
			l.invalidate()
		}
		cancelConn()
		l.setConnection(nil, nil)
		_ = conn.Close(context.Background())
		if ctx.Err() != nil {
			return
		}
		if !waitPolicyRetry(ctx) {
			return
		}
	}
}

func (l *PolicyListener) connect(ctx context.Context) (*pgx.Conn, error) {
	if l.pool == nil || l.pool.Config() == nil || l.pool.Config().ConnConfig == nil {
		return nil, context.Canceled
	}
	conn, err := pgx.ConnectConfig(ctx, l.pool.Config().ConnConfig.Copy())
	if err != nil {
		return nil, err
	}
	if _, err := conn.Exec(ctx, "LISTEN "+policyChannel); err != nil {
		_ = conn.Close(context.Background())
		return nil, err
	}
	return conn, nil
}

func (l *PolicyListener) invalidate() {
	l.invalidations.Add(1)
	if l.onInvalidate != nil {
		l.onInvalidate()
	}
}

func (l *PolicyListener) setConnection(conn *pgx.Conn, cancel context.CancelFunc) {
	l.mu.Lock()
	l.conn = conn
	l.connCancel = cancel
	l.mu.Unlock()
}

func (l *PolicyListener) InvalidationCount() uint64 {
	return l.invalidations.Load()
}

// Disconnect closes the current dedicated connection. The listener will
// reconnect and invalidate all cache entries; this is also useful for a
// controlled connection rotation during operations.
func (l *PolicyListener) Disconnect() {
	if l == nil {
		return
	}
	l.mu.Lock()
	cancel := l.connCancel
	l.mu.Unlock()
	if cancel != nil {
		cancel()
	}
}

func (l *PolicyListener) Close(ctx context.Context) error {
	if l == nil {
		return nil
	}
	if ctx == nil {
		ctx = context.Background()
	}
	l.cancel()
	select {
	case <-l.done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func waitPolicyRetry(ctx context.Context) bool {
	timer := time.NewTimer(100 * time.Millisecond)
	defer timer.Stop()
	select {
	case <-timer.C:
		return true
	case <-ctx.Done():
		return false
	}
}
