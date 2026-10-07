// Package jobs owns the lifecycle of in-process background work.
package jobs

import (
	"context"
	"sync"
)

// Runner tracks background tasks that must stop before the process exits.
// Start rejects work after Shutdown begins and cancels the task context so
// cooperative workers can finish promptly.
type Runner struct {
	ctx    context.Context
	cancel context.CancelFunc

	mu        sync.Mutex
	accepting bool
	wg        sync.WaitGroup
}

func New(parent context.Context) *Runner {
	if parent == nil {
		parent = context.Background()
	}
	ctx, cancel := context.WithCancel(parent)
	return &Runner{ctx: ctx, cancel: cancel, accepting: true}
}

// Start schedules one task. It returns false when shutdown has started.
func (r *Runner) Start(task func(context.Context)) bool {
	if task == nil {
		return false
	}
	r.mu.Lock()
	if !r.accepting {
		r.mu.Unlock()
		return false
	}
	r.wg.Add(1)
	r.mu.Unlock()
	go func() {
		defer r.wg.Done()
		task(r.ctx)
	}()
	return true
}

// Shutdown stops accepting work, cancels running tasks, and waits for them
// until ctx expires. A nil runner is already shut down.
func (r *Runner) Shutdown(ctx context.Context) error {
	if r == nil {
		return nil
	}
	if ctx == nil {
		ctx = context.Background()
	}
	r.mu.Lock()
	r.accepting = false
	r.cancel()
	r.mu.Unlock()
	done := make(chan struct{})
	go func() {
		r.wg.Wait()
		close(done)
	}()
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (r *Runner) Context() context.Context {
	if r == nil {
		return context.Background()
	}
	return r.ctx
}
