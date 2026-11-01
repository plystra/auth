package jobs

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/plystra/auth/internal/db"
	"github.com/riverqueue/river"
	"github.com/riverqueue/river/riverdriver/riverpgxv5"
)

type AgentExpiryService interface {
	ExpireAgents(context.Context) (int, error)
}

type AgentExpiryArgs struct{}

func (AgentExpiryArgs) Kind() string { return "agent_expiry" }

type AgentExpiryWorker struct {
	river.WorkerDefaults[AgentExpiryArgs]
	Service AgentExpiryService
}

type EmailDeliveryService interface {
	DeliverEmail(context.Context, []byte) error
}

type EmailDeliveryArgs struct {
	Ciphertext []byte `json:"ciphertext"`
}

func (EmailDeliveryArgs) Kind() string { return "email_delivery" }

type EmailDeliveryWorker struct {
	river.WorkerDefaults[EmailDeliveryArgs]
	Service EmailDeliveryService
}

func (w *EmailDeliveryWorker) Work(ctx context.Context, job *river.Job[EmailDeliveryArgs]) error {
	if w.Service == nil {
		return fmt.Errorf("email delivery service is not configured")
	}
	return w.Service.DeliverEmail(ctx, job.Args.Ciphertext)
}

func (w *AgentExpiryWorker) Work(ctx context.Context, _ *river.Job[AgentExpiryArgs]) error {
	if w.Service == nil {
		return fmt.Errorf("agent expiry service is not configured")
	}
	_, err := w.Service.ExpireAgents(ctx)
	return err
}

// Client is the process-local River producer. Workers are added by the
// capability that owns a job; this producer is safe to use from business
// transactions without opening a second connection.
type Client struct {
	pool                    *pgxpool.Pool
	river                   *river.Client[pgx.Tx]
	workers                 *river.Workers
	agentExpiryRegistered   bool
	emailDeliveryRegistered bool
}

func NewClient(pool *pgxpool.Pool) (*Client, error) {
	client, err := river.NewClient(riverpgxv5.New(pool), &river.Config{})
	if err != nil {
		return nil, fmt.Errorf("configure river client: %w", err)
	}
	return &Client{pool: pool, river: client}, nil
}

func (c *Client) RegisterAgentExpiry(service AgentExpiryService) error {
	if c == nil || c.pool == nil || c.river == nil {
		return fmt.Errorf("river client is not configured")
	}
	if c.agentExpiryRegistered {
		return fmt.Errorf("agent expiry job is already registered")
	}
	if err := c.ensureWorkers(); err != nil {
		return err
	}
	river.AddWorker(c.workers, &AgentExpiryWorker{Service: service})
	c.agentExpiryRegistered = true
	c.river.PeriodicJobs().Add(river.NewPeriodicJob(
		river.PeriodicInterval(time.Minute),
		func() (river.JobArgs, *river.InsertOpts) { return AgentExpiryArgs{}, nil },
		&river.PeriodicJobOpts{RunOnStart: true},
	))
	return nil
}

func (c *Client) RegisterEmailDelivery(service EmailDeliveryService) error {
	if c == nil || c.pool == nil || c.river == nil || service == nil {
		return fmt.Errorf("email delivery service is not configured")
	}
	if c.emailDeliveryRegistered {
		return fmt.Errorf("email delivery job is already registered")
	}
	if err := c.ensureWorkers(); err != nil {
		return err
	}
	river.AddWorker(c.workers, &EmailDeliveryWorker{Service: service})
	c.emailDeliveryRegistered = true
	return nil
}

func (c *Client) ensureWorkers() error {
	if c.workers != nil {
		return nil
	}
	workers := river.NewWorkers()
	client, err := river.NewClient(riverpgxv5.New(c.pool), &river.Config{
		Queues:  map[string]river.QueueConfig{river.QueueDefault: {MaxWorkers: 1}},
		Workers: workers,
	})
	if err != nil {
		return fmt.Errorf("configure agent expiry worker: %w", err)
	}
	c.river = client
	c.workers = workers
	return nil
}

func (c *Client) Start(ctx context.Context) error {
	if c == nil || c.river == nil {
		return fmt.Errorf("river client is not configured")
	}
	return c.river.Start(ctx)
}

func (c *Client) Stop(ctx context.Context) error {
	if c == nil || c.river == nil {
		return nil
	}
	return c.river.Stop(ctx)
}

// InsertTx enqueues args on the exact transaction owned by Store.InTx. A
// query set backed by the pool is rejected so callers cannot accidentally
// create a job outside the business transaction.
func (c *Client) InsertTx(ctx context.Context, q *db.Queries, args river.JobArgs) error {
	if c == nil || c.river == nil {
		return fmt.Errorf("river client is not configured")
	}
	tx, ok := q.Transaction()
	if !ok {
		return fmt.Errorf("river enqueue requires a store transaction")
	}
	if _, err := c.river.InsertTx(ctx, tx, args, nil); err != nil {
		return fmt.Errorf("enqueue river job: %w", err)
	}
	return nil
}
