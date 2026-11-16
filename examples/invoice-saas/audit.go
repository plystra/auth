package invoicesaas

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/plystra/auth/examples/invoice-saas/internal/db"
	"github.com/plystra/auth/internal/ids"
	"github.com/plystra/auth/internal/requestinfo"
	"github.com/riverqueue/river"
	"github.com/riverqueue/river/riverdriver/riverpgxv5"
)

type auditDeliveryArgs struct {
	DeliveryID string `json:"delivery_id"`
}

func (auditDeliveryArgs) Kind() string { return "invoice_audit_delivery" }

type auditWorker struct {
	river.WorkerDefaults[auditDeliveryArgs]
	store *Store
	auth  *AuthClient
}

func (w *auditWorker) Work(ctx context.Context, job *river.Job[auditDeliveryArgs]) error {
	return w.store.deliverAudit(ctx, w.auth, job.Args.DeliveryID)
}

// StartAudit starts the durable consumer before the SaaS listener accepts work.
func (s *Store) StartAudit(ctx context.Context, auth *AuthClient) error {
	if auth == nil {
		return errors.New("Invoice SaaS audit requires an Auth client")
	}
	workers := river.NewWorkers()
	river.AddWorker(workers, &auditWorker{store: s, auth: auth})
	client, err := river.NewClient(riverpgxv5.New(s.pool), &river.Config{
		Queues: map[string]river.QueueConfig{river.QueueDefault: {MaxWorkers: 2}}, Workers: workers,
		CancelledJobRetentionPeriod: -1, DiscardedJobRetentionPeriod: -1,
	})
	if err != nil {
		return errors.New("cannot configure the Invoice SaaS audit worker")
	}
	if err := client.Start(ctx); err != nil {
		return errors.New("cannot start the Invoice SaaS audit worker")
	}
	s.jobs = client
	return nil
}

func (s *Store) StopAudit(ctx context.Context) error { return s.jobs.Stop(ctx) }

func (s *Store) enqueueAudit(ctx context.Context, q *db.Queries, tx pgx.Tx, row db.Invoice, subject subjectIdentity, action, outcome, digest string) error {
	event, err := q.CreateAuditDelivery(ctx, db.CreateAuditDeliveryParams{
		ID: string(ids.New[ids.ID]("evt")), InvoiceID: row.ID, SpaceID: row.SpaceID, GroupID: row.GroupID,
		MemberID: subject.MemberID, UserID: optionalText(subject.UserID), Action: action, Outcome: outcome,
		RequestID: requestinfo.Get(ctx).ID, RequestDigest: optionalText(digest),
	})
	if err != nil {
		return err
	}
	job, err := s.jobs.InsertTx(ctx, tx, auditDeliveryArgs{DeliveryID: event.ID}, nil)
	if err != nil {
		return err
	}
	return q.SetAuditDeliveryJob(ctx, db.SetAuditDeliveryJobParams{ID: event.ID, JobID: pgtype.Int8{Int64: job.Job.ID, Valid: true}})
}

func (s *Store) recordAudit(ctx context.Context, row db.Invoice, subject subjectIdentity, action, outcome, digest string) error {
	if err := s.inTx(ctx, func(q *db.Queries, tx pgx.Tx) error {
		return s.enqueueAudit(ctx, q, tx, row, subject, action, outcome, digest)
	}); err != nil {
		return unavailable()
	}
	return nil
}

type auditReceipt struct {
	ID         string    `json:"id"`
	OccurredAt time.Time `json:"occurred_at"`
}

type auditReport struct {
	Subject struct {
		MemberID string `json:"member_id"`
		UserID   string `json:"user_id,omitempty"`
	} `json:"subject"`
	Action        string   `json:"action"`
	Outcome       string   `json:"outcome"`
	Resource      resource `json:"resource"`
	RequestDigest string   `json:"request_digest,omitempty"`
}

// The destination includes the exact credential because Auth's idempotency
// scope is bound to it. A rotation must not silently turn an ambiguous retry
// into a first request under another scope. Only a fingerprint is persisted.
func (c *AuthClient) auditDestination() [32]byte {
	return sha256.Sum256([]byte(c.config.ServerURL + "\x00" + c.config.ClientID + "\x00" + c.config.APIKey.Value()))
}

func (c *AuthClient) reportAudit(ctx context.Context, event db.InvoiceAuditDelivery) (auditReceipt, string, bool) {
	input := auditReport{Action: event.Action, Outcome: event.Outcome,
		Resource:      resource{Type: "invoice", ID: event.InvoiceID, SpaceID: event.SpaceID, GroupID: event.GroupID},
		RequestDigest: event.RequestDigest.String}
	input.Subject.MemberID, input.Subject.UserID = event.MemberID, event.UserID.String
	body, err := json.Marshal(input)
	if err != nil {
		return auditReceipt{}, "AUTH_UNAVAILABLE", false
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(c.config.ServerURL, "/")+"/server/v1/audit/events", bytes.NewReader(body))
	if err != nil {
		return auditReceipt{}, "AUTH_UNAVAILABLE", false
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.config.APIKey.Value())
	req.Header.Set("X-Request-Id", event.RequestID)
	req.Header.Set("Idempotency-Key", fmt.Sprintf("%s:%d", event.ID, event.Generation))
	response, err := c.http.Do(req)
	if err != nil {
		return auditReceipt{}, "AUTH_UNAVAILABLE", false
	}
	defer func() { _ = response.Body.Close() }()
	body, err = readBounded(response.Body)
	if err != nil {
		return auditReceipt{}, "AUTH_UNAVAILABLE", false
	}
	if response.StatusCode != http.StatusOK {
		var failure struct {
			Error struct{ Code string } `json:"error"`
		}
		// Only an explicitly replayed failure proves that this idempotency
		// generation did not append an event. Proxy errors and lost replies
		// retain the same key until its safe retry window ends.
		knownFailure := json.Unmarshal(body, &failure) == nil && failure.Error.Code != "" &&
			response.Header.Get("Idempotency-Replayed") == "true" &&
			(response.StatusCode == http.StatusServiceUnavailable || response.StatusCode == http.StatusBadRequest ||
				response.StatusCode == http.StatusForbidden || response.StatusCode == http.StatusNotFound)
		return auditReceipt{}, "AUTH_REJECTED", knownFailure
	}
	var receipt struct {
		Data auditReceipt `json:"data"`
	}
	if json.Unmarshal(body, &receipt) != nil || !ids.AuditID(receipt.Data.ID).Valid() || receipt.Data.OccurredAt.IsZero() {
		return auditReceipt{}, "INVALID_RECEIPT", false
	}
	return receipt.Data, "", false
}

func (s *Store) deliverAudit(ctx context.Context, auth *AuthClient, id string) error {
	var event db.InvoiceAuditDelivery
	destination := auth.auditDestination()
	err := s.inTx(ctx, func(q *db.Queries, _ pgx.Tx) error {
		var err error
		event, err = q.LockAuditDelivery(ctx, db.LockAuditDeliveryParams{ID: id})
		if err != nil || event.AuditID.Valid || event.Blocked {
			return err
		}
		if !event.AttemptStartedAt.Valid {
			event, err = q.StartAuditDeliveryAttempt(ctx, db.StartAuditDeliveryAttemptParams{ID: id, DestinationHash: destination[:]})
			return err
		}
		code := ""
		if !bytes.Equal(event.DestinationHash, destination[:]) {
			code = "DESTINATION_CHANGED"
		} else if time.Since(event.AttemptStartedAt.Time) >= 23*time.Hour {
			// Auth deduplicates for 24 hours; stop an hour early to leave room
			// for clock differences and requests already in flight.
			code = "IDEMPOTENCY_WINDOW_EXPIRED"
		}
		if code != "" {
			event.Blocked = true
			return q.UpdateAuditDeliveryResult(ctx, db.UpdateAuditDeliveryResultParams{
				ID: id, PreviousGeneration: event.Generation, Generation: event.Generation, Blocked: true, LastError: optionalText(code),
			})
		}
		return nil
	})
	if err != nil {
		return errors.New("audit delivery storage unavailable")
	}
	if event.AuditID.Valid {
		return nil
	}
	if event.Blocked {
		return river.JobCancel(errors.New("audit delivery requires reconciliation; use audit-status"))
	}
	receipt, code, reset := auth.reportAudit(ctx, event)
	err = s.inTx(ctx, func(q *db.Queries, _ pgx.Tx) error {
		generation := event.Generation
		if reset {
			generation++
		}
		return q.UpdateAuditDeliveryResult(ctx, db.UpdateAuditDeliveryResultParams{
			ID: id, PreviousGeneration: event.Generation, Generation: generation, ResetAttempt: reset, LastError: optionalText(code),
			AuditID: optionalText(receipt.ID), DeliveredAt: pgtype.Timestamptz{Time: time.Now().UTC(), Valid: receipt.ID != ""},
		})
	})
	if err != nil {
		return errors.New("audit delivery receipt storage unavailable")
	}
	if code != "" {
		return errors.New("audit delivery not confirmed; use audit-status")
	}
	return nil
}

type AuditDeliveryStatus struct {
	ID        string    `json:"id"`
	InvoiceID string    `json:"invoice_id"`
	Action    string    `json:"action"`
	Outcome   string    `json:"outcome"`
	State     string    `json:"state"`
	AuditID   string    `json:"audit_id,omitempty"`
	LastError string    `json:"last_error,omitempty"`
	RequestID string    `json:"request_id"`
	CreatedAt time.Time `json:"created_at"`
}

func (s *Store) AuditStatus(ctx context.Context, after string, limit int) ([]AuditDeliveryStatus, error) {
	if limit < 1 || limit > 100 || (after != "" && !strings.HasPrefix(after, "evt_")) {
		return nil, errors.New("audit-status requires --limit between 1 and 100 and an event ID for --after")
	}
	rows, err := s.queries.ListAuditDeliveries(ctx, db.ListAuditDeliveriesParams{AfterID: after, LimitCount: int32(limit)})
	if err != nil {
		return nil, errors.New("cannot read audit delivery status")
	}
	result := make([]AuditDeliveryStatus, 0, len(rows))
	for _, row := range rows {
		result = append(result, AuditDeliveryStatus{ID: row.ID, InvoiceID: row.InvoiceID, Action: row.Action, Outcome: row.Outcome,
			State: row.State, AuditID: row.AuditID.String, LastError: row.LastError.String, RequestID: row.RequestID, CreatedAt: row.CreatedAt.Time})
	}
	return result, nil
}

func optionalText(value string) pgtype.Text { return pgtype.Text{String: value, Valid: value != ""} }
