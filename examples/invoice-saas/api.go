package invoicesaas

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/danielgtaylor/huma/v2"
	"github.com/danielgtaylor/huma/v2/adapters/humago"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/plystra/auth/examples/invoice-saas/internal/db"
	"github.com/plystra/auth/internal/apierr"
	"github.com/plystra/auth/internal/requestinfo"
	"github.com/plystra/auth/internal/route"
	"github.com/plystra/auth/internal/secret"
)

type API struct {
	Store *Store
	Auth  *AuthClient
}

type Invoice struct {
	ID          string     `json:"id"`
	SpaceID     string     `json:"space_id"`
	GroupID     string     `json:"group_id"`
	AmountCents int64      `json:"amount_cents"`
	Currency    string     `json:"currency"`
	Status      string     `json:"status"`
	Version     int64      `json:"version"`
	ApprovedBy  string     `json:"approved_by,omitempty"`
	ApprovedAt  *time.Time `json:"approved_at,omitempty"`
}

type InvoiceInput struct {
	Authorization string `header:"Authorization"`
	ID            string `path:"id" pattern:"^inv_[a-zA-Z0-9_-]+$" maxLength:"128"`
}

type ApproveInput struct {
	Authorization string `header:"Authorization"`
	ID            string `path:"id" pattern:"^inv_[a-zA-Z0-9_-]+$" maxLength:"128"`
	Body          struct {
		ExpectedVersion int64 `json:"expected_version" minimum:"1"`
	}
}

type InvoiceOutput struct {
	DecisionID string `header:"X-Auth-Decision-Id"`
	Body       struct {
		Data Invoice `json:"data"`
	}
}

func (a *API) Handler() http.Handler {
	mux := http.NewServeMux()
	a.Register(humago.New(mux, route.HumaConfig("Invoice SaaS", "1.0.0")))
	return route.Middleware(route.Principal, mux)
}

// Register declares the example's own business API. Authorization is always a
// public HTTP call to Auth; no Auth domain service or database is accessed.
func (a *API) Register(api huma.API) {
	route.Register(api, route.NewSpec("invoice-saas.read", "GET", "/invoices/{id}", route.Principal, "invoice:read", []route.Subject{route.HumanAgent}, route.WithAuthoritativeCheck()), a.read)
	route.Register(api, route.NewSpec("invoice-saas.approve", "POST", "/invoices/{id}/approve", route.Principal, "invoice:approve", []route.Subject{route.HumanAgent}, route.WithAuthoritativeCheck()), a.approve)
}

func (a *API) load(ctx context.Context, bearer, id string) (db.Invoice, secret.String, subjectIdentity, error) {
	token, subject, err := a.Auth.authenticate(ctx, bearer)
	if err != nil {
		return db.Invoice{}, "", subjectIdentity{}, err
	}
	row, err := a.Store.queries.GetInvoice(ctx, db.GetInvoiceParams{ID: id})
	if errors.Is(err, pgx.ErrNoRows) {
		return db.Invoice{}, "", subjectIdentity{}, apierr.New("NOT_FOUND", "The invoice was not found.")
	}
	if err != nil {
		return db.Invoice{}, "", subjectIdentity{}, unavailable()
	}
	return row, token, subject, nil
}

func invoiceResource(row db.Invoice) resource {
	return resource{Type: "invoice", ID: row.ID, SpaceID: row.SpaceID, GroupID: row.GroupID}
}

func (a *API) read(ctx context.Context, in *InvoiceInput) (*InvoiceOutput, error) {
	row, token, subject, err := a.load(ctx, in.Authorization, in.ID)
	if err != nil {
		return nil, err
	}
	decision, err := a.Auth.check(ctx, token, "invoice:read", invoiceResource(row), requestinfo.Get(ctx).ID)
	if err != nil {
		_ = a.Store.recordAudit(ctx, row, subject, "invoice.read", "failure", "")
		return nil, err
	}
	outcome := "success"
	if decision.Decision != "allow" {
		outcome = "deny"
	}
	if err := a.Store.recordAudit(ctx, row, subject, "invoice.read", outcome, ""); err != nil {
		return nil, err
	}
	if decision.Decision != "allow" {
		return nil, denied(decision, "", "")
	}
	return invoiceOutput(row, decision.DecisionID), nil
}

func (a *API) approve(ctx context.Context, in *ApproveInput) (*InvoiceOutput, error) {
	row, token, subject, err := a.load(ctx, in.Authorization, in.ID)
	if err != nil {
		return nil, err
	}
	digest, err := approvalDigest(row)
	if err != nil {
		return nil, unavailable()
	}
	requestID := requestinfo.Get(ctx).ID
	decision, err := a.Auth.check(ctx, token, "invoice:approve", invoiceResource(row), requestID)
	if err != nil {
		_ = a.Store.recordAudit(ctx, row, subject, "invoice.approve", "failure", digest)
		return nil, err
	}
	if decision.Decision != "allow" {
		var approvalID string
		if decision.DenyCode == "APPROVAL_REQUIRED" && row.Status == "draft" && row.Version == in.Body.ExpectedVersion {
			reason := fmt.Sprintf("Approve invoice %s: %d minor units %s, version %d.", row.ID, row.AmountCents, row.Currency, row.Version)
			approvalID, err = a.Auth.requestApproval(ctx, token, invoiceResource(row), digest, reason, requestID)
			if err != nil {
				_ = a.Store.recordAudit(ctx, row, subject, "invoice.approve", "failure", digest)
				return nil, err
			}
		}
		if err := a.Store.recordAudit(ctx, row, subject, "invoice.approve", "deny", digest); err != nil {
			return nil, err
		}
		return nil, denied(decision, approvalID, digest)
	}
	// Auth's decision and this SaaS mutation are separate transactions. The
	// version predicate prevents a concurrent request from approving twice.
	var approved db.Invoice
	var conflict bool
	err = a.Store.inTx(ctx, func(q *db.Queries, tx pgx.Tx) error {
		var err error
		approved, err = q.ApproveInvoice(ctx, db.ApproveInvoiceParams{
			ID: row.ID, ExpectedVersion: in.Body.ExpectedVersion, MemberID: pgtype.Text{String: subject.MemberID, Valid: true},
		})
		outcome := "success"
		if errors.Is(err, pgx.ErrNoRows) {
			conflict, outcome = true, "failure"
		} else if err != nil {
			return err
		}
		return a.Store.enqueueAudit(ctx, q, tx, row, subject, "invoice.approve", outcome, digest)
	})
	if err != nil {
		return nil, unavailable()
	}
	if conflict {
		return nil, apierr.New("CONFLICT", "The invoice version changed or it is already approved.")
	}
	return invoiceOutput(approved, decision.DecisionID), nil
}

func approvalDigest(row db.Invoice) (string, error) {
	// Digest and reason describe immutable, server-read invoice facts.
	payload, err := json.Marshal(struct {
		Action      string `json:"action"`
		InvoiceID   string `json:"invoice_id"`
		Version     int64  `json:"version"`
		AmountCents int64  `json:"amount_cents"`
		Currency    string `json:"currency"`
	}{"invoice:approve", row.ID, row.Version, row.AmountCents, row.Currency})
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(payload)
	return hex.EncodeToString(sum[:]), nil
}

func denied(decision decision, approvalID, digest string) *apierr.Error {
	details := map[string]string{"decision_id": decision.DecisionID}
	if approvalID != "" {
		details["approval_id"], details["request_digest"] = approvalID, digest
	}
	return apierr.WithStatus(&apierr.Error{Code: decision.DenyCode, Message: "Auth denied the invoice operation.", Details: details}, http.StatusForbidden)
}

func invoiceOutput(row db.Invoice, decisionID string) *InvoiceOutput {
	out := &InvoiceOutput{DecisionID: decisionID}
	out.Body.Data = Invoice{ID: row.ID, SpaceID: row.SpaceID, GroupID: row.GroupID, AmountCents: row.AmountCents, Currency: row.Currency, Status: row.Status, Version: row.Version, ApprovedBy: row.ApprovedBy.String}
	if row.ApprovedAt.Valid {
		at := row.ApprovedAt.Time
		out.Body.Data.ApprovedAt = &at
	}
	return out
}
