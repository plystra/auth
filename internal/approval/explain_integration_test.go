package approval

import (
	"context"
	"crypto/sha256"
	"testing"

	"github.com/plystra/auth/internal/authz/engine"
)

func TestExplainBusinessReportsPendingAndRejectedApprovalWithoutConsumption(t *testing.T) {
	ctx := context.Background()
	f := newApprovalFixture(t)
	assertDecision := func(code string) {
		t.Helper()
		explained, _, err := f.authz.ExplainBusiness(ctx, f.check("inv_explain"), "invoice", "inv_explain")
		if err != nil || explained.Code != code || explained.Effect != engine.Deny || len(explained.Trace) == 0 {
			t.Fatalf("explain = %+v, error = %v; want %s", explained, err, code)
		}
		last := explained.Trace[len(explained.Trace)-1]
		if last != engine.Reject(code).Trace[0] {
			t.Fatalf("approval status and trace disagree: %+v", explained)
		}
		checked, _, err := f.authz.CheckBusiness(ctx, f.check("inv_explain"), "invoice", "inv_explain")
		if err != nil || checked.Code != explained.Code || checked.Effect != explained.Effect {
			t.Fatalf("check and explain disagree: %+v, %v", checked, err)
		}
	}
	assertDecision("APPROVAL_REQUIRED")
	digest := sha256.Sum256([]byte("explain approval request"))
	created, err := f.service.CreateBusiness(ctx, "key_approval_test", f.agentID, "auth.bindings:manage", f.resource("inv_explain"), digest[:], "Explain approval")
	if err != nil {
		t.Fatal(err)
	}
	assertDecision("APPROVAL_PENDING")
	proof := f.stepUpContext(t, created.ID, "approvals.reject")
	if _, err := f.service.Decide(proof, "usr_approval_owner", created.ID, false); err != nil {
		t.Fatal(err)
	}
	assertDecision("APPROVAL_REJECTED")
	var consumed bool
	if err := f.store.Pool.QueryRow(ctx, `SELECT consumed_at IS NOT NULL FROM approval_requests WHERE id = $1`, created.ID).Scan(&consumed); err != nil || consumed {
		t.Fatalf("explanation consumed an approval: consumed=%v error=%v", consumed, err)
	}
}
