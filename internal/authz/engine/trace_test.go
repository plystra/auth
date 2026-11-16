package engine

import (
	"encoding/json"
	"slices"
	"strings"
	"testing"
)

func TestTraceStopsAtEvaluatedAssignmentFailure(t *testing.T) {
	for _, tc := range []struct {
		name, code string
		change     func(*Request)
		steps      []string
	}{
		{"allow", "allowed", func(*Request) {}, []string{"subject_input", "permission", "principal_kind", "envelope", "scope"}},
		{"missing", "INVALID_SUBJECT", func(r *Request) { r.MemberID = "" }, []string{"subject"}},
		{"credential", "TOKEN_SCOPE_EXCLUDED", func(r *Request) { r.TokenScopes = []string{} }, []string{"subject_input", "token_scope"}},
		{"permission", "NO_MATCHING_PERMISSION", func(r *Request) { r.Assignments = nil }, []string{"subject_input", "permission"}},
		{"principal", "PRINCIPAL_KIND_NOT_ALLOWED", func(r *Request) { r.Assignments[0].PrincipalKinds = []string{"application"} }, []string{"subject_input", "permission", "principal_kind"}},
		{"envelope", "ENVELOPE_EXCLUDED", func(r *Request) { r.Assignments[0].EnvelopeEnforced = true }, []string{"subject_input", "permission", "principal_kind", "envelope"}},
		{"scope", "SCOPE_OUT_OF_BOUNDS", func(r *Request) { r.ResourceSpace = "spc_hidden" }, []string{"subject_input", "permission", "principal_kind", "envelope", "scope"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := Request{MemberID: "mem_private", PrincipalType: "human", Permission: "document:read", ResourceSpace: "spc_private",
				Assignments: []Assignment{{MemberID: "mem_private", Permissions: []string{"document:read"}, Scope: Scope{Kind: "space", Anchor: "spc_private"}}}}
			tc.change(&r)
			got := Check(r)
			if got.Code != tc.code {
				t.Fatalf("decision = %s, want %s", got.Code, tc.code)
			}
			steps := make([]string, len(got.Trace))
			for i, step := range got.Trace {
				steps[i] = step.Step
				want := "pass"
				if got.Effect == Deny && i == len(got.Trace)-1 {
					want = "fail"
				}
				if step.Result != want {
					t.Fatalf("step %s result = %s, want %s", step.Step, step.Result, want)
				}
			}
			if !slices.Equal(steps, tc.steps) {
				t.Fatalf("evaluated steps = %v, want %v", steps, tc.steps)
			}
			encoded, err := json.Marshal(got)
			if err != nil {
				t.Fatal(err)
			}
			for _, hidden := range []string{"mem_private", "spc_private", "spc_hidden"} {
				if strings.Contains(string(encoded), hidden) {
					t.Fatal("trace leaked a private identity")
				}
			}
		})
	}
}

func TestTracePreservesRecursiveOwnerFailuresAndApprovalBoundary(t *testing.T) {
	grant := func(id string) Request {
		return Request{MemberID: id, PrincipalType: "agent", Permission: "document:read", ResourceSpace: "spc_private",
			Assignments: []Assignment{{MemberID: id, Permissions: []string{"document:read"}, Scope: Scope{Kind: "space", Anchor: "spc_private"}}}}
	}
	top, parent, child := grant("mem_top"), grant("mem_parent"), grant("mem_child")
	top.PrincipalType = "human"
	parent.Owner, child.Owner = &top, &parent
	for _, tc := range []struct {
		code, failed string
		change       func()
	}{
		{"allowed", "", func() {}},
		{"OWNER_ENVELOPE_EXCLUDED", "owner.owner.envelope", func() { top.Assignments[0].EnvelopeEnforced = true }},
		{"OWNER_INACTIVE", "owner.owner_envelope", func() { top.Assignments[0].EnvelopeEnforced = false; parent.Owner = nil }},
		{"APPROVAL_REQUIRED", "approval", func() { parent.Owner = &top; child.Assignments[0].AgentApprovalRequired = true }},
		{"allowed", "", func() { child.ApprovalValid = true }},
	} {
		tc.change()
		got := Check(child)
		if got.Code != tc.code {
			t.Fatalf("decision = %s, want %s", got.Code, tc.code)
		}
		if tc.failed != "" && !slices.ContainsFunc(got.Trace, func(s TraceStep) bool { return s.Step == tc.failed && s.Result == "fail" }) {
			t.Fatalf("missing actual owner/approval failure %s in %+v", tc.failed, got.Trace)
		}
		if got.Code == "allowed" && !slices.ContainsFunc(got.Trace, func(s TraceStep) bool { return s.Step == "owner.owner.scope" && s.Result == "pass" }) {
			t.Fatal("recursive owner evaluation was discarded")
		}
	}
}

func TestApprovalStatusReplacesFailureWithoutMutatingPriorTrace(t *testing.T) {
	required := Reject("APPROVAL_REQUIRED", Passed("owner_envelope", "owners allowed"))
	for _, code := range []string{"APPROVAL_PENDING", "APPROVAL_REJECTED"} {
		got := required.WithApprovalStatus(code)
		if got.Code != code || got.Effect != Deny || len(got.Trace) != 2 || got.Trace[0] != required.Trace[0] || got.Trace[1] != Reject(code).Trace[0] {
			t.Fatalf("approval result lost evaluated authority: %+v", got)
		}
	}
	if required.Trace[1] != Reject("APPROVAL_REQUIRED").Trace[0] {
		t.Fatal("approval update mutated an existing decision")
	}
}
