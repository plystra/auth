package engine

import (
	"slices"
	"testing"
)

func TestCheckChoosesClosestGrantFailureIndependentOfOrder(t *testing.T) {
	grant := Assignment{MemberID: "mem_subject", Permissions: []string{"document:read"}, Envelope: []string{"document:read"}, EnvelopeEnforced: true, Scope: Scope{Kind: "space", Anchor: "spc_resource"}}
	wrongSubject, wrongPermission, excluded, outside := grant, grant, grant, grant
	wrongSubject.MemberID = "mem_other"
	wrongPermission.Permissions = []string{"document:write"}
	excluded.Envelope = nil
	outside.Scope.Anchor = "spc_other"
	for _, tc := range []struct {
		name, code string
		grants     []Assignment
	}{
		{"no_candidate", "NO_MATCHING_PERMISSION", nil},
		{"irrelevant", "NO_MATCHING_PERMISSION", []Assignment{wrongSubject, wrongPermission}},
		{"envelope", "ENVELOPE_EXCLUDED", []Assignment{wrongSubject, wrongPermission, excluded}},
		{"closest_scope", "SCOPE_OUT_OF_BOUNDS", []Assignment{wrongSubject, wrongPermission, excluded, outside}},
		{"matching_grant", "allowed", []Assignment{wrongSubject, wrongPermission, excluded, outside, grant}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var baseline []TraceStep
			var permute func(int)
			permute = func(index int) {
				if index < len(tc.grants) {
					for i := index; i < len(tc.grants); i++ {
						tc.grants[index], tc.grants[i] = tc.grants[i], tc.grants[index]
						permute(index + 1)
						tc.grants[index], tc.grants[i] = tc.grants[i], tc.grants[index]
					}
					return
				}
				got := Check(Request{MemberID: "mem_subject", PrincipalType: "human", PrincipalKinds: []string{"human", "agent"}, Permission: "document:read", ResourceSpace: "spc_resource", Assignments: tc.grants})
				if got.Code != tc.code || (got.Effect == Allow) != (tc.code == "allowed") {
					t.Fatalf("candidate decision = %s/%s, want %s", got.Effect, got.Code, tc.code)
				}
				if baseline == nil {
					baseline = got.Trace
				} else if !slices.Equal(baseline, got.Trace) {
					t.Fatal("grant order changed the selected failure trace")
				}
				if got.Effect == Deny && got.Trace[len(got.Trace)-1] != Reject(tc.code).Trace[0] {
					t.Fatal("selected cause and trace disagree")
				}
			}
			permute(0)
		})
	}
}

func TestPrincipalKindPolicyAppliesWithoutGrantsAndToEveryOwner(t *testing.T) {
	for _, kind := range []string{"human", "agent", "application"} {
		request := Request{MemberID: "mem_subject", PrincipalType: kind, Permission: "document:read", ResourceSpace: "spc_resource", PrincipalKinds: []string{}}
		denied := Check(request)
		if denied.Code != "PRINCIPAL_KIND_NOT_ALLOWED" || len(denied.Trace) != 2 || denied.Trace[1].Step != "principal_kind" {
			t.Fatalf("%s without grants bypassed directory policy: %+v", kind, denied)
		}
		request.PrincipalKinds = []string{kind}
		if got := Check(request); got.Code != "NO_MATCHING_PERMISSION" {
			t.Fatalf("directory policy created authority for %s: %+v", kind, got)
		}
	}
	parent := Request{MemberID: "mem_parent", PrincipalType: "agent", Permission: "document:read", ResourceSpace: "spc_resource",
		Assignments: []Assignment{{MemberID: "mem_parent", Permissions: []string{"document:read"}, Scope: Scope{Kind: "global"}}},
		Owner:       &Request{MemberID: "mem_human", PrincipalType: "human", Permission: "document:read", PrincipalKinds: []string{"human", "agent"}},
	}
	child := Request{MemberID: "mem_child", PrincipalType: "agent", Permission: "document:read", ResourceSpace: "spc_resource", PrincipalKinds: []string{"agent"},
		Assignments: []Assignment{{MemberID: "mem_child", Permissions: []string{"document:read"}, Scope: Scope{Kind: "global"}}}, Owner: &parent,
	}
	got := Check(child)
	if got.Code != "OWNER_ENVELOPE_EXCLUDED" || !slices.ContainsFunc(got.Trace, func(step TraceStep) bool { return step.Step == "owner.owner.principal_kind" && step.Result == "fail" }) {
		t.Fatalf("an owner overrode the same action's directory policy: %+v", got)
	}
}
