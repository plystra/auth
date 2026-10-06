package engine

import "testing"

func TestCheckRespectsGrantScopeAndDefaultDeny(t *testing.T) {
	tests := []struct {
		name    string
		request Request
		want    Effect
		code    string
	}{
		{
			name:    "space grant allows matching resource",
			request: Request{MemberID: "mem_1", Permission: "document:read", ResourceSpace: "spc_1", Assignments: []Assignment{{MemberID: "mem_1", Permissions: []string{"document:read"}, Scope: Scope{Kind: "space", Anchor: "spc_1"}}}},
			want:    Allow, code: "allowed",
		},
		{
			name:    "space grant denies a different resource",
			request: Request{MemberID: "mem_1", Permission: "document:read", ResourceSpace: "spc_2", Assignments: []Assignment{{MemberID: "mem_1", Permissions: []string{"document:read"}, Scope: Scope{Kind: "space", Anchor: "spc_1"}}}},
			want:    Deny, code: "SCOPE_OUT_OF_BOUNDS",
		},
		{
			name:    "self grant requires owner",
			request: Request{MemberID: "mem_1", Permission: "profile:read", ResourceSpace: "spc_1", ResourceOwner: "mem_2", Assignments: []Assignment{{MemberID: "mem_1", Permissions: []string{"profile:read"}, Scope: Scope{Kind: "self"}}}},
			want:    Deny, code: "SCOPE_OUT_OF_BOUNDS",
		},
		{
			name:    "global grant matches any resource",
			request: Request{MemberID: "mem_1", Permission: "audit:read", ResourceSpace: "spc_2", Assignments: []Assignment{{MemberID: "mem_1", Permissions: []string{"audit:read"}, Scope: Scope{Kind: "global"}}}},
			want:    Allow, code: "allowed",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Check(tt.request)
			if got.Effect != tt.want || got.Code != tt.code {
				t.Fatalf("Check() = %+v, want effect=%s code=%s", got, tt.want, tt.code)
			}
		})
	}
}

func TestAgentAuthorityIsBoundToOwnerEnvelope(t *testing.T) {
	owner := Request{
		MemberID: "mem_owner", Permission: "invoice:approve", ResourceSpace: "spc_1",
		Assignments: []Assignment{{MemberID: "mem_owner", Permissions: []string{"invoice:approve"}, Scope: Scope{Kind: "space", Anchor: "spc_1"}}},
	}
	agent := Request{
		MemberID: "mem_agent", PrincipalType: "agent", Permission: "invoice:approve", ResourceSpace: "spc_1",
		Assignments: []Assignment{{MemberID: "mem_agent", Permissions: []string{"invoice:approve"}, Scope: Scope{Kind: "space", Anchor: "spc_1"}}},
		Owner:       &owner,
	}
	if got := Check(agent); got.Effect != Allow {
		t.Fatalf("agent should be allowed while owner is allowed: %+v", got)
	}
	owner.Assignments[0].Permissions = []string{"invoice:read"}
	if got := Check(agent); got.Code != "OWNER_ENVELOPE_EXCLUDED" {
		t.Fatalf("agent should follow owner envelope: %+v", got)
	}
}

func TestCheckRejectsAnExplicitlyEmptyEffectiveEnvelope(t *testing.T) {
	request := Request{
		MemberID: "mem_1", Permission: "document:read", ResourceSpace: "spc_1",
		Assignments: []Assignment{{MemberID: "mem_1", Permissions: []string{"document:read"}, Scope: Scope{Kind: "space", Anchor: "spc_1"}, EnvelopeEnforced: true}},
	}
	if got := Check(request); got.Effect != Deny || got.Code != "ENVELOPE_EXCLUDED" {
		t.Fatalf("explicitly empty envelope decision = %+v, want ENVELOPE_EXCLUDED", got)
	}
}

func TestAgentApprovalAndPrincipalKind(t *testing.T) {
	request := Request{
		MemberID: "mem_agent", PrincipalType: "agent", Permission: "billing:write", ResourceSpace: "spc_1",
		Assignments: []Assignment{{MemberID: "mem_agent", Permissions: []string{"billing:write"}, PrincipalKinds: []string{"agent"}, AgentApprovalRequired: true, Scope: Scope{Kind: "space", Anchor: "spc_1"}}},
		Owner:       &Request{MemberID: "mem_owner", Permission: "billing:write", ResourceSpace: "spc_1", Assignments: []Assignment{{MemberID: "mem_owner", Permissions: []string{"billing:write"}, Scope: Scope{Kind: "space", Anchor: "spc_1"}}}},
	}
	if got := Check(request); got.Code != "APPROVAL_REQUIRED" {
		t.Fatalf("expected approval requirement: %+v", got)
	}
	request.ApprovalValid = true
	if got := Check(request); got.Effect != Allow {
		t.Fatalf("valid approval should allow: %+v", got)
	}
}

func TestOwnerEnvelopeDoesNotPropagateOwnerApproval(t *testing.T) {
	request := Request{
		MemberID: "mem_child", PrincipalType: "agent", Permission: "billing:write", ResourceSpace: "spc_1",
		Assignments: []Assignment{{MemberID: "mem_child", Permissions: []string{"billing:write"}, Scope: Scope{Kind: "space", Anchor: "spc_1"}}},
		Owner: &Request{
			MemberID: "mem_parent", PrincipalType: "agent", Permission: "billing:write", ResourceSpace: "spc_1",
			Assignments: []Assignment{{MemberID: "mem_parent", Permissions: []string{"billing:write"}, AgentApprovalRequired: true, Scope: Scope{Kind: "space", Anchor: "spc_1"}}},
			Owner: &Request{
				MemberID: "mem_human", Permission: "billing:write", ResourceSpace: "spc_1",
				Assignments: []Assignment{{MemberID: "mem_human", Permissions: []string{"billing:write"}, Scope: Scope{Kind: "space", Anchor: "spc_1"}}},
			},
		},
	}
	if got := Check(request); got.Effect != Allow {
		t.Fatalf("owner approval must not be required while checking the envelope: %+v", got)
	}
}

func TestNestedInactiveOwnerReturnsOwnerInactive(t *testing.T) {
	grant := func(member string) Assignment {
		return Assignment{MemberID: member, Permissions: []string{"auth.members:manage"}, Scope: Scope{Kind: "space", Anchor: "spc_1"}}
	}
	parent := Request{MemberID: "mem_parent", PrincipalType: "agent", Permission: "auth.members:manage", ResourceSpace: "spc_1", Assignments: []Assignment{grant("mem_parent")}}
	child := Request{MemberID: "mem_child", PrincipalType: "agent", Permission: "auth.members:manage", ResourceSpace: "spc_1", Assignments: []Assignment{grant("mem_child")}, Owner: &parent}
	if got := Check(child); got.Effect != Deny || got.Code != "OWNER_INACTIVE" {
		t.Fatalf("nested inactive owner decision = %+v, want OWNER_INACTIVE", got)
	}
}

func TestCheckTableCoversEveryScopeAndDecisionReason(t *testing.T) {
	grant := func(permission string, scope Scope) Assignment {
		return Assignment{MemberID: "mem_1", Permissions: []string{permission}, Scope: scope}
	}
	owner := func(permission string) *Request {
		return &Request{MemberID: "mem_owner", Permission: permission, ResourceSpace: "spc_1", Assignments: []Assignment{grantFor("mem_owner", permission)}}
	}
	tests := []struct {
		name string
		in   Request
		want Effect
		code string
	}{
		{name: "invalid subject", in: Request{Permission: "document:read"}, want: Deny, code: "invalid_subject"},
		{name: "self", in: Request{MemberID: "mem_1", Permission: "profile:read", ResourceSpace: "spc_1", ResourceOwner: "mem_1", Assignments: []Assignment{grant("profile:read", Scope{Kind: "self"})}}, want: Allow, code: "allowed"},
		{name: "group", in: Request{MemberID: "mem_1", Permission: "document:read", ResourceSpace: "spc_1", ResourceGroup: "grp_1", Assignments: []Assignment{grant("document:read", Scope{Kind: "group", Anchor: "grp_1"})}}, want: Allow, code: "allowed"},
		{name: "group tree", in: Request{MemberID: "mem_1", Permission: "document:read", ResourceSpace: "spc_1", ResourceGroup: "grp_child", ResourceGroupAncestors: []string{"grp_root"}, Assignments: []Assignment{grant("document:read", Scope{Kind: "group_tree", Anchor: "grp_root"})}}, want: Allow, code: "allowed"},
		{name: "space", in: Request{MemberID: "mem_1", Permission: "document:read", ResourceSpace: "spc_1", Assignments: []Assignment{grant("document:read", Scope{Kind: "space", Anchor: "spc_1"})}}, want: Allow, code: "allowed"},
		{name: "space tree", in: Request{MemberID: "mem_1", Permission: "document:read", ResourceSpace: "spc_child", ResourceSpaceAncestors: []string{"spc_root"}, Assignments: []Assignment{grant("document:read", Scope{Kind: "space_tree", Anchor: "spc_root"})}}, want: Allow, code: "allowed"},
		{name: "global", in: Request{MemberID: "mem_1", Permission: "audit:read", ResourceSpace: "spc_any", Assignments: []Assignment{grant("audit:read", Scope{Kind: "global"})}}, want: Allow, code: "allowed"},
		{name: "unknown permission", in: Request{MemberID: "mem_1", Permission: "missing:read", ResourceSpace: "spc_1"}, want: Deny, code: "NO_MATCHING_PERMISSION"},
		{name: "principal kind", in: Request{MemberID: "mem_1", PrincipalType: "agent", Permission: "document:read", ResourceSpace: "spc_1", Assignments: []Assignment{{MemberID: "mem_1", Permissions: []string{"document:read"}, PrincipalKinds: []string{"human"}, Scope: Scope{Kind: "space", Anchor: "spc_1"}}}}, want: Deny, code: "PRINCIPAL_KIND_NOT_ALLOWED"},
		{name: "envelope", in: Request{MemberID: "mem_1", Permission: "document:read", ResourceSpace: "spc_1", Assignments: []Assignment{{MemberID: "mem_1", Permissions: []string{"document:read"}, EnvelopeEnforced: true, Scope: Scope{Kind: "space", Anchor: "spc_1"}}}}, want: Deny, code: "ENVELOPE_EXCLUDED"},
		{name: "scope", in: Request{MemberID: "mem_1", Permission: "document:read", ResourceSpace: "spc_2", Assignments: []Assignment{grant("document:read", Scope{Kind: "space", Anchor: "spc_1"})}}, want: Deny, code: "SCOPE_OUT_OF_BOUNDS"},
		{name: "owner inactive", in: Request{MemberID: "mem_1", PrincipalType: "agent", Permission: "document:read", ResourceSpace: "spc_1", Assignments: []Assignment{grant("document:read", Scope{Kind: "space", Anchor: "spc_1"})}}, want: Deny, code: "OWNER_INACTIVE"},
		{name: "owner envelope", in: Request{MemberID: "mem_1", PrincipalType: "agent", Permission: "document:read", ResourceSpace: "spc_1", Assignments: []Assignment{grant("document:read", Scope{Kind: "space", Anchor: "spc_1"})}, Owner: &Request{MemberID: "mem_owner", Permission: "document:read", ResourceSpace: "spc_1", Assignments: []Assignment{grantFor("mem_owner", "other:read")}}}, want: Deny, code: "OWNER_ENVELOPE_EXCLUDED"},
		{name: "approval", in: Request{MemberID: "mem_1", PrincipalType: "agent", Permission: "billing:write", ResourceSpace: "spc_1", Assignments: []Assignment{{MemberID: "mem_1", Permissions: []string{"billing:write"}, AgentApprovalRequired: true, Scope: Scope{Kind: "space", Anchor: "spc_1"}}}, Owner: owner("billing:write")}, want: Deny, code: "APPROVAL_REQUIRED"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Check(tt.in)
			if got.Effect != tt.want || got.Code != tt.code {
				t.Fatalf("Check() = %+v, want effect=%s code=%s", got, tt.want, tt.code)
			}
		})
	}
}

func grantFor(memberID, permission string) Assignment {
	return Assignment{MemberID: memberID, Permissions: []string{permission}, Scope: Scope{Kind: "space", Anchor: "spc_1"}}
}
