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
			want:    Deny, code: "missing_permission",
		},
		{
			name:    "self grant requires owner",
			request: Request{MemberID: "mem_1", Permission: "profile:read", ResourceSpace: "spc_1", ResourceOwner: "mem_2", Assignments: []Assignment{{MemberID: "mem_1", Permissions: []string{"profile:read"}, Scope: Scope{Kind: "self"}}}},
			want:    Deny, code: "missing_permission",
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
