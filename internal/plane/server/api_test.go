package server

import (
	"strings"
	"testing"

	"github.com/plystra/auth/internal/authz/engine"
)

func TestExplainTraceDescribesEveryAuthorizationDenyCode(t *testing.T) {
	codes := []string{
		"INVALID_SUBJECT",
		"SUBJECT_NOT_FOUND",
		"ACTOR_USER_INACTIVE",
		"BINDING_REVOKED",
		"UNKNOWN_PERMISSION",
		"PERMISSION_DISABLED",
		"ACTOR_MEMBER_INACTIVE",
		"PRINCIPAL_KIND_NOT_ALLOWED",
		"ENVELOPE_EXCLUDED",
		"SCOPE_OUT_OF_BOUNDS",
		"OWNER_INACTIVE",
		"OWNER_ENVELOPE_EXCLUDED",
		"APPROVAL_REQUIRED",
		"APPROVAL_PENDING",
		"APPROVAL_REJECTED",
		"RESOURCE_GROUP_NOT_FOUND",
		"RESOURCE_GROUP_INACTIVE",
		"SPACE_INACTIVE",
		"KEY_SCOPE_EXCLUDED",
		"APPLICATION_NOT_INSTALLED",
		"TOKEN_SCOPE_EXCLUDED",
		"NO_MATCHING_PERMISSION",
	}
	for _, code := range codes {
		t.Run(code, func(t *testing.T) {
			decision := engine.Reject(code)
			trace := explainTrace(decision)
			if len(trace) != 1 || trace[0].Step == "authorization" || trace[0].Result != "fail" {
				t.Fatalf("trace = %+v, want one specific failed authorization step", trace)
			}
			if trace[0].Detail == "authorization denied" || strings.TrimSpace(trace[0].Detail) == "" {
				t.Fatalf("trace detail = %q, want a code-specific explanation", trace[0].Detail)
			}
			if summary := explainSummary("document:read", decision); !strings.Contains(summary, code) {
				t.Fatalf("summary = %q, want deny code %q", summary, code)
			}
		})
	}
}
