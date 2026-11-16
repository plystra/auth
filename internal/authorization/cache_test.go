package authorization

import (
	"testing"

	"github.com/plystra/auth/internal/authz/engine"
)

func TestDecisionCacheCopiesStructuredTraceOnReadAndWrite(t *testing.T) {
	cache := newDecisionCache()
	original := engine.Reject("ENVELOPE_EXCLUDED", engine.Passed("catalog", "catalog checked"))
	cache.put("request", original, 7)
	original.Trace[0].Detail = "caller write"
	first, version, ok := cache.get("request")
	if !ok || version != 7 || first.Trace[0].Detail != "catalog checked" {
		t.Fatal("cache retained caller-owned trace storage")
	}
	first.Trace[0].Detail = "reader write"
	second, _, _ := cache.get("request")
	if second.Trace[0].Detail != "catalog checked" {
		t.Fatal("a cache reader mutated subsequent decisions")
	}
}
