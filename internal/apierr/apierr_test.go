package apierr

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestStatusUsesStableHTTPSemantics(t *testing.T) {
	tests := map[string]int{
		"invalid_client":              http.StatusUnauthorized,
		"invalid_credentials":         http.StatusUnauthorized,
		"mfa_required":                http.StatusForbidden,
		"browser_origin_rejected":     http.StatusForbidden,
		"BROWSER_ORIGIN_REJECTED":     http.StatusForbidden,
		"unavailable":                 http.StatusServiceUnavailable,
		"temporarily_unavailable":     http.StatusServiceUnavailable,
		"not_implemented":             http.StatusNotImplemented,
		"invalid_grant":               http.StatusBadRequest,
		"invalid_scope":               http.StatusBadRequest,
		"inline_grants_not_allowed":   http.StatusBadRequest,
		"OWNER_ENVELOPE_EXCLUDED":     http.StatusForbidden,
		"PRINCIPAL_KIND_NOT_ALLOWED":  http.StatusForbidden,
		"PERMISSION_DISABLED":         http.StatusForbidden,
		"SCOPE_OUT_OF_BOUNDS":         http.StatusForbidden,
		"AUTHORITY_DELTA_NOT_COVERED": http.StatusForbidden,
	}
	for code, want := range tests {
		if got := Status(code); got != want {
			t.Errorf("Status(%q) = %d, want %d", code, got, want)
		}
	}
}

func TestErrorJSONIsEnvelope(t *testing.T) {
	raw, err := json.Marshal(New("invalid_grant", "grant is invalid"))
	if err != nil {
		t.Fatal(err)
	}
	var got struct {
		Error Error `json:"error"`
	}
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatal(err)
	}
	if got.Error.Code != "invalid_grant" || got.Error.Message != "grant is invalid" {
		t.Fatalf("unexpected envelope: %s", raw)
	}
}

func TestWriteUsesExplicitStatusOverride(t *testing.T) {
	response := httptest.NewRecorder()
	Write(response, WithStatus(New("IDEMPOTENCY_KEY_REUSED", "key was reused"), http.StatusConflict))
	if response.Code != http.StatusConflict {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusConflict)
	}
}
