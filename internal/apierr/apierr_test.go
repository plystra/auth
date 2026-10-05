package apierr

import (
	"encoding/json"
	"net/http"
	"testing"
)

func TestStatusUsesStableHTTPSemantics(t *testing.T) {
	tests := map[string]int{
		"invalid_credentials":     http.StatusUnauthorized,
		"browser_origin_rejected": http.StatusForbidden,
		"BROWSER_ORIGIN_REJECTED": http.StatusForbidden,
		"unavailable":             http.StatusServiceUnavailable,
		"not_implemented":         http.StatusNotImplemented,
		"invalid_grant":           http.StatusBadRequest,
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
