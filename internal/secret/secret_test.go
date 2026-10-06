package secret

import (
	"bytes"
	"fmt"
	"log/slog"
	"strings"
	"testing"
)

func TestSecretRedactsFmtAndSlogOutput(t *testing.T) {
	value := New("ply_sk_sensitive-value")
	typed := String(value)
	formatted := fmt.Sprintf("%s %q %v %+v %#v", typed, typed, typed, typed, typed)
	if strings.Contains(formatted, value.Value()) || !strings.Contains(formatted, "[REDACTED]") {
		t.Fatalf("formatted secret leaked or was not redacted: %q", formatted)
	}

	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, nil))
	logger.Info("credential", "token", value)
	if strings.Contains(buf.String(), value.Value()) || !strings.Contains(buf.String(), "REDACTED") {
		t.Fatalf("slog secret leaked or was not redacted: %q", buf.String())
	}
	buf.Reset()
	slog.New(slog.NewJSONHandler(&buf, nil)).Info("credential", "token", value)
	if strings.Contains(buf.String(), value.Value()) || !strings.Contains(buf.String(), "REDACTED") {
		t.Fatalf("JSON slog secret leaked or was not redacted: %q", buf.String())
	}
}

func TestSecretLogOutputHasNoCredentialPrefixes(t *testing.T) {
	values := []String{
		New("ply_rt_refresh-value"), New("ply_ag_agent-value"),
		New("ply_sk_application-value"), New("ply_ops_operator-value"),
	}
	var buf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buf, nil))
	for _, value := range values {
		logger.Info("credential", "token", value)
		fmt.Fprintln(&buf, value)
	}
	for _, prefix := range []string{"ply_rt_", "ply_ag_", "ply_sk_", "ply_ops_"} {
		if strings.Contains(buf.String(), prefix) {
			t.Fatalf("log output contains credential prefix %q", prefix)
		}
	}
}
