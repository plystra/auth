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
	formatted := fmt.Sprintf("%s %v %+v %#v", value, value, value, value)
	if strings.Contains(formatted, value.Value()) || !strings.Contains(formatted, "[REDACTED]") {
		t.Fatalf("formatted secret leaked or was not redacted: %q", formatted)
	}

	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, nil))
	logger.Info("credential", "token", value)
	if strings.Contains(buf.String(), value.Value()) || !strings.Contains(buf.String(), "REDACTED") {
		t.Fatalf("slog secret leaked or was not redacted: %q", buf.String())
	}
}
