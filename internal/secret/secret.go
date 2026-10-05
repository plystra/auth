package secret

import (
	"fmt"
	"log/slog"
)

type Secret string

func New(value string) Secret                  { return Secret(value) }
func (s Secret) String() string                { return "[REDACTED]" }
func (s Secret) GoString() string              { return "[REDACTED]" }
func (s Secret) LogValue() slog.Value          { return slog.StringValue("[REDACTED]") }
func (s Secret) Format(f fmt.State, verb rune) { _, _ = f.Write([]byte("[REDACTED]")) }
func (s Secret) Value() string                 { return string(s) }
