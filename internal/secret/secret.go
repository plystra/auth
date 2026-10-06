package secret

import (
	"fmt"
	"log/slog"
)

type String string

func New(value string) String                  { return String(value) }
func (s String) String() string                { return "[REDACTED]" }
func (s String) GoString() string              { return "[REDACTED]" }
func (s String) LogValue() slog.Value          { return slog.StringValue("[REDACTED]") }
func (s String) Format(f fmt.State, verb rune) { _, _ = f.Write([]byte("[REDACTED]")) }
func (s String) Value() string                 { return string(s) }
