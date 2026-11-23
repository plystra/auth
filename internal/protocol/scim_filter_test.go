package protocol

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/plystra/auth/internal/apierr"
)

func FuzzSCIMUserFilter(f *testing.F) {
	for _, seed := range []string{
		"",
		`userName eq "Alice@Example.Test"`,
		`userName eq "Alice\u0040Example.Test"`,
		`userName eq "alice@@example.test"`,
		`userName eq "a\u0000@example.test"`,
		`userName eq "a\uD800@example.test"`,
		`userName eq "alice@example.test" or userName eq "bob@example.test"`,
		strings.Repeat(" ", 513),
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, expression string) {
		value, err := parseSCIMUserFilter(expression)
		if err != nil {
			var public *apierr.Error
			if value != "" || !errors.As(err, &public) || public.Code != "invalid_filter" {
				t.Fatal("rejected filters must return only invalid_filter")
			}
			return
		}
		if len(expression) > 512 || (value == "") != (strings.TrimSpace(expression) == "") {
			t.Fatal("accepted filter bypassed the expression bound or became unfiltered")
		}
		if value == "" {
			return
		}
		if !utf8.ValidString(value) || len(value) > 320 || strings.Count(value, "@") != 1 || value != strings.ToLower(value) {
			t.Fatal("accepted filter did not produce a normalized email")
		}
		literal, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		roundTrip, err := parseSCIMUserFilter("userName eq " + string(literal))
		if err != nil || roundTrip != value {
			t.Fatal("canonical filter did not preserve the lookup value")
		}
	})
}
