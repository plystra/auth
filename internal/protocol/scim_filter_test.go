package protocol

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/plystra/auth/internal/apierr"
	"github.com/plystra/auth/internal/enterprise"
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
		`ExTeRnAlId EQ "Case/Sensitive"`,
		`externalId eq "Employee\u002d7"`,
		`externalId eq ""`,
		`externalId eq "a\u0000b"`,
		`active eq false`,
		`AcTiVe EQ true`,
		`active eq "false"`,
		strings.Repeat(" ", 513),
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, expression string) {
		filter, err := parseSCIMCollectionFilter(expression, "userName")
		if err != nil {
			var public *apierr.Error
			if filter != (enterprise.SCIMCollectionFilter{}) || !errors.As(err, &public) || public.Code != "invalid_filter" {
				t.Fatal("rejected filters must return only invalid_filter")
			}
			return
		}
		if len(expression) > 4096 || (filter == (enterprise.SCIMCollectionFilter{})) != (strings.TrimSpace(expression) == "") {
			t.Fatal("accepted filter bypassed the expression bound or became unfiltered")
		}
		if filter.Active != nil {
			if filter.Name != "" || filter.ExternalID != "" || len(expression) > 512 {
				t.Fatal("accepted active filter exceeded its scope or bound")
			}
			return
		}
		if filter.ExternalID != "" {
			if filter.Name != "" || len(filter.ExternalID) > 512 || !utf8.ValidString(filter.ExternalID) {
				t.Fatal("accepted externalId filter is invalid")
			}
			literal, err := json.Marshal(filter.ExternalID)
			if err != nil {
				t.Fatal(err)
			}
			roundTrip, err := parseSCIMCollectionFilter("externalId eq "+string(literal), "userName")
			if err != nil || roundTrip != filter {
				t.Fatal("externalId filter did not preserve the exact lookup value")
			}
			return
		}
		value := filter.Name
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
		roundTrip, err := parseSCIMCollectionFilter("userName eq "+string(literal), "userName")
		if err != nil || roundTrip != filter {
			t.Fatal("canonical filter did not preserve the lookup value")
		}
	})
}
