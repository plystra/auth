package enterprise

import (
	"encoding/json"
	"fmt"
	"strings"
	"unicode"
	"unicode/utf8"
)

// SCIMName contains directory-owned name components with their canonical spelling.
// An empty component in a write denotes an unassigned value.
type SCIMName map[string]string

func SCIMNameAttributes() []string {
	return []string{"formatted", "familyName", "givenName", "middleName", "honorificPrefix", "honorificSuffix"}
}

func (n *SCIMName) UnmarshalJSON(data []byte) error {
	var fields map[string]*string
	if err := json.Unmarshal(data, &fields); err != nil {
		return err
	}
	result := make(SCIMName, len(fields))
	for raw, value := range fields {
		field := scimNameAttribute(raw)
		if field == "" {
			return fmt.Errorf("invalid SCIM name attribute")
		}
		if _, duplicate := result[field]; duplicate {
			return fmt.Errorf("duplicate SCIM name attribute")
		}
		name := ""
		if value != nil {
			name = *value
		}
		if !validSCIMNameValue(name) {
			return fmt.Errorf("invalid SCIM name value")
		}
		result[field] = name
	}
	*n = result
	return nil
}

func scimNameAttribute(raw string) string {
	for _, field := range SCIMNameAttributes() {
		if strings.EqualFold(raw, field) {
			return field
		}
	}
	return ""
}

func validSCIMNameValue(value string) bool {
	return len(value) <= 256 && utf8.ValidString(value) &&
		!strings.ContainsRune(value, utf8.RuneError) && !strings.ContainsFunc(value, unicode.IsControl)
}

func encodeSCIMName(initial SCIMName, patches []SCIMName) ([]byte, error) {
	result := make(SCIMName, len(initial))
	for _, update := range append([]SCIMName{initial}, patches...) {
		if update == nil {
			clear(result)
		}
		for field, value := range update {
			if scimNameAttribute(field) != field || field == "" || !validSCIMNameValue(value) {
				return nil, fmt.Errorf("invalid SCIM name component")
			}
			if value == "" {
				delete(result, field)
			} else {
				result[field] = value
			}
		}
	}
	return json.Marshal(result)
}
