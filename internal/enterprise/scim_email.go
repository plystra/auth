package enterprise

import (
	"encoding/json"
	"net/mail"
	"slices"
	"strings"

	"github.com/plystra/auth/internal/apierr"
)

// SCIMEmail is directory profile data. It cannot establish account identity.
type SCIMEmail struct {
	Value   string `json:"value"`
	Type    string `json:"type,omitempty"`
	Display string `json:"display,omitempty"`
	Primary bool   `json:"primary,omitempty"`
}

type SCIMEmailPatch struct {
	Operation string
	Selector  string // A nonempty value selects emails by type.
	Addresses []SCIMEmail
}

func validSCIMEmailType(value string) bool {
	return len(value) <= 64 && !strings.ContainsAny(value, " \t\r\n") && validSCIMNameValue(value)
}

func normalizeSCIMEmail(address SCIMEmail) (SCIMEmail, error) {
	address.Value = strings.ToLower(strings.TrimSpace(address.Value))
	address.Type = strings.ToLower(strings.TrimSpace(address.Type))
	parsed, err := mail.ParseAddress(address.Value)
	if err != nil || parsed.Address != address.Value || !ValidSCIMUserName(address.Value) ||
		!validSCIMEmailType(address.Type) || !validSCIMNameValue(address.Display) {
		return SCIMEmail{}, apierr.New("invalid_request", "SCIM email fields are invalid")
	}
	return address, nil
}

func normalizeSCIMEmails(input []SCIMEmail) ([]SCIMEmail, error) {
	if len(input) > 16 {
		return nil, apierr.New("invalid_request", "SCIM emails accepts at most 16 addresses")
	}
	result := make([]SCIMEmail, 0, len(input))
	seen := make(map[[2]string]bool, len(input))
	primary := false
	for _, item := range input {
		address, err := normalizeSCIMEmail(item)
		if err != nil {
			return nil, err
		}
		key := [2]string{address.Type, address.Value}
		if seen[key] || primary && address.Primary {
			return nil, apierr.New("invalid_request", "SCIM emails contain duplicate addresses or more than one primary address")
		}
		seen[key] = true
		primary = primary || address.Primary
		result = append(result, address)
	}
	return result, nil
}

func encodeSCIMEmails(input []SCIMEmail, patches []SCIMEmailPatch) ([]byte, error) {
	result, err := normalizeSCIMEmails(input)
	if err != nil {
		return nil, err
	}
	for _, patch := range patches {
		addresses, err := normalizeSCIMEmails(patch.Addresses)
		if err != nil {
			return nil, err
		}
		if patch.Selector != "" {
			result, err = patchSCIMEmailType(result, strings.ToLower(patch.Selector), patch.Operation, addresses)
			if err != nil {
				return nil, err
			}
		} else {
			switch patch.Operation {
			case "remove", "replace":
				result = addresses
			case "add":
				result = addSCIMEmails(result, addresses)
			default:
				return nil, apierr.New("invalid_request", "SCIM emails operation is unsupported")
			}
		}
		result, err = normalizeSCIMEmails(result)
		if err != nil {
			return nil, err
		}
	}
	return json.Marshal(result)
}

func addSCIMEmails(result, additions []SCIMEmail) []SCIMEmail {
	for _, address := range additions {
		if address.Primary {
			for i := range result {
				result[i].Primary = false
			}
		}
		index := slices.IndexFunc(result, func(existing SCIMEmail) bool {
			return existing.Type == address.Type && existing.Value == address.Value
		})
		if index < 0 {
			result = append(result, address)
		} else if address.Primary {
			result[index].Primary = true
		}
	}
	return result
}

func patchSCIMEmailType(result []SCIMEmail, kind, operation string, addresses []SCIMEmail) ([]SCIMEmail, error) {
	if !validSCIMEmailType(kind) {
		return nil, apierr.New("invalid_filter", "SCIM email type is invalid")
	}
	if operation == "remove" {
		return slices.DeleteFunc(result, func(address SCIMEmail) bool { return address.Type == kind }), nil
	}
	if len(addresses) != 1 || operation != "add" && operation != "replace" {
		return nil, apierr.New("invalid_request", "SCIM email update requires one address")
	}
	index := -1
	for i, address := range result {
		if address.Type == kind {
			if index >= 0 {
				return nil, apierr.New("invalid_request", "SCIM email type matches multiple addresses")
			}
			index = i
		}
	}
	if index < 0 {
		if operation == "add" {
			return append(result, SCIMEmail{Value: addresses[0].Value, Type: kind}), nil
		}
		return nil, apierr.New("scim_no_target", "SCIM email type does not match an address")
	}
	result[index].Value = addresses[0].Value
	return result, nil
}
