package protocol

import (
	"bytes"
	"encoding/json"
	"strings"

	"github.com/plystra/auth/internal/apierr"
	"github.com/plystra/auth/internal/enterprise"
)

func scimEmailsPatch(operation, path string, raw any) (enterprise.SCIMEmailPatch, error) {
	patch := enterprise.SCIMEmailPatch{Operation: operation}
	if strings.EqualFold(path, "emails") {
		if operation == "remove" {
			return patch, nil
		}
		if _, ok := raw.([]any); !ok {
			return patch, apierr.New("invalid_request", "SCIM emails must be an array")
		}
		data, err := json.Marshal(raw)
		if err != nil {
			return patch, apierr.New("invalid_request", "SCIM emails are invalid")
		}
		decoder := json.NewDecoder(bytes.NewReader(data))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&patch.Addresses); err != nil {
			return patch, apierr.New("invalid_request", "SCIM email fields are invalid")
		}
		return patch, nil
	}
	start, end := strings.IndexByte(path, '['), strings.LastIndexByte(path, ']')
	if start < 0 || end <= start || len(path) > 4096 {
		return patch, apierr.New("invalid_filter", "SCIM email filter requires equality on type")
	}
	attribute, comparison, literal := splitSCIMComparison(path[start+1 : end])
	selector, ok := decodeSCIMFilterValue(literal)
	if !ok || selector == "" || !strings.EqualFold(attribute, "type") || !strings.EqualFold(comparison, "eq") {
		return patch, apierr.New("invalid_filter", "SCIM email filter requires equality on type")
	}
	patch.Selector = selector
	suffix := path[end+1:]
	if operation == "remove" && suffix == "" {
		return patch, nil
	}
	value, ok := raw.(string)
	if !ok || operation == "remove" || !strings.EqualFold(suffix, ".value") {
		return patch, apierr.New("invalid_request", "SCIM email PATCH path or value is invalid")
	}
	patch.Addresses = []enterprise.SCIMEmail{{Value: value}}
	return patch, nil
}
