package stepup

import (
	"crypto/sha256"
	"encoding/json"

	"github.com/plystra/auth/internal/apierr"
)

// Digest canonicalizes JSON by decoding and re-encoding it before hashing.
// This makes insignificant whitespace and object-key ordering irrelevant while
// keeping the exact request content bound to the step-up proof.
func Digest(raw json.RawMessage) ([]byte, error) {
	var value any
	if err := json.Unmarshal(raw, &value); err != nil {
		return nil, apierr.New("VALIDATION_FAILED", "request must contain valid JSON")
	}
	return DigestValue(value)
}

func DigestValue(value any) ([]byte, error) {
	raw, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	var canonical any
	if err := json.Unmarshal(raw, &canonical); err != nil {
		return nil, apierr.New("VALIDATION_FAILED", "request must contain valid JSON")
	}
	raw, err = json.Marshal(canonical)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(raw)
	return sum[:], nil
}
