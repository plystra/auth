package security

import (
	"sort"

	"github.com/lestrrat-go/jwx/v3/jwk"
)

// JWKSet validates that the signing key can be represented by the mandated jwx
// implementation and returns the standards-compatible public set.
func (s *Signer) JWKSet() (jwk.Set, error) {
	s.mu.RLock()
	ids := make([]string, 0, len(s.keys))
	for id, signingKey := range s.keys {
		if signingKey.status == KeyActive || signingKey.status == KeyRetiring {
			ids = append(ids, id)
		}
	}
	sort.Strings(ids)
	set := jwk.NewSet()
	for _, id := range ids {
		key, err := jwk.Import(s.keys[id].public)
		if err != nil {
			s.mu.RUnlock()
			return nil, err
		}
		_ = key.Set(jwk.KeyIDKey, id)
		_ = key.Set(jwk.AlgorithmKey, "ES256")
		_ = key.Set(jwk.KeyUsageKey, "sig")
		if err := set.AddKey(key); err != nil {
			s.mu.RUnlock()
			return nil, err
		}
	}
	s.mu.RUnlock()
	if len(ids) == 0 {
		return nil, ErrNoActiveSigningKey
	}
	return set, nil
}
