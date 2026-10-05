package security

import "github.com/lestrrat-go/jwx/v3/jwk"

// JWKSet validates that the signing key can be represented by the mandated jwx
// implementation and returns the standards-compatible public set.
func (s *Signer) JWKSet() (jwk.Set, error) {
	key, err := jwk.Import(s.public)
	if err != nil {
		return nil, err
	}
	_ = key.Set(jwk.KeyIDKey, s.keyID)
	_ = key.Set(jwk.AlgorithmKey, "ES256")
	_ = key.Set(jwk.KeyUsageKey, "sig")
	set := jwk.NewSet()
	if err := set.AddKey(key); err != nil {
		return nil, err
	}
	return set, nil
}
