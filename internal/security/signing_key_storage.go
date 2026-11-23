package security

import (
	"crypto/x509"
	"errors"
)

type EncryptedSigningKey struct {
	KID        string
	Issuer     string
	Ciphertext []byte
	Status     KeyStatus
}

func signingKeyStorageScope(issuer, kid string) []byte {
	return []byte("plystra-auth:signing-key:v1\x00" + kid + "\x00" + issuer)
}

// SealActiveSigningKey captures the active key without exposing a plaintext
// export to the database or its callers.
func (s *Signer) SealActiveSigningKey(encryptionKey []byte) (EncryptedSigningKey, error) {
	if len(encryptionKey) != 32 {
		return EncryptedSigningKey{}, errors.New("signing key encryption key must be 32 bytes")
	}
	s.mu.RLock()
	kid, key := s.keyID, s.private
	s.mu.RUnlock()
	if kid == "" || key == nil {
		return EncryptedSigningKey{}, ErrNoActiveSigningKey
	}
	plain, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return EncryptedSigningKey{}, err
	}
	defer clear(plain)
	ciphertext, err := encryptSigningKey(plain, encryptionKey, signingKeyStorageScope(s.issuer, kid))
	if err != nil {
		return EncryptedSigningKey{}, err
	}
	return EncryptedSigningKey{KID: kid, Issuer: s.issuer, Ciphertext: ciphertext, Status: KeyActive}, nil
}

func RestoreSigningKeys(issuer string, encryptionKey []byte, records []EncryptedSigningKey) (*Signer, error) {
	if len(encryptionKey) != 32 {
		return nil, errors.New("signing key encryption key must be 32 bytes")
	}
	signer := &Signer{issuer: issuer, keys: make(map[string]signingKey, len(records))}
	var staged bool
	for _, record := range records {
		if record.Issuer != issuer {
			return nil, errors.New("stored signing keys belong to a different issuer")
		}
		if _, exists := signer.keys[record.KID]; exists {
			return nil, errors.New("duplicate stored signing key ID")
		}
		key, err := restoreSigningKey(record, encryptionKey)
		if err != nil {
			return nil, err
		}
		switch record.Status {
		case KeyActive:
			if signer.keyID != "" {
				return nil, errors.New("multiple active signing keys")
			}
			signer.keyID, signer.private, signer.public = record.KID, key.private, key.public
		case KeyNext:
			if staged {
				return nil, errors.New("multiple staged signing keys")
			}
			staged = true
		case KeyRetiring:
			key.private = nil
		default:
			return nil, errors.New("invalid stored signing key status")
		}
		signer.keys[record.KID] = key
	}
	if signer.private == nil {
		return nil, ErrNoActiveSigningKey
	}
	return signer, nil
}

func restoreSigningKey(record EncryptedSigningKey, encryptionKey []byte) (signingKey, error) {
	plain, err := decryptSigningKey(record.Ciphertext, encryptionKey, signingKeyStorageScope(record.Issuer, record.KID))
	if err != nil {
		return signingKey{}, err
	}
	defer clear(plain)
	key, err := parseSigningKey(plain)
	if err != nil {
		return signingKey{}, err
	}
	kid, err := signingKeyID(&key.PublicKey)
	if err != nil {
		return signingKey{}, err
	}
	if kid != record.KID {
		return signingKey{}, errors.New("stored signing key does not match its key ID")
	}
	return signingKey{private: key, public: &key.PublicKey, status: record.Status}, nil
}
