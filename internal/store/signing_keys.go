package store

import (
	"context"
	"fmt"

	"github.com/plystra/auth/internal/db"
	"github.com/plystra/auth/internal/security"
)

// InitializeSigningKeys seeds a pristine database once and loads its
// authoritative ring. Concurrent starters use the same committed active key.
func (s *Store) InitializeSigningKeys(ctx context.Context, seed *security.Signer, encryptionKey []byte) (*security.Signer, error) {
	key, err := seed.SealActiveSigningKey(encryptionKey)
	if err != nil {
		return nil, err
	}
	var signer *security.Signer
	err = s.InTx(ctx, func(q *db.Queries) error {
		if err := q.InitializeSigningKey(ctx, db.InitializeSigningKeyParams{
			Kid: key.KID, Issuer: key.Issuer, PrivateKeyCiphertext: key.Ciphertext,
		}); err != nil {
			return err
		}
		signer, err = LoadSigningKeys(ctx, q, seed.Issuer(), encryptionKey)
		return err
	})
	if err != nil {
		return nil, fmt.Errorf("load stored signing keys: %w", err)
	}
	return signer, nil
}

// LoadSigningKeys reads one committed ring, or the current transaction's view
// when called as part of credential issuance or authorization.
func LoadSigningKeys(ctx context.Context, q *db.Queries, issuer string, encryptionKey []byte) (*security.Signer, error) {
	rows, err := q.ListSigningKeys(ctx)
	if err != nil {
		return nil, err
	}
	records := make([]security.EncryptedSigningKey, 0, len(rows))
	for _, row := range rows {
		records = append(records, security.EncryptedSigningKey{
			KID: row.Kid, Issuer: row.Issuer, Ciphertext: row.PrivateKeyCiphertext, Status: security.KeyStatus(row.Status),
		})
	}
	return security.RestoreSigningKeys(issuer, encryptionKey, records)
}
