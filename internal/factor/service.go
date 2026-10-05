package factor

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/plystra/auth/internal/db"
	"github.com/plystra/auth/internal/ids"
	"github.com/plystra/auth/internal/secret"
	"github.com/plystra/auth/internal/store"
	"github.com/pquerna/otp/totp"
)

type Service struct {
	Store   *store.Store
	DataKey secret.Secret
}
type Enrollment struct {
	FactorID string `json:"factor_id"`
	Secret   string `json:"secret"`
	URI      string `json:"otpauth_uri"`
}

func (s *Service) cipher() (cipher.AEAD, error) {
	key := []byte(s.DataKey.Value())
	if len(key) != 32 {
		return nil, errors.New("factor data key must be 32 bytes")
	}
	block, e := aes.NewCipher(key)
	if e != nil {
		return nil, e
	}
	return cipher.NewGCM(block)
}
func (s *Service) BeginTOTP(ctx context.Context, userID, email string) (Enrollment, error) {
	key, e := totp.Generate(totp.GenerateOpts{Issuer: "Plystra Auth", AccountName: email, Period: 30, SecretSize: 20})
	if e != nil {
		return Enrollment{}, e
	}
	a, e := s.cipher()
	if e != nil {
		return Enrollment{}, e
	}
	blob, e := seal(a, []byte(key.Secret()))
	if e != nil {
		return Enrollment{}, e
	}
	id := ids.New[ids.FactorID]("fac")
	_, e = s.Store.Queries().CreateFactor(ctx, db.CreateFactorParams{ID: string(id), UserID: userID, Kind: "totp", Name: "authenticator", SecretCiphertext: blob})
	if e != nil {
		return Enrollment{}, e
	}
	return Enrollment{FactorID: string(id), Secret: key.Secret(), URI: key.URL()}, nil
}
func (s *Service) VerifyTOTP(ctx context.Context, userID, factorID, code string) error {
	row, e := s.Store.Queries().ListFactors(ctx, db.ListFactorsParams{UserID: userID})
	if e != nil {
		return e
	}
	for _, f := range row {
		if f.ID != factorID || f.Kind != "totp" {
			continue
		}
		a, e := s.cipher()
		if e != nil {
			return e
		}
		raw, e := open(a, f.SecretCiphertext)
		if e != nil {
			return e
		}
		if !totp.Validate(strings.TrimSpace(code), string(raw)) {
			return errors.New("invalid one-time code")
		}
		return s.Store.InTx(ctx, func(q *db.Queries) error {
			return q.TouchFactor(ctx, db.TouchFactorParams{ID: f.ID, UserID: userID, Counter: pgtype.Int8{Int64: 0, Valid: true}})
		})
	}
	return errors.New("factor not found")
}
func (s *Service) GenerateBackupCodes(count int) ([]string, error) {
	if count < 5 || count > 20 {
		return nil, errors.New("backup code count must be between 5 and 20")
	}
	out := make([]string, count)
	for i := range out {
		b := make([]byte, 10)
		if _, e := io.ReadFull(rand.Reader, b); e != nil {
			return nil, e
		}
		out[i] = strings.ToUpper(base64.RawURLEncoding.EncodeToString(b)[:12])
	}
	return out, nil
}
func BackupCodeDigest(code string) []byte {
	sum := sha256.Sum256([]byte(strings.ToUpper(strings.TrimSpace(code))))
	return sum[:]
}
func seal(a cipher.AEAD, plain []byte) ([]byte, error) {
	nonce := make([]byte, a.NonceSize())
	if _, e := io.ReadFull(rand.Reader, nonce); e != nil {
		return nil, e
	}
	return a.Seal(nonce, nonce, plain, nil), nil
}
func open(a cipher.AEAD, blob []byte) ([]byte, error) {
	if len(blob) < a.NonceSize() {
		return nil, fmt.Errorf("ciphertext too short")
	}
	return a.Open(nil, blob[:a.NonceSize()], blob[a.NonceSize():], nil)
}
