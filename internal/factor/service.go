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
	"time"

	"github.com/plystra/auth/internal/db"
	"github.com/plystra/auth/internal/ids"
	"github.com/plystra/auth/internal/secret"
	"github.com/plystra/auth/internal/store"
	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
)

type Service struct {
	Store   *store.Store
	DataKey secret.String
}
type Enrollment struct {
	FactorID string        `json:"factor_id"`
	Secret   secret.String `json:"secret"`
	URI      string        `json:"otpauth_uri"`
}

var ErrInvalidCode = errors.New("invalid one-time code")

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
	var enrollment Enrollment
	e = s.Store.InTx(ctx, func(q *db.Queries) error {
		var err error
		enrollment, err = s.beginTOTPWithQueries(ctx, q, userID, key.Secret(), key.URL(), blob)
		return err
	})
	return enrollment, e
}

// BeginTOTPTx is used by bootstrap flows that must create the operator and
// its mandatory MFA factor atomically.
func (s *Service) BeginTOTPTx(ctx context.Context, q *db.Queries, userID, email string) (Enrollment, error) {
	key, err := totp.Generate(totp.GenerateOpts{Issuer: "Plystra Auth", AccountName: email, Period: 30, SecretSize: 20})
	if err != nil {
		return Enrollment{}, err
	}
	a, err := s.cipher()
	if err != nil {
		return Enrollment{}, err
	}
	blob, err := seal(a, []byte(key.Secret()))
	if err != nil {
		return Enrollment{}, err
	}
	return s.beginTOTPWithQueries(ctx, q, userID, key.Secret(), key.URL(), blob)
}

func (s *Service) beginTOTPWithQueries(ctx context.Context, q *db.Queries, userID, raw, uri string, blob []byte) (Enrollment, error) {
	id := ids.New[ids.FactorID]("fac")
	if _, err := q.CreateFactor(ctx, db.CreateFactorParams{ID: string(id), UserID: userID, Kind: "totp", Name: "authenticator", SecretCiphertext: blob}); err != nil {
		return Enrollment{}, err
	}
	return Enrollment{FactorID: string(id), Secret: secret.New(raw), URI: uri}, nil
}
func (s *Service) VerifyTOTP(ctx context.Context, userID, factorID, code string) error {
	return s.Store.InTx(ctx, func(q *db.Queries) error {
		return s.VerifyTOTPTx(ctx, q, userID, factorID, code, time.Now().UTC())
	})
}

// VerifyTOTPTx consumes the time step while holding factor locks so concurrent
// requests cannot reuse a code, including across login and step-up.
func (s *Service) VerifyTOTPTx(ctx context.Context, q *db.Queries, userID, factorID, code string, now time.Time) error {
	if len(code) != 6 || strings.Trim(code, "0123456789") != "" {
		return ErrInvalidCode
	}
	rows, err := q.LockTOTPFactors(ctx, db.LockTOTPFactorsParams{UserID: userID})
	if err != nil {
		return err
	}
	a, err := s.cipher()
	if err != nil {
		return err
	}
	for _, f := range rows {
		if factorID != "" && f.ID != factorID {
			continue
		}
		raw, err := open(a, f.SecretCiphertext)
		if err != nil {
			return err
		}
		// Match the exact step, rather than resetting the counter after validation.
		for _, offset := range []int64{0, -1, 1} {
			step := now.Unix()/30 + offset
			if step <= f.Counter {
				continue
			}
			valid, err := totp.ValidateCustom(code, string(raw), time.Unix(step*30, 0),
				totp.ValidateOpts{Period: 30, Skew: 0, Digits: otp.DigitsSix, Algorithm: otp.AlgorithmSHA1})
			if err != nil {
				clear(raw)
				return err
			}
			if valid {
				clear(raw)
				_, err = q.ConsumeTOTPStep(ctx, db.ConsumeTOTPStepParams{ID: f.ID, Step: step})
				return err
			}
		}
		clear(raw)
	}
	return ErrInvalidCode
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
