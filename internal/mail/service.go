package mail

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"time"

	"github.com/plystra/auth/internal/db"
	"github.com/plystra/auth/internal/jobs"
	"github.com/plystra/auth/internal/secret"
)

type Sender interface {
	Send(context.Context, string, string, string) error
}

type Service struct {
	jobs   *jobs.Client
	sender Sender
	aead   cipher.AEAD
}

type delivery struct {
	Kind      string    `json:"kind"`
	To        string    `json:"to"`
	Token     string    `json:"token"`
	ExpiresAt time.Time `json:"expires_at"`
}

func New(dataKey secret.String, jobClient *jobs.Client, sender Sender) (*Service, error) {
	if len(dataKey.Value()) != 32 || jobClient == nil || sender == nil {
		return nil, errors.New("mail delivery requires a 32-byte data key, jobs, and SMTP sender")
	}
	key, err := hkdf.Key(sha256.New, []byte(dataKey.Value()), nil, "plystra-auth-email-delivery-v1", 32)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return &Service{jobs: jobClient, sender: sender, aead: aead}, nil
}

func (s *Service) EnqueueVerificationTx(ctx context.Context, q *db.Queries, to string, token secret.String, expiresAt time.Time) error {
	return s.enqueueTx(ctx, q, "email_verification", to, token, expiresAt)
}

func (s *Service) EnqueuePasswordResetTx(ctx context.Context, q *db.Queries, to string, token secret.String, expiresAt time.Time) error {
	return s.enqueueTx(ctx, q, "password_reset", to, token, expiresAt)
}

func (s *Service) enqueueTx(ctx context.Context, q *db.Queries, kind, to string, token secret.String, expiresAt time.Time) error {
	if s == nil || s.jobs == nil || s.aead == nil || s.sender == nil {
		return errors.New("mail delivery is not configured")
	}
	if to == "" || token.Value() == "" || !expiresAt.After(time.Now().UTC()) {
		return errors.New("email verification delivery is invalid")
	}
	plain, err := json.Marshal(delivery{Kind: kind, To: to, Token: token.Value(), ExpiresAt: expiresAt.UTC()})
	if err != nil {
		return err
	}
	nonce := make([]byte, s.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return err
	}
	ciphertext := s.aead.Seal(nonce, nonce, plain, []byte("plystra-auth-email-delivery-v1"))
	return s.jobs.InsertTx(ctx, q, jobs.EmailDeliveryArgs{Ciphertext: ciphertext})
}

func (s *Service) DeliverEmail(ctx context.Context, ciphertext []byte) error {
	if s == nil || s.aead == nil || s.sender == nil || len(ciphertext) <= s.aead.NonceSize() {
		return errors.New("email delivery payload is invalid")
	}
	nonceSize := s.aead.NonceSize()
	plain, err := s.aead.Open(nil, ciphertext[:nonceSize], ciphertext[nonceSize:], []byte("plystra-auth-email-delivery-v1"))
	if err != nil {
		return errors.New("email delivery payload authentication failed")
	}
	var payload delivery
	if err := json.Unmarshal(plain, &payload); err != nil {
		return errors.New("email delivery payload is invalid")
	}
	if payload.To == "" || payload.Token == "" {
		return errors.New("email delivery payload is invalid")
	}
	if !payload.ExpiresAt.After(time.Now().UTC()) {
		return nil
	}
	switch payload.Kind {
	case "email_verification":
		return s.sender.Send(ctx, payload.To, "Verify your Plystra Auth email", "Enter this verification token in Plystra Auth: "+payload.Token+"\n")
	case "password_reset":
		return s.sender.Send(ctx, payload.To, "Reset your Plystra Auth password", "Enter this password reset token in Plystra Auth: "+payload.Token+"\n")
	default:
		return errors.New("email delivery payload is invalid")
	}
}
