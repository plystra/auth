package security

import (
	"errors"
	"time"
	"unicode/utf8"

	"github.com/plystra/auth/internal/ids"
	"github.com/plystra/auth/internal/secret"
)

// HumanIDToken identifies the authenticated account to the client that obtained
// consent. Keep its claims separate from the credentials used to call APIs.
type HumanIDToken struct {
	UserID    ids.UserID
	ClientID  string
	Nonce     secret.String
	IssuedAt  time.Time
	ExpiresAt time.Time
}

func (s *Signer) SignHumanIDToken(in HumanIDToken) (secret.String, error) {
	if s == nil {
		return "", ErrNoActiveSigningKey
	}
	if s.issuer == "" || !in.UserID.Valid() || in.ClientID == "" || in.Nonce.Value() == "" ||
		!utf8.ValidString(string(in.UserID)) || !utf8.ValidString(in.ClientID) || !utf8.ValidString(in.Nonce.Value()) ||
		in.IssuedAt.Unix() <= 0 || in.ExpiresAt.Unix() <= in.IssuedAt.Unix() {
		return "", errors.New("invalid human ID token claims")
	}
	claims := struct {
		Issuer    string     `json:"iss"`
		Subject   ids.UserID `json:"sub"`
		Audience  string     `json:"aud"`
		IssuedAt  int64      `json:"iat"`
		ExpiresAt int64      `json:"exp"`
		Nonce     string     `json:"nonce"`
	}{
		Issuer: s.issuer, Subject: in.UserID, Audience: in.ClientID,
		IssuedAt: in.IssuedAt.Unix(), ExpiresAt: in.ExpiresAt.Unix(), Nonce: in.Nonce.Value(),
	}
	token, err := s.signJWT("JWT", claims)
	return secret.New(token), err
}
