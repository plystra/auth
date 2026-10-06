package security

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
	"strings"
	"time"
)

type Claims struct {
	Issuer    string   `json:"iss"`
	Subject   string   `json:"sub"`
	MemberID  string   `json:"mid,omitempty"`
	SpaceID   string   `json:"spc,omitempty"`
	Audience  string   `json:"aud"`
	ExpiresAt int64    `json:"exp"`
	IssuedAt  int64    `json:"iat"`
	JWTID     string   `json:"jti"`
	SessionID string   `json:"sid"`
	Assurance int      `json:"aal"`
	AMR       []string `json:"amr"`
	Actor     string   `json:"act,omitempty"`
	Type      string   `json:"typ,omitempty"`
	Scopes    []string `json:"scp,omitempty"`
}

const DefaultApplicationAudience = "default"

type Signer struct {
	private *ecdsa.PrivateKey
	public  *ecdsa.PublicKey
	issuer  string
	keyID   string
}

func NewSigner(pemFile, issuer string) (*Signer, error) {
	data, err := os.ReadFile(pemFile)
	if err != nil {
		return nil, fmt.Errorf("signing key: %w", err)
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, errors.New("invalid signing key PEM")
	}
	var key *ecdsa.PrivateKey
	if k, e := x509.ParsePKCS8PrivateKey(block.Bytes); e == nil {
		key, _ = k.(*ecdsa.PrivateKey)
	}
	if key == nil {
		if k, e := x509.ParseECPrivateKey(block.Bytes); e == nil {
			key = k
		}
	}
	if key == nil {
		return nil, errors.New("signing key is not EC private key")
	}
	if key.Curve != elliptic.P256() {
		return nil, errors.New("signing key must be P-256")
	}
	publicBytes, err := key.PublicKey.Bytes()
	if err != nil {
		return nil, fmt.Errorf("encode signing public key: %w", err)
	}
	sum := sha256.Sum256(publicBytes)
	return &Signer{private: key, public: &key.PublicKey, issuer: issuer, keyID: fmt.Sprintf("%x", sum[:8])}, nil
}
func GenerateSigner(issuer string) (*Signer, error) {
	key, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if e != nil {
		return nil, e
	}
	return &Signer{private: key, public: &key.PublicKey, issuer: issuer, keyID: "dev"}, nil
}
func (s *Signer) Sign(c Claims) (string, error) {
	header := map[string]string{"alg": "ES256", "kid": s.keyID, "typ": "at+jwt"}
	h, _ := json.Marshal(header)
	payload, _ := json.Marshal(c)
	enc := func(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }
	input := enc(h) + "." + enc(payload)
	hash := sha256.Sum256([]byte(input))
	r, ss, e := ecdsa.Sign(rand.Reader, s.private, hash[:])
	if e != nil {
		return "", e
	}
	sig := make([]byte, 64)
	rb, sb := r.Bytes(), ss.Bytes()
	copy(sig[32-len(rb):32], rb)
	copy(sig[64-len(sb):], sb)
	return input + "." + enc(sig), nil
}
func (s *Signer) Verify(token string, now time.Time, audience string) (Claims, error) {
	var c Claims
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return c, errors.New("invalid token")
	}
	headerRaw, e := base64.RawURLEncoding.DecodeString(parts[0])
	if e != nil {
		return c, errors.New("invalid header")
	}
	var header struct {
		Alg string `json:"alg"`
		Typ string `json:"typ"`
	}
	if json.Unmarshal(headerRaw, &header) != nil || header.Alg != "ES256" || header.Typ != "at+jwt" {
		return c, errors.New("invalid token header")
	}
	raw, e := base64.RawURLEncoding.DecodeString(parts[1])
	if e != nil {
		return c, errors.New("invalid payload")
	}
	if json.Unmarshal(raw, &c) != nil {
		return c, errors.New("invalid claims")
	}
	if c.Issuer != s.issuer || c.Audience != audience || c.ExpiresAt <= now.Unix() || c.Subject == "" || (c.Type != "user" && c.Type != "agent") {
		return c, errors.New("token claims rejected")
	}
	sig, e := base64.RawURLEncoding.DecodeString(parts[2])
	if e != nil || len(sig) != 64 {
		return c, errors.New("invalid signature")
	}
	hash := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	ok := ecdsa.Verify(s.public, hash[:], new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:]))
	if !ok {
		return c, errors.New("invalid signature")
	}
	return c, nil
}
func (s *Signer) JWKS() (map[string]any, error) {
	publicBytes, err := s.public.Bytes()
	if err != nil {
		return nil, fmt.Errorf("encode signing public key: %w", err)
	}
	if len(publicBytes) != 65 || publicBytes[0] != 4 {
		return nil, errors.New("invalid P-256 public key encoding")
	}
	return map[string]any{"keys": []any{map[string]string{"kty": "EC", "crv": "P-256", "x": base64.RawURLEncoding.EncodeToString(publicBytes[1:33]), "y": base64.RawURLEncoding.EncodeToString(publicBytes[33:]), "use": "sig", "alg": "ES256", "kid": s.keyID}}}, nil
}

func (s *Signer) Issuer() string { return s.issuer }
