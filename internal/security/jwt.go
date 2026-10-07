package security

import (
	"crypto/aes"
	"crypto/cipher"
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
	"sort"
	"strings"
	"sync"
	"time"
)

type Claims struct {
	Issuer    string      `json:"iss"`
	Subject   string      `json:"sub"`
	MemberID  string      `json:"mid,omitempty"`
	SpaceID   string      `json:"spc,omitempty"`
	Audience  string      `json:"aud"`
	ExpiresAt int64       `json:"exp"`
	IssuedAt  int64       `json:"iat"`
	JWTID     string      `json:"jti"`
	SessionID string      `json:"sid"`
	Assurance int         `json:"aal"`
	AMR       []string    `json:"amr"`
	Actor     *ActorClaim `json:"act,omitempty"`
	Type      string      `json:"typ,omitempty"`
	Scopes    []string    `json:"scp,omitempty"`
}

// ActorClaim records the member that delegated an Agent token and recursively
// preserves the owner chain. It intentionally contains identifiers and types,
// never credentials or user-controlled display data.
type ActorClaim struct {
	Subject  string      `json:"sub"`
	MemberID string      `json:"mid,omitempty"`
	Type     string      `json:"typ,omitempty"`
	Actor    *ActorClaim `json:"act,omitempty"`
}

const DefaultApplicationAudience = "default"

var ErrNoActiveSigningKey = errors.New("no active signing key")

type KeyStatus string

const (
	KeyNext     KeyStatus = "next"
	KeyActive   KeyStatus = "active"
	KeyRetiring KeyStatus = "retiring"
)

type signingKey struct {
	private *ecdsa.PrivateKey
	public  *ecdsa.PublicKey
	status  KeyStatus
}

type Signer struct {
	mu      sync.RWMutex
	private *ecdsa.PrivateKey
	public  *ecdsa.PublicKey
	issuer  string
	keyID   string
	keys    map[string]signingKey
}

const encryptedSigningKeyPEMType = "PLYSTRA AUTH ENCRYPTED SIGNING KEY"

// NewSigner loads an ES256 private key from an AES-GCM encrypted PEM file.
// The encryption key is deliberately separate from the data key used for
// user factors so compromise of one key does not unwrap the other secret.
func NewSigner(pemFile, issuer string, encryptionKey []byte) (*Signer, error) {
	if len(encryptionKey) != 32 {
		return nil, errors.New("signing key encryption key must be 32 bytes")
	}
	data, err := os.ReadFile(pemFile)
	if err != nil {
		return nil, fmt.Errorf("signing key: %w", err)
	}
	block, _ := pem.Decode(data)
	if block == nil || block.Type != encryptedSigningKeyPEMType {
		return nil, errors.New("signing key must be an encrypted PEM")
	}
	plain, err := decryptSigningKey(block.Bytes, encryptionKey)
	if err != nil {
		return nil, fmt.Errorf("decrypt signing key: %w", err)
	}
	var key *ecdsa.PrivateKey
	if k, e := x509.ParsePKCS8PrivateKey(plain); e == nil {
		key, _ = k.(*ecdsa.PrivateKey)
	}
	if key == nil {
		if k, e := x509.ParseECPrivateKey(plain); e == nil {
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
	return newSigner(key, issuer, fmt.Sprintf("%x", sum[:8])), nil
}

// EncryptSigningKeyPEM serializes an ES256 private key into the encrypted PEM
// format accepted by NewSigner. It is intended for provisioning tooling and
// tests; callers must keep the returned bytes and encryption key secret.
func EncryptSigningKeyPEM(key *ecdsa.PrivateKey, encryptionKey []byte) ([]byte, error) {
	if key == nil {
		return nil, errors.New("signing key is nil")
	}
	if len(encryptionKey) != 32 {
		return nil, errors.New("signing key encryption key must be 32 bytes")
	}
	plain, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("marshal signing key: %w", err)
	}
	ciphertext, err := encryptSigningKey(plain, encryptionKey)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: encryptedSigningKeyPEMType, Bytes: ciphertext}), nil
}

func encryptSigningKey(plain, key []byte) ([]byte, error) {
	aead, err := signingKeyAEAD(key)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("generate signing key nonce: %w", err)
	}
	return aead.Seal(nonce, nonce, plain, nil), nil
}

func decryptSigningKey(ciphertext, key []byte) ([]byte, error) {
	aead, err := signingKeyAEAD(key)
	if err != nil {
		return nil, err
	}
	if len(ciphertext) < aead.NonceSize() {
		return nil, errors.New("encrypted signing key is truncated")
	}
	nonce, payload := ciphertext[:aead.NonceSize()], ciphertext[aead.NonceSize():]
	plain, err := aead.Open(nil, nonce, payload, nil)
	if err != nil {
		return nil, errors.New("encrypted signing key authentication failed")
	}
	return plain, nil
}

func signingKeyAEAD(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("signing key encryption cipher: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("signing key encryption mode: %w", err)
	}
	return aead, nil
}
func GenerateSigner(issuer string) (*Signer, error) {
	key, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if e != nil {
		return nil, e
	}
	publicBytes, err := key.PublicKey.Bytes()
	if err != nil {
		return nil, fmt.Errorf("encode signing public key: %w", err)
	}
	sum := sha256.Sum256(publicBytes)
	return newSigner(key, issuer, fmt.Sprintf("%x", sum[:8])), nil
}

func newSigner(key *ecdsa.PrivateKey, issuer, keyID string) *Signer {
	return &Signer{private: key, public: &key.PublicKey, issuer: issuer, keyID: keyID, keys: map[string]signingKey{keyID: {private: key, public: &key.PublicKey, status: KeyActive}}}
}

// StageNext generates a new signing key without changing the key used for new
// tokens. It is the first step of an operational rotation transaction.
func (s *Signer) StageNext() (string, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return "", err
	}
	publicBytes, err := key.PublicKey.Bytes()
	if err != nil {
		return "", fmt.Errorf("encode signing public key: %w", err)
	}
	sum := sha256.Sum256(publicBytes)
	kid := fmt.Sprintf("%x", sum[:8])
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.keys[kid]; exists {
		return "", errors.New("signing key id collision")
	}
	for existingID, existing := range s.keys {
		if existing.status == KeyNext {
			delete(s.keys, existingID)
		}
	}
	s.keys[kid] = signingKey{private: key, public: &key.PublicKey, status: KeyNext}
	return kid, nil
}

// PromoteNext makes the staged key active and retains the previous active key
// as retiring so tokens already issued during the overlap remain verifiable.
func (s *Signer) PromoteNext() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	var nextID string
	var next signingKey
	for id, key := range s.keys {
		if key.status == KeyNext {
			nextID, next = id, key
			break
		}
	}
	if nextID == "" {
		return errors.New("no staged signing key")
	}
	for id, key := range s.keys {
		if key.status == KeyActive {
			key.status = KeyRetiring
			s.keys[id] = key
		}
	}
	next.status = KeyActive
	s.keys[nextID] = next
	s.private, s.public, s.keyID = next.private, next.public, nextID
	return nil
}

// DropRetiring removes a retiring key after the maximum access-token lifetime
// has elapsed. Active and next keys cannot be removed through this method.
func (s *Signer) DropRetiring(kid string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	key, ok := s.keys[kid]
	if !ok || key.status != KeyRetiring {
		return errors.New("signing key is not retiring")
	}
	delete(s.keys, kid)
	return nil
}

func (s *Signer) Sign(c Claims) (string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
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
		Kid string `json:"kid"`
	}
	if json.Unmarshal(headerRaw, &header) != nil || header.Alg != "ES256" || header.Typ != "at+jwt" || header.Kid == "" {
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
	s.mu.RLock()
	key, ok := s.keys[header.Kid]
	s.mu.RUnlock()
	if !ok || (key.status != KeyActive && key.status != KeyRetiring) {
		return c, errors.New("unknown signing key")
	}
	hash := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	ok = ecdsa.Verify(key.public, hash[:], new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:]))
	if !ok {
		return c, errors.New("invalid signature")
	}
	return c, nil
}
func (s *Signer) JWKS() (map[string]any, error) {
	s.mu.RLock()
	ids := make([]string, 0, len(s.keys))
	for id, key := range s.keys {
		if key.status == KeyActive || key.status == KeyRetiring {
			ids = append(ids, id)
		}
	}
	sort.Strings(ids)
	keys := make([]any, 0, len(ids))
	for _, id := range ids {
		key := s.keys[id]
		jwk, err := publicJWK(key.public, id)
		if err != nil {
			s.mu.RUnlock()
			return nil, err
		}
		keys = append(keys, jwk)
	}
	s.mu.RUnlock()
	if len(keys) == 0 {
		return nil, errors.New("no active signing key")
	}
	return map[string]any{"keys": keys}, nil
}

func publicJWK(public *ecdsa.PublicKey, kid string) (map[string]string, error) {
	publicBytes, err := public.Bytes()
	if err != nil {
		return nil, fmt.Errorf("encode signing public key: %w", err)
	}
	if len(publicBytes) != 65 || publicBytes[0] != 4 {
		return nil, errors.New("invalid P-256 public key encoding")
	}
	return map[string]string{"kty": "EC", "crv": "P-256", "x": base64.RawURLEncoding.EncodeToString(publicBytes[1:33]), "y": base64.RawURLEncoding.EncodeToString(publicBytes[33:]), "use": "sig", "alg": "ES256", "kid": kid}, nil
}

func (s *Signer) Issuer() string { return s.issuer }
