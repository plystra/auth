package invoicesaas

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/json"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jws"
	"github.com/lestrrat-go/jwx/v3/jwt"
	"github.com/plystra/auth/internal/apierr"
	"github.com/plystra/auth/internal/secret"
)

type keyCache struct {
	sync.Mutex
	keys              map[string]*ecdsa.PublicKey
	expires, lastMiss time.Time
}

func (c *AuthClient) authenticate(ctx context.Context, bearer string) (secret.String, string, error) {
	invalid := apierr.New("INVALID_TOKEN", "A valid SaaS access token is required.")
	if !strings.HasPrefix(bearer, "Bearer ") {
		return "", "", invalid
	}
	token := secret.New(strings.TrimPrefix(bearer, "Bearer "))
	if len(token.Value()) > 16384 || strings.Count(token.Value(), ".") != 2 {
		return "", "", invalid
	}
	message, err := jws.ParseString(token.Value())
	if err != nil || len(message.Signatures()) != 1 {
		return "", "", invalid
	}
	headers := message.Signatures()[0].ProtectedHeaders()
	algorithm, _ := headers.Algorithm()
	typ, _ := headers.Type()
	kid, _ := headers.KeyID()
	if algorithm != jwa.ES256() || typ != "at+jwt" || kid == "" || len(kid) > 128 {
		return "", "", invalid
	}
	if critical, exists := headers.Critical(); exists && len(critical) != 0 {
		return "", "", invalid
	}
	key, err := c.signingKey(ctx, kid)
	if err != nil {
		return "", "", err
	}
	if key == nil {
		return "", "", invalid
	}
	claims, err := jwt.ParseString(token.Value(), jwt.WithKey(jwa.ES256(), key), jwt.WithValidate(true),
		jwt.WithIssuer(c.config.Issuer), jwt.WithAudience(c.config.ClientID),
		jwt.WithRequiredClaim("exp"), jwt.WithRequiredClaim("iat"), jwt.WithRequiredClaim("sub"), jwt.WithRequiredClaim("jti"))
	if err != nil {
		return "", "", invalid
	}
	var kind, memberID string
	_ = claims.Get("typ", &kind)
	_ = claims.Get("mid", &memberID)
	subject, _ := claims.Subject()
	jwtID, _ := claims.JwtID()
	if subject == "" || memberID == "" || jwtID == "" || (kind != "agent" && kind != "user") {
		return "", "", invalid
	}
	return token, memberID, nil
}

func (c *AuthClient) signingKey(ctx context.Context, kid string) (*ecdsa.PublicKey, error) {
	c.keys.Lock()
	defer c.keys.Unlock()
	now := time.Now()
	if c.keys.keys != nil && now.Before(c.keys.expires) {
		if key := c.keys.keys[kid]; key != nil {
			return key, nil
		}
		// Bound refreshes triggered by attacker-controlled unknown key IDs.
		if now.Sub(c.keys.lastMiss) < time.Second {
			return nil, nil
		}
		c.keys.lastMiss = now
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, c.config.JWKSURL, nil)
	if err != nil {
		return nil, unavailable()
	}
	response, err := c.http.Do(request)
	if err != nil {
		return nil, unavailable()
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode != http.StatusOK {
		return nil, unavailable()
	}
	body, err := readBounded(response.Body)
	if err != nil {
		return nil, unavailable()
	}
	set := jwk.NewSet()
	if json.Unmarshal(body, set) != nil || set.Len() == 0 || set.Len() > 32 {
		return nil, unavailable()
	}
	keys := make(map[string]*ecdsa.PublicKey, set.Len())
	for i := 0; i < set.Len(); i++ {
		key, _ := set.Key(i)
		id, _ := key.KeyID()
		alg, _ := key.Algorithm()
		use, _ := key.KeyUsage()
		var public ecdsa.PublicKey
		if id == "" || keys[id] != nil || alg != jwa.ES256() || use != "sig" || key.Has("d") ||
			key.Validate() != nil || jwk.Export(key, &public) != nil || public.Curve != elliptic.P256() {
			return nil, unavailable()
		}
		keys[id] = &public
	}
	c.keys.keys, c.keys.expires = keys, now.Add(5*time.Minute)
	return keys[kid], nil
}
