package security

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/plystra/auth/internal/secret"
)

func TestHumanIDTokenVerifiesAtRelyingPartyThroughKeyRotation(t *testing.T) {
	signer, err := GenerateSigner("https://issuer.example.test")
	if err != nil {
		t.Fatal(err)
	}
	keys := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		set, err := signer.JWKS()
		if err != nil {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(set)
	}))
	t.Cleanup(keys.Close)
	ctx := oidc.ClientContext(t.Context(), keys.Client())
	now := time.Now().UTC().Truncate(time.Second)
	in := HumanIDToken{UserID: "usr_oidc_account", ClientID: "app_relying_party", Nonce: secret.New("MixedCase-1_2"), IssuedAt: now, ExpiresAt: now.Add(time.Minute)}
	verify := func(raw secret.String, issuer, clientID string, at time.Time) (*oidc.IDToken, error) {
		cfg := &oidc.Config{ClientID: clientID, SupportedSigningAlgs: []string{oidc.ES256}, Now: func() time.Time { return at }}
		return oidc.NewVerifier(issuer, oidc.NewRemoteKeySet(ctx, keys.URL), cfg).Verify(ctx, raw.Value())
	}
	first, err := signer.SignHumanIDToken(in)
	if err != nil {
		t.Fatal(err)
	}
	firstKid := jwtHeaderKid(t, first.Value())
	nextKid, err := signer.StageNext()
	if err != nil {
		t.Fatal(err)
	}
	if err := signer.PromoteNext(); err != nil {
		t.Fatal(err)
	}
	second, err := signer.SignHumanIDToken(in)
	if err != nil || jwtHeaderKid(t, second.Value()) != nextKid || firstKid == nextKid {
		t.Fatal("new ID token did not use the promoted key")
	}
	for _, raw := range []secret.String{first, second} {
		token, err := verify(raw, signer.Issuer(), in.ClientID, now)
		if err != nil {
			t.Fatal("relying party rejected a current ID token")
		}
		if token.Subject != string(in.UserID) || token.Nonce != in.Nonce.Value() || token.Issuer != signer.Issuer() ||
			!slices.Equal(token.Audience, []string{in.ClientID}) || !token.IssuedAt.Equal(in.IssuedAt) || !token.Expiry.Equal(in.ExpiresAt) {
			t.Fatal("verified token lost the human login binding")
		}
		var fields map[string]json.RawMessage
		if err := token.Claims(&fields); err != nil || len(fields) != 6 {
			t.Fatal("unexpected claims in human ID token")
		}
		header, err := base64.RawURLEncoding.DecodeString(strings.SplitN(raw.Value(), ".", 2)[0])
		var protected struct{ Alg, Typ, Kid string }
		if err != nil || json.Unmarshal(header, &protected) != nil || protected.Alg != "ES256" || protected.Typ != "JWT" || protected.Kid == "" {
			t.Fatal("invalid protected ID token headers")
		}
		if _, err := signer.Verify(raw.Value(), now, in.ClientID); err == nil {
			t.Fatal("access-token verifier accepted an ID token")
		}
	}
	if _, err := verify(second, signer.Issuer(), "other-client", now); err == nil {
		t.Fatal("ID token verified for another relying party")
	}
	if _, err := verify(second, "https://other.example.test", in.ClientID, now); err == nil {
		t.Fatal("ID token verified for another issuer")
	}
	if _, err := verify(second, signer.Issuer(), in.ClientID, in.ExpiresAt.Add(time.Second)); err == nil {
		t.Fatal("relying party accepted an expired token")
	}
	if err := signer.DropRetiring(firstKid); err != nil {
		t.Fatal(err)
	}
	if _, err := verify(first, signer.Issuer(), in.ClientID, now); err == nil {
		t.Fatal("fresh JWKS lookup still trusted the removed key")
	}
}

func TestHumanIDTokenRequiresAccountClientNonceAndValidLifetime(t *testing.T) {
	signer, err := GenerateSigner("https://issuer.example.test")
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	valid := HumanIDToken{UserID: "usr_oidc_account", ClientID: "app_client", Nonce: secret.New("nonce"), IssuedAt: now, ExpiresAt: now.Add(time.Minute)}
	for name, change := range map[string]func(*HumanIDToken){
		"agent":          func(in *HumanIDToken) { in.UserID = "mem_agent" },
		"missing user":   func(in *HumanIDToken) { in.UserID = "" },
		"missing client": func(in *HumanIDToken) { in.ClientID = "" },
		"missing nonce":  func(in *HumanIDToken) { in.Nonce = "" },
		"invalid nonce":  func(in *HumanIDToken) { in.Nonce = secret.New(string([]byte{0xff})) },
		"missing iat":    func(in *HumanIDToken) { in.IssuedAt = time.Time{} },
		"empty lifetime": func(in *HumanIDToken) { in.ExpiresAt = in.IssuedAt.Add(time.Millisecond) },
	} {
		t.Run(name, func(t *testing.T) {
			in := valid
			change(&in)
			if raw, err := signer.SignHumanIDToken(in); err == nil || raw.Value() != "" {
				t.Fatal("invalid claim set yielded an ID token")
			}
		})
	}
}
