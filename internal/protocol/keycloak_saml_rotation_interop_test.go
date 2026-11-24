//go:build interop

package protocol

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/plystra/auth/internal/enterprise"
	"github.com/plystra/auth/internal/factor"
	"github.com/plystra/auth/internal/secret"
	"github.com/pquerna/otp/totp"
	"golang.org/x/oauth2"
)

type keycloakSigningKey struct {
	KID         string `json:"kid"`
	ProviderID  string `json:"providerId"`
	Certificate string `json:"certificate"`
}

type keycloakKeyProvider struct {
	ID           string              `json:"id,omitempty"`
	ParentID     string              `json:"parentId"`
	Name         string              `json:"name"`
	ProviderID   string              `json:"providerId"`
	ProviderType string              `json:"providerType"`
	Config       map[string][]string `json:"config"`
}

func (a keycloakAdmin) signingKeys(t *testing.T) (keycloakSigningKey, []keycloakSigningKey) {
	t.Helper()
	var shows struct {
		Active map[string]string
		Keys   []keycloakSigningKey
	}
	a.call(t, http.MethodGet, "/keys", nil, &shows, http.StatusOK)
	active := shows.Active["RS256"]
	for _, key := range shows.Keys {
		if active != "" && key.KID == active && key.Certificate != "" && key.ProviderID != "" {
			return key, shows.Keys
		}
	}
	t.Fatal("Keycloak did not publish its active RSA signing key")
	return keycloakSigningKey{}, nil
}

func verifyKeycloakSAMLRotation(t *testing.T, rp *humanRP, admin keycloakAdmin, issuer string, transport *http.Transport, spaceID string, connection enterprise.Connection, login func(), priorAccess string) {
	t.Helper()
	oldBrowser := newOIDCBrowser(t, rp)
	oldPath := oldBrowser.beginFromAuthorization(t, oauth2.GenerateVerifier(), oauth2.GenerateVerifier(), oauth2.GenerateVerifier())
	identified, _ := oldBrowser.request(t, http.MethodPost, oldPath+"/identify", map[string]string{
		"email": "original@workforce.example.test", "method": "password",
	}, rp.host.URL, "", http.StatusOK)
	keycloakSAMLCallback(t, rp, transport, issuer, connection.RedirectURI, oldPath, identified)

	original, _ := admin.signingKeys(t)
	var realm struct{ ID string }
	admin.call(t, http.MethodGet, "", nil, &realm, http.StatusOK)
	if realm.ID == "" {
		t.Fatal("the disposable Keycloak realm has no identifier")
	}
	nextProvider := keycloakKeyProvider{
		ParentID: realm.ID, Name: "rollover-fixture", ProviderID: "rsa-generated",
		ProviderType: "org.keycloak.keys.KeyProvider",
		Config: map[string][]string{
			"priority": {"1000"}, "enabled": {"true"}, "active": {"false"},
			"algorithm": {"RS256"}, "keySize": {"2048"},
		},
	}
	location, err := url.Parse(admin.call(t, http.MethodPost, "/components", nextProvider, nil, http.StatusCreated))
	if err != nil {
		t.Fatal("Keycloak did not identify the new key provider")
	}
	_, nextProvider.ID, _ = strings.Cut(location.Path, "/components/")
	if nextProvider.ID == "" || strings.Contains(nextProvider.ID, "/") {
		t.Fatal("Keycloak returned an invalid key provider identifier")
	}
	nextPath := "/components/" + url.PathEscape(nextProvider.ID)
	active, keys := admin.signingKeys(t)
	var successor keycloakSigningKey
	for _, key := range keys {
		if key.ProviderID == nextProvider.ID {
			successor = key
			break
		}
	}
	if active.KID != original.KID || successor.KID == "" || successor.KID == original.KID || successor.Certificate == "" {
		t.Fatal("Keycloak did not publish a distinct standby certificate while keeping the original signer")
	}

	rp.workforce.Sessions.Factors = &factor.Service{Store: rp.st, DataKey: secret.New(strings.Repeat("d", 32))}
	enrollment, err := rp.workforce.Sessions.Factors.BeginTOTP(t.Context(), "usr_human_rp", "rp@example.test")
	if err != nil {
		t.Fatal(err)
	}
	client := employeeLifecycleClient{server: rp.host}
	management := "/v1/spaces/" + spaceID + "/sso-connections/" + connection.ID
	tag, previousTOTP := connection.ETag(), int64(-1)
	importMetadata := func(metadata string) {
		t.Helper()
		now := time.Now().UTC()
		period := now.Unix() / 30
		if period == previousTOTP {
			timer := time.NewTimer(time.Until(time.Unix((period+1)*30, 0)))
			defer timer.Stop()
			select {
			case <-t.Context().Done():
				t.Fatal("waiting for the next TOTP period was canceled")
			case <-timer.C:
			}
			now = time.Now().UTC()
			period = now.Unix() / 30
		}
		mfa, err := totp.GenerateCode(enrollment.Secret.Value(), now)
		if err != nil {
			t.Fatal(err)
		}
		previousTOTP = period
		const jsonType = "application/json"
		client.send(t, http.MethodPost, "/v1/auth/step-up", rp.session.AccessToken, jsonType, "", map[string]any{
			"operation": enterprise.SSOConnectionUpdateOperation, "mfa_code": mfa,
			"request": enterprise.SAMLMetadataUpdateRequest(spaceID, connection.ID, tag, metadata),
		}).requireStatus(t, http.StatusOK)
		updated := client.send(t, http.MethodPatch, management, rp.session.AccessToken, jsonType, tag, map[string]string{
			"saml_metadata": metadata,
		})
		updated.requireStatus(t, http.StatusOK)
		if updated.etag == "" || updated.etag == tag {
			t.Fatal("the online metadata update did not return a new ETag")
		}
		tag = updated.etag
	}

	overlap := fetchKeycloakSAMLMetadata(t, admin.client, issuer)
	overlapCerts := strings.Join(strings.Fields(overlap), "")
	if !strings.Contains(overlapCerts, original.Certificate) || !strings.Contains(overlapCerts, successor.Certificate) {
		t.Fatal("the IdP metadata did not publish both signing certificates")
	}
	importMetadata(overlap)
	admin.call(t, http.MethodGet, nextPath, nil, &nextProvider, http.StatusOK)
	nextProvider.Config["active"] = []string{"true"}
	admin.call(t, http.MethodPut, nextPath, nextProvider, nil, http.StatusNoContent)
	if current, _ := admin.signingKeys(t); current.KID != successor.KID {
		t.Fatal("Keycloak did not elect the replacement signing key")
	}
	login()

	oldProviderPath := "/components/" + url.PathEscape(original.ProviderID)
	var oldProvider keycloakKeyProvider
	admin.call(t, http.MethodGet, oldProviderPath, nil, &oldProvider, http.StatusOK)
	oldProvider.Config["enabled"] = []string{"false"}
	admin.call(t, http.MethodPut, oldProviderPath, oldProvider, nil, http.StatusNoContent)
	retired := fetchKeycloakSAMLMetadata(t, admin.client, issuer)
	retiredCerts := strings.Join(strings.Fields(retired), "")
	if strings.Contains(retiredCerts, original.Certificate) || !strings.Contains(retiredCerts, successor.Certificate) {
		t.Fatal("the IdP metadata did not retire the original certificate")
	}
	importMetadata(retired)
	oldBrowser.request(t, http.MethodPost, oldPath+"/sso/saml/complete", nil, rp.host.URL, "", http.StatusBadRequest)
	login()
	client.send(t, http.MethodGet, "/oauth/userinfo", priorAccess, "", "", nil).requireStatus(t, http.StatusOK)
	var audited int
	if err := rp.st.Pool.QueryRow(t.Context(), `SELECT count(*) FROM audit_logs
		WHERE action='sso.connection.saml_metadata.update' AND resource_id=$1 AND outcome='success'
		  AND length(metadata->>'previous_trust_sha256')=64 AND length(metadata->>'new_trust_sha256')=64`, connection.ID).
		Scan(&audited); err != nil || audited != 2 {
		t.Fatal("the two Keycloak certificate changes did not leave digest-only audit evidence")
	}
}
