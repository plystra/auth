//go:build interop

package protocol

import (
	"errors"
	"net/http"
	"net/url"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/plystra/auth/internal/authorization"
	"github.com/plystra/auth/internal/enterprise"
	"github.com/plystra/auth/internal/factor"
	"github.com/plystra/auth/internal/security"
	"github.com/pquerna/otp/totp"
	"golang.org/x/oauth2"
)

type workforceNetworkGate struct {
	transport *http.Transport
	offline   atomic.Bool
}

func (g *workforceNetworkGate) RoundTrip(req *http.Request) (*http.Response, error) {
	if g.offline.Load() {
		return nil, errors.New("fixture IdP is unreachable from Auth")
	}
	return g.transport.RoundTrip(req)
}

func TestKeycloakWorkforceRecoversFromForcedDomainOutage(t *testing.T) {
	ctx := t.Context()
	upstream := &http.Client{Timeout: 15 * time.Second}
	rp := newHumanRPWithWorkforce(t, false, upstream)
	callback := rp.host.URL + "/oidc/upstream"
	issuer, transport := keycloakFixture(t, callback)
	gate := &workforceNetworkGate{transport: transport}
	upstream.Transport = gate
	t.Cleanup(transport.CloseIdleConnections)
	const ownerID, email, username = "usr_human_rp", "original@workforce.example.test", "original"
	space, owner, err := rp.workforce.Authorization.CreateSpace(ctx, ownerID, "Workforce recovery", "workforce-recovery")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := rp.st.Pool.Exec(ctx, `INSERT INTO authorization_grants (id,space_id,permission_keys,grantee_member_id,scope,anchor_space_id,granted_by)
		VALUES ('grt_domain_recovery',$1,'["auth.connections:manage"]',$2,'space',$1,$2)`, space.ID, owner.ID); err != nil {
		t.Fatal(err)
	}
	actor := authorization.WithHumanActor(ctx, owner.ID, ownerID)
	connection, err := rp.workforce.CreateConnection(actor, owner.ID, space.ID, enterprise.ConnectionInput{
		Name: "Workforce Keycloak", Provider: "oidc", Issuer: issuer, ClientID: keycloakClientID,
		ClientSecret: keycloakClientSecret, RedirectURI: callback,
	})
	if err != nil {
		t.Fatal(err)
	}
	domain, err := rp.workforce.CreateDomain(actor, owner.ID, space.ID, enterprise.DomainInput{
		Domain: "workforce.example.test", ConnectionID: connection.ID, ForceSSO: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	rp.workforce.DNSResolver = employeeDomainResolver{domain.VerificationToken}
	if err := rp.workforce.VerifyDomain(actor, owner.ID, space.ID, domain.ID); err != nil {
		t.Fatal(err)
	}
	rp.workforce.Sessions.Factors = &factor.Service{Store: rp.st, DataKey: rp.workforce.DataKey}
	admin := employeeLifecycleClient{server: rp.host}
	prove := func(operation, factorName string, request any) {
		t.Helper()
		mfa, err := rp.workforce.Sessions.Factors.EnrollTOTPForUser(ctx, ownerID, "rp@example.test", factorName)
		if err != nil {
			t.Fatal(err)
		}
		code, err := totp.GenerateCode(mfa.Secret.Value(), time.Now().UTC())
		if err != nil {
			t.Fatal(err)
		}
		admin.send(t, http.MethodPost, "/v1/auth/step-up", rp.session.AccessToken, "application/json", "", map[string]any{
			"operation": operation, "request": request, "mfa_code": code,
		}).requireStatus(t, http.StatusOK)
	}
	domainPath := "/v1/spaces/" + space.ID + "/domains"
	prove("domains.list", "read the domain", enterprise.SettingsListRequest("domains.list", space.ID))
	domains := keycloakInteropData[[]enterprise.Domain](t, "verified domain list", admin.send(t, http.MethodGet, domainPath, rp.session.AccessToken, "", "", nil))
	if len(domains) != 1 || !domains[0].ForceSSO || domains[0].ID != domain.ID || domains[0].ETag == "" {
		t.Fatal("the public domain read did not return the enforced verified domain")
	}
	setEnforcement := func(current enterprise.Domain, required bool) enterprise.Domain {
		t.Helper()
		prove(enterprise.DomainUpdateOperation, "require SSO: "+strconv.FormatBool(required), enterprise.DomainUpdateRequest(space.ID, domain.ID, current.ETag, required))
		reply := admin.send(t, http.MethodPatch, domainPath+"/"+domain.ID, rp.session.AccessToken, "application/json", current.ETag, map[string]bool{"force_sso": required})
		updated := keycloakInteropData[enterprise.Domain](t, "update domain enforcement", reply)
		if updated.ID != domain.ID || updated.ConnectionID != connection.ID || updated.ForceSSO != required || updated.ETag == current.ETag {
			t.Fatal("domain enforcement did not preserve the verified domain and connection")
		}
		return updated
	}
	signIn := func(password string, unavailable bool) string {
		t.Helper()
		browser := newOIDCBrowser(t, rp)
		verifier, state, nonce := oauth2.GenerateVerifier(), oauth2.GenerateVerifier(), oauth2.GenerateVerifier()
		path := browser.beginFromAuthorization(t, verifier, state, nonce)
		identify := map[string]string{"email": email, "method": "password"}
		if unavailable {
			browser.request(t, http.MethodPost, path+"/identify", identify, rp.host.URL, "", http.StatusServiceUnavailable, "temporarily_unavailable")
			return ""
		}
		identified, _ := browser.request(t, http.MethodPost, path+"/identify", identify, rp.host.URL, "", http.StatusOK)
		var authenticated interactionResponse
		if password != "" {
			if identified.NextStep != "password" || identified.SSOConnectionID != "" {
				t.Fatal("the reverted policy did not allow local authentication")
			}
			authenticated, _ = browser.request(t, http.MethodPost, path+"/authenticate", map[string]string{"password": password}, rp.host.URL, "", http.StatusOK)
		} else {
			if identified.NextStep != "sso" || identified.SSOConnectionID != connection.ID {
				t.Fatal("the enforced domain did not select the enterprise connection")
			}
			upstream := keycloakAuthorize(t, transport, identified.AuthorizationURL, callback, username)
			authenticated, _ = browser.request(t, http.MethodPost, path+"/sso/complete", map[string]string{"state": upstream.Get("state"), "code": upstream.Get("code")}, rp.host.URL, "", http.StatusOK)
		}
		if authenticated.NextStep != "consent" || authenticated.Email != email {
			t.Fatal("the employee did not return to the original application interaction")
		}
		decision, _ := browser.request(t, http.MethodPost, path+"/decision", map[string]string{"decision": "approve"}, rp.host.URL, "", http.StatusOK)
		redirect, err := url.Parse(decision.RedirectTo)
		if err != nil || redirect.Query().Get("state") != state || redirect.Scheme+"://"+redirect.Host+redirect.Path != rp.config.RedirectURL {
			t.Fatal("application callback or state changed")
		}
		clientContext := oidc.ClientContext(ctx, rp.host.Client())
		tokens, err := rp.config.Exchange(clientContext, redirect.Query().Get("code"), oauth2.VerifierOption(verifier))
		if err != nil {
			t.Fatal("the relying party could not exchange the authorization code")
		}
		raw, _ := tokens.Extra("id_token").(string)
		identity, err := rp.provider.Verifier(&oidc.Config{ClientID: rp.config.ClientID}).Verify(clientContext, raw)
		if err != nil || identity.Subject == "" || identity.Nonce != nonce {
			t.Fatal("the relying party could not verify the employee identity")
		}
		return identity.Subject
	}
	userID := signIn("", false)
	// Establish the employee's existing local credential before interrupting upstream access.
	localPassword := oauth2.GenerateVerifier()
	hash, err := security.DefaultPasswordHasher().Hash(localPassword)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := rp.st.Pool.Exec(ctx, `UPDATE users SET password_hash=$1 WHERE id=$2`, hash, userID); err != nil {
		t.Fatal(err)
	}
	gate.offline.Store(true)
	signIn("", true)
	reverted := setEnforcement(domains[0], false)
	if signIn(localPassword, false) != userID {
		t.Fatal("local fallback changed the employee's application identity")
	}
	gate.offline.Store(false)
	setEnforcement(reverted, true)
	if signIn("", false) != userID {
		t.Fatal("restoring enterprise sign-in changed the employee's application identity")
	}
	var changes int
	if err := rp.st.Pool.QueryRow(ctx, `SELECT count(*) FROM audit_logs WHERE action='sso.domain.policy.update' AND outcome='success'
		AND resource_id=$1 AND user_id=$2`, domain.ID, ownerID).Scan(&changes); err != nil || changes != 2 {
		t.Fatal("the two policy changes were not audited for the administrator")
	}
}
