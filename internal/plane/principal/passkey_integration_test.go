package principal

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/danielgtaylor/huma/v2/adapters/humago"
	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/protocol/webauthncbor"
	"github.com/go-webauthn/webauthn/protocol/webauthncose"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/plystra/auth/internal/apierr"
	"github.com/plystra/auth/internal/factor"
	"github.com/plystra/auth/internal/route"
	"github.com/plystra/auth/internal/secret"
	"github.com/plystra/auth/internal/session"
	"github.com/plystra/auth/internal/stepup"
)

func TestPasskeyEnrollmentHTTPValidatesOriginSessionAndOneTimeChallenge(t *testing.T) {
	ctx := context.Background()
	st, authz, actor, _, sessions, signer := newPrincipalFixture(t)
	web, err := webauthn.New(&webauthn.Config{RPID: "auth.test", RPDisplayName: "Plystra Auth", RPOrigins: []string{"https://auth.test"}})
	if err != nil {
		t.Fatal(err)
	}
	factors := &factor.Service{Store: st, DataKey: secret.New(strings.Repeat("d", 32)), StepUp: sessions, WebAuthn: web}
	tokens, err := sessions.CreateForMember(ctx, "usr_principal_actor", actor.ID, nil, "test", 1)
	if err != nil {
		t.Fatal(err)
	}
	otherSession, err := sessions.CreateForMember(ctx, "usr_principal_actor", actor.ID, nil, "other", 1)
	if err != nil {
		t.Fatal(err)
	}
	api := &API{Authorization: authz, Sessions: sessions, Signer: signer, Factors: factors}
	mux := http.NewServeMux()
	api.Register(humago.New(mux, route.HumaConfig("principal test", "1.0.0")))
	handler := route.Middleware(route.Principal, mux)
	post := func(token string, body []byte) *httptest.ResponseRecorder {
		t.Helper()
		r := httptest.NewRequest(http.MethodPost, "/v1/me/factors", strings.NewReader(string(body)))
		r.Header.Set("Authorization", "Bearer "+token)
		r.Header.Set("Content-Type", "application/json")
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, r)
		return response
	}
	beginBody := []byte(`{"kind":"passkey","name":"laptop"}`)
	if noStepUp := post(tokens.AccessToken, beginBody); noStepUp.Code != http.StatusForbidden {
		t.Fatalf("passkey enrollment without step-up status=%d body=%s", noStepUp.Code, noStepUp.Body.String())
	}
	seedStepUpProof(t, st, tokens.SessionID, "me.factors.create", map[string]any{"kind": "passkey", "name": "laptop"})
	begin := post(tokens.AccessToken, beginBody)
	if begin.Code != http.StatusOK {
		t.Fatalf("begin passkey enrollment status=%d body=%s", begin.Code, begin.Body.String())
	}
	var begun struct {
		Data struct {
			Passkey factor.PasskeyChallenge `json:"passkey"`
		} `json:"data"`
	}
	if err := json.Unmarshal(begin.Body.Bytes(), &begun); err != nil {
		t.Fatal(err)
	}
	challenge := begun.Data.Passkey
	if challenge.ID == "" || challenge.Options == nil || challenge.ExpiresAt.Before(time.Now()) {
		t.Fatalf("invalid passkey challenge: %+v", challenge)
	}
	if challenge.Options.Response.AuthenticatorSelection.UserVerification != protocol.VerificationRequired {
		t.Fatal("passkey challenge did not require user verification")
	}
	credential, credentialID := testPasskeyCredential(t, challenge.Options.Response.Challenge.String(), "https://auth.test", "auth.test", true)
	finishBody, err := json.Marshal(map[string]any{"kind": "passkey", "challenge_id": challenge.ID, "credential": json.RawMessage(credential)})
	if err != nil {
		t.Fatal(err)
	}
	if wrongSession := post(otherSession.AccessToken, finishBody); wrongSession.Code != http.StatusBadRequest {
		t.Fatalf("another session completed passkey enrollment: status=%d body=%s", wrongSession.Code, wrongSession.Body.String())
	}
	if reusedStepUp := post(tokens.AccessToken, beginBody); reusedStepUp.Code != http.StatusForbidden {
		t.Fatalf("passkey begin reused step-up proof: status=%d", reusedStepUp.Code)
	}
	finished := post(tokens.AccessToken, finishBody)
	if finished.Code != http.StatusOK {
		t.Fatalf("finish passkey enrollment status=%d body=%s", finished.Code, finished.Body.String())
	}
	var saved struct {
		Data struct {
			FactorID string `json:"factor_id"`
		} `json:"data"`
	}
	if err := json.Unmarshal(finished.Body.Bytes(), &saved); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(saved.Data.FactorID, "fac_") {
		t.Fatalf("passkey factor ID=%q", saved.Data.FactorID)
	}
	if replay := post(tokens.AccessToken, finishBody); replay.Code != http.StatusBadRequest {
		t.Fatalf("passkey challenge replay status=%d body=%s", replay.Code, replay.Body.String())
	}
	var storedID, ciphertext []byte
	if err := st.Pool.QueryRow(ctx, `SELECT credential_id, secret_ciphertext FROM factors WHERE id = $1`, saved.Data.FactorID).Scan(&storedID, &ciphertext); err != nil {
		t.Fatal(err)
	}
	if string(storedID) != string(credentialID) || len(ciphertext) == 0 || strings.Contains(string(ciphertext), string(credentialID)) {
		t.Fatal("passkey credential was not stored with an encrypted record")
	}
	listed := httptest.NewRecorder()
	listReq := httptest.NewRequest(http.MethodGet, "/v1/me/factors", nil)
	listReq.Header.Set("Authorization", "Bearer "+tokens.AccessToken)
	handler.ServeHTTP(listed, listReq)
	if listed.Code != http.StatusOK || !strings.Contains(listed.Body.String(), saved.Data.FactorID) || strings.Contains(listed.Body.String(), base64.RawURLEncoding.EncodeToString(credentialID)) {
		t.Fatalf("passkey listing status=%d or leaked credential material", listed.Code)
	}
}

func TestPasskeyEnrollmentRejectsWrongOriginAndExpiredChallenge(t *testing.T) {
	ctx := context.Background()
	st, authz, actor, _, sessions, signer := newPrincipalFixture(t)
	web, err := webauthn.New(&webauthn.Config{RPID: "auth.test", RPDisplayName: "Plystra Auth", RPOrigins: []string{"https://auth.test"}})
	if err != nil {
		t.Fatal(err)
	}
	factors := &factor.Service{Store: st, DataKey: secret.New(strings.Repeat("d", 32)), StepUp: sessions, WebAuthn: web}
	tokens, err := sessions.CreateForMember(ctx, "usr_principal_actor", actor.ID, nil, "test", 1)
	if err != nil {
		t.Fatal(err)
	}
	api := &API{Authorization: authz, Sessions: sessions, Signer: signer, Factors: factors}
	start := func(name string) factor.PasskeyChallenge {
		t.Helper()
		seedStepUpProof(t, st, tokens.SessionID, "me.factors.create", map[string]any{"kind": "passkey", "name": name})
		in := &FactorsInput{Authorization: "Bearer " + tokens.AccessToken}
		in.Body.Kind, in.Body.Name = "passkey", name
		out, err := api.createFactor(ctx, in)
		if err != nil {
			t.Fatal(err)
		}
		return *out.Body.Data.Passkey
	}
	finish := func(challenge factor.PasskeyChallenge, origin string, verified bool) error {
		t.Helper()
		response, _ := testPasskeyCredential(t, challenge.Options.Response.Challenge.String(), origin, "auth.test", verified)
		_, err := factors.FinishPasskeyEnrollment(ctx, "usr_principal_actor", tokens.SessionID, challenge.ID, response)
		return err
	}
	wrongOrigin := start("wrong-origin")
	if err := finish(wrongOrigin, "https://evil.test", true); err == nil {
		t.Fatal("passkey registered from an untrusted origin")
	}
	if err := finish(wrongOrigin, "https://auth.test", true); err == nil {
		t.Fatal("failed origin validation did not consume the challenge")
	}
	unverified := start("unverified")
	if err := finish(unverified, "https://auth.test", false); err == nil {
		t.Fatal("passkey registered without user verification")
	}
	expired := start("expired")
	if _, err := st.Pool.Exec(ctx, `UPDATE passkey_challenges SET expires_at = now() - interval '1 second' WHERE id = $1`, expired.ID); err != nil {
		t.Fatal(err)
	}
	if err := finish(expired, "https://auth.test", true); err == nil {
		t.Fatal("expired passkey challenge was accepted")
	}
}

func TestPasskeyEnrollmentConcurrentFinishAndAuditRollback(t *testing.T) {
	ctx := context.Background()
	st, _, actor, _, sessions, _ := newPrincipalFixture(t)
	web, err := webauthn.New(&webauthn.Config{RPID: "auth.test", RPDisplayName: "Plystra Auth", RPOrigins: []string{"https://auth.test"}})
	if err != nil {
		t.Fatal(err)
	}
	factors := &factor.Service{Store: st, DataKey: secret.New(strings.Repeat("d", 32)), StepUp: sessions, WebAuthn: web}
	tokens, err := sessions.CreateForMember(ctx, "usr_principal_actor", actor.ID, nil, "test", 1)
	if err != nil {
		t.Fatal(err)
	}
	start := func(name string) factor.PasskeyChallenge {
		t.Helper()
		seedStepUpProof(t, st, tokens.SessionID, "me.factors.create", map[string]any{"kind": "passkey", "name": name})
		requestCtx, err := principalPasskeyStepUpContext(tokens.SessionID, name)
		if err != nil {
			t.Fatal(err)
		}
		challenge, err := factors.BeginPasskeyEnrollment(requestCtx, "usr_principal_actor", tokens.SessionID, name)
		if err != nil {
			t.Fatal(err)
		}
		return challenge
	}
	finish := func(challenge factor.PasskeyChallenge) (string, error) {
		response, _ := testPasskeyCredential(t, challenge.Options.Response.Challenge.String(), "https://auth.test", "auth.test", true)
		return factors.FinishPasskeyEnrollment(ctx, "usr_principal_actor", tokens.SessionID, challenge.ID, response)
	}
	concurrent := start("concurrent")
	response, _ := testPasskeyCredential(t, concurrent.Options.Response.Challenge.String(), "https://auth.test", "auth.test", true)
	results := make(chan error, 2)
	var wg sync.WaitGroup
	for range 2 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := factors.FinishPasskeyEnrollment(ctx, "usr_principal_actor", tokens.SessionID, concurrent.ID, response)
			results <- err
		}()
	}
	wg.Wait()
	close(results)
	var successes, rejections int
	for err := range results {
		if err == nil {
			successes++
			continue
		}
		var public *apierr.Error
		if !errors.As(err, &public) || public.Code != "invalid_grant" {
			t.Fatalf("concurrent passkey finish error=%v", err)
		}
		rejections++
	}
	if successes != 1 || rejections != 1 {
		t.Fatalf("concurrent passkey finish successes=%d rejections=%d", successes, rejections)
	}

	rollback := start("rollback")
	if _, err := st.Pool.Exec(ctx, `
		CREATE FUNCTION reject_passkey_creation_audit() RETURNS trigger LANGUAGE plpgsql AS $$
		BEGIN IF NEW.action = 'factor.passkey.create' THEN RAISE EXCEPTION 'test audit failure'; END IF; RETURN NEW; END;
		$$;
		CREATE TRIGGER test_reject_passkey_creation_audit BEFORE INSERT ON audit_logs
		FOR EACH ROW EXECUTE FUNCTION reject_passkey_creation_audit();
	`); err != nil {
		t.Fatal(err)
	}
	if _, err := finish(rollback); err == nil {
		t.Fatal("passkey enrollment survived audit failure")
	}
	var count int
	if err := st.Pool.QueryRow(ctx, `SELECT count(*) FROM factors WHERE user_id = 'usr_principal_actor' AND name = 'rollback'`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatal("passkey factor survived audit rollback")
	}
	if _, err := st.Pool.Exec(ctx, `DROP TRIGGER test_reject_passkey_creation_audit ON audit_logs`); err != nil {
		t.Fatal(err)
	}
	if _, err := finish(rollback); err != nil {
		t.Fatalf("audit rollback consumed passkey challenge: %v", err)
	}
}

func principalPasskeyStepUpContext(sessionID, name string) (context.Context, error) {
	digest, err := stepup.DigestValue(map[string]any{"kind": "passkey", "name": name})
	if err != nil {
		return nil, err
	}
	return session.WithStepUpRequirement(context.Background(), session.StepUpRequirement{SessionID: sessionID, Operation: "me.factors.create", Digest: digest}), nil
}

func testPasskeyCredential(t *testing.T, challenge, origin, rpID string, verified bool) ([]byte, []byte) {
	t.Helper()
	private, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	credentialID := make([]byte, 32)
	if _, err := rand.Read(credentialID); err != nil {
		t.Fatal(err)
	}
	publicBytes, err := private.PublicKey.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	publicKey, err := webauthncbor.Marshal(map[int64]any{
		1: int64(webauthncose.EllipticKey), 3: int64(webauthncose.AlgES256),
		-1: int64(webauthncose.P256),
		-2: publicBytes[1:33],
		-3: publicBytes[33:65],
	})
	if err != nil {
		t.Fatal(err)
	}
	rpHash := sha256.Sum256([]byte(rpID))
	flags := protocol.FlagUserPresent | protocol.FlagAttestedCredentialData
	if verified {
		flags |= protocol.FlagUserVerified
	}
	authData := append([]byte(nil), rpHash[:]...)
	authData = append(authData, byte(flags))
	authData = binary.BigEndian.AppendUint32(authData, 0)
	authData = append(authData, make([]byte, 16)...)
	authData = binary.BigEndian.AppendUint16(authData, uint16(len(credentialID)))
	authData = append(authData, credentialID...)
	authData = append(authData, publicKey...)
	attestation, err := webauthncbor.Marshal(map[string]any{"fmt": "none", "attStmt": map[string]any{}, "authData": authData})
	if err != nil {
		t.Fatal(err)
	}
	clientData, err := json.Marshal(map[string]any{"type": "webauthn.create", "challenge": challenge, "origin": origin, "crossOrigin": false})
	if err != nil {
		t.Fatal(err)
	}
	id := base64.RawURLEncoding.EncodeToString(credentialID)
	response, err := json.Marshal(map[string]any{
		"id": id, "rawId": id, "type": "public-key",
		"response": map[string]any{
			"attestationObject": base64.RawURLEncoding.EncodeToString(attestation),
			"clientDataJSON":    base64.RawURLEncoding.EncodeToString(clientData),
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	return response, credentialID
}
