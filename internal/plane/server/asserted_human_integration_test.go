package server

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/danielgtaylor/huma/v2/adapters/humago"
	"github.com/plystra/auth/internal/application"
	"github.com/plystra/auth/internal/db"
	"github.com/plystra/auth/internal/route"
	"github.com/plystra/auth/internal/store"
)

const sharedSecondAccount = "usr_server_shared_account"

func assertedHumanFixture(t *testing.T) (*store.Store, func(context.Context, string, string) *httptest.ResponseRecorder, string) {
	t.Helper()
	st, authz, member, spaceID, key, sessions := newServerFixture(t)
	ctx := t.Context()
	if _, err := st.Pool.Exec(ctx, `UPDATE members SET binding_policy='shared' WHERE id=$1`, member.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Pool.Exec(ctx, `INSERT INTO users (id,email,email_normalized,password_hash,status)
		VALUES ($1,'shared-account@example.test','shared-account@example.test','fixture-hash','active')`, sharedSecondAccount); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Pool.Exec(ctx, `INSERT INTO user_members (user_id,member_id) VALUES ($1,$2)`, sharedSecondAccount, member.ID); err != nil {
		t.Fatal(err)
	}
	api := &API{Applications: &application.Service{Store: st, HMACKeys: [][]byte{[]byte(strings.Repeat("s", 32))}}, Authorization: authz, Sessions: sessions}
	mux := http.NewServeMux()
	api.Register(humago.New(mux, route.HumaConfig("Exact human assertion", "1")))
	handler := route.Middleware(route.Server, mux)
	request := func(ctx context.Context, userID, targetSpace string) *httptest.ResponseRecorder {
		body, _ := json.Marshal(CheckBody{Subject: CheckSubject{MemberID: member.ID, UserID: userID}, Action: "self:read",
			Resource: CheckResource{Type: "member", ID: member.ID, SpaceID: targetSpace}})
		req := httptest.NewRequestWithContext(ctx, http.MethodPost, "/server/v1/authz/check", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+key)
		res := httptest.NewRecorder()
		handler.ServeHTTP(res, req)
		return res
	}
	return st, request, spaceID
}

func TestAssertedHumanRequiresCurrentExactAccountBinding(t *testing.T) {
	st, request, space := assertedHumanFixture(t)
	ctx := t.Context()
	for _, userID := range []string{"usr_server_actor", sharedSecondAccount, ""} {
		res := request(ctx, userID, space)
		if res.Code != http.StatusOK || !strings.Contains(res.Body.String(), `"decision":"allow"`) {
			t.Fatalf("initial assertion = %d %s", res.Code, res.Body.String())
		}
	}
	for _, mutation := range []string{
		`UPDATE users SET status='disabled', disabled_at=now() WHERE id=$1`,
		`UPDATE users SET status='active', disabled_at=NULL WHERE id=$1;
		 UPDATE user_members SET expires_at=clock_timestamp()-interval '1 second' WHERE user_id=$1`,
		`UPDATE user_members SET expires_at=NULL, revoked_at=clock_timestamp(), status='revoked' WHERE user_id=$1`,
	} {
		// Execute individual statements so bound fixtures also work with extended-query mode.
		for _, statement := range strings.Split(mutation, ";") {
			if _, err := st.Pool.Exec(ctx, statement, sharedSecondAccount); err != nil {
				t.Fatal(err)
			}
		}
		denied := request(ctx, sharedSecondAccount, space)
		if denied.Code != http.StatusNotFound || !strings.Contains(denied.Body.String(), "SUBJECT_NOT_FOUND") {
			t.Fatalf("invalid account-bound assertion = %d %s", denied.Code, denied.Body.String())
		}
		for _, userID := range []string{"usr_server_actor", ""} {
			allowed := request(ctx, userID, space)
			if allowed.Code != http.StatusOK || !strings.Contains(allowed.Body.String(), `"decision":"allow"`) {
				t.Fatal("the separate live user and member-only assertions should still work")
			}
		}
	}
}

func TestAccountAssertionChecksUniqueActiveMembershipInExplicitSpace(t *testing.T) {
	const accountID = "usr_server_actor"
	const unboundMember = "mem_unbound_extra"
	st, authz, original, space, key, sessions := newServerFixture(t)
	ctx := t.Context()
	exec := func(statement string, args ...any) {
		t.Helper()
		if _, err := st.Pool.Exec(ctx, statement, args...); err != nil {
			t.Fatal(err)
		}
	}
	exec(`UPDATE api_keys SET scopes = '["auth.authz:check","auth.authz:explain"]' WHERE name='server-test'`)
	api := &API{Applications: &application.Service{Store: st, HMACKeys: [][]byte{[]byte(strings.Repeat("s", 32))}}, Authorization: authz, Sessions: sessions}
	mux := http.NewServeMux()
	api.Register(humago.New(mux, route.HumaConfig("Account assertion", "1")))
	host := httptest.NewTLSServer(route.Middleware(route.Server, mux))
	t.Cleanup(host.Close)
	request := func(operation string, input any, status int, want string) {
		t.Helper()
		body, err := json.Marshal(input)
		if err != nil {
			t.Fatal(err)
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, host.URL+"/server/v1/authz/"+operation, bytes.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+key)
		response, err := host.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = response.Body.Close() }()
		var result json.RawMessage
		if err := json.NewDecoder(response.Body).Decode(&result); err != nil {
			t.Fatal(err)
		}
		if response.StatusCode != status || !bytes.Contains(result, []byte(want)) {
			t.Fatalf("%s returned %d %s, want %d containing %s", operation, response.StatusCode, result, status, want)
		}
	}
	check := CheckBody{
		Subject:  CheckSubject{UserID: accountID},
		Action:   "self:read",
		Resource: CheckResource{Type: "member", ID: original.ID, SpaceID: space},
	}
	foreign, _, err := authz.CreateSpace(ctx, accountID, "Other Space", "account-assertion-other-space")
	if err != nil {
		t.Fatal(err)
	}
	request("check", check, http.StatusOK, `"decision":"allow"`)
	request("batch-check", BatchCheckBody{Requests: []CheckBody{check}}, http.StatusOK, `"decision":"allow"`)
	request("explain", check, http.StatusOK, `"decision":"allow"`)
	wrongTarget := check
	wrongTarget.Resource.SpaceID = foreign.ID
	request("check", wrongTarget, http.StatusOK, "KEY_SCOPE_EXCLUDED")
	wrongTarget.Resource.SpaceID = ""
	request("check", wrongTarget, http.StatusBadRequest, "VALIDATION_FAILED")
	exec(`UPDATE api_keys SET allow_subject_assertion = false WHERE name='server-test'`)
	request("check", check, http.StatusBadRequest, "VALIDATION_FAILED")
	exec(`UPDATE api_keys SET allow_subject_assertion = true WHERE name='server-test'`)

	exec(`INSERT INTO members (id, space_id, name, type) VALUES ($1, $2, 'Second identity', 'human')`, unboundMember, space)
	exec(`INSERT INTO user_members (user_id, member_id) VALUES ($1, $2)`, accountID, unboundMember)
	request("check", check, http.StatusNotFound, "SUBJECT_NOT_FOUND")
	explicit := check
	explicit.Subject.MemberID = original.ID
	request("check", explicit, http.StatusOK, `"decision":"allow"`)
	exec(`UPDATE user_members SET expires_at=clock_timestamp()-interval '1 second' WHERE user_id=$1 AND member_id=$2`, accountID, unboundMember)
	request("check", check, http.StatusOK, `"decision":"allow"`)

	denied := check
	denied.Action = "fixture:undeclared"
	request("check", denied, http.StatusOK, `"decision":"deny"`)
	var recordedUser, recordedMember, source string
	if err := st.Pool.QueryRow(ctx, `SELECT user_id, member_id, metadata->>'subject_source'
		FROM audit_logs WHERE action='authz.check' AND permission_key=$1 AND space_id=$2`,
		denied.Action, space).Scan(&recordedUser, &recordedMember, &source); err != nil {
		t.Fatal(err)
	}
	if recordedUser != accountID || recordedMember != original.ID || source != "application_assertion" {
		t.Fatal("the decision audit did not use the resolved identity")
	}
	exec(`UPDATE user_members SET status='revoked', revoked_at=clock_timestamp() WHERE user_id=$1 AND member_id=$2`, accountID, original.ID)
	request("check", check, http.StatusNotFound, "SUBJECT_NOT_FOUND")
}

func TestAssertedHumanRechecksAccountAfterWaitingForLock(t *testing.T) {
	st, request, space := assertedHumanFixture(t)
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	ready := make(chan struct{})
	release := make(chan struct{})
	defer func() {
		select {
		case <-release:
		default:
			close(release)
		}
	}()
	committed := make(chan error, 1)
	go func() {
		committed <- st.InTx(ctx, func(q *db.Queries) error {
			if err := q.SetUserStatus(ctx, db.SetUserStatusParams{ID: sharedSecondAccount, Status: "disabled"}); err != nil {
				return err
			}
			close(ready)
			select {
			case <-release:
				return nil
			case <-ctx.Done():
				return ctx.Err()
			}
		})
	}()
	select {
	case <-ready:
	case err := <-committed:
		t.Fatalf("set up blocked account: %v", err)
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	responses := make(chan *httptest.ResponseRecorder, 1)
	go func() { responses <- request(ctx, sharedSecondAccount, space) }()
	ticker := time.NewTicker(20 * time.Millisecond)
	defer ticker.Stop()
	for {
		var waiting bool
		if err := st.Pool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM pg_stat_activity WHERE pid<>pg_backend_pid()
			AND datname=current_database() AND wait_event_type='Lock' AND query LIKE '%LockUserForAuthorization%')`).Scan(&waiting); err != nil {
			t.Fatal(err)
		}
		if waiting {
			break
		}
		select {
		case response := <-responses:
			t.Fatalf("assertion completed before the locked authority update: HTTP %d", response.Code)
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		case <-ticker.C:
		}
	}
	close(release)
	if err := <-committed; err != nil {
		t.Fatal(err)
	}
	res := <-responses
	if res.Code != http.StatusNotFound || !strings.Contains(res.Body.String(), "SUBJECT_NOT_FOUND") {
		t.Fatalf("assertion after concurrent offboarding = %d %s", res.Code, res.Body.String())
	}
}
