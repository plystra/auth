package protocol

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/plystra/auth/internal/account"
	"github.com/plystra/auth/internal/authorization"
	"github.com/plystra/auth/internal/db"
	"github.com/plystra/auth/internal/enterprise"
	"github.com/plystra/auth/internal/store"
)

type directorySSOFixture struct {
	st         *store.Store
	svc        *enterprise.Service
	provider   *oidcTestProvider
	owner      authorization.Member
	spaceID    string
	connection enterprise.Connection
	directory  enterprise.Directory
	user       enterprise.SCIMUser
	userID     string
	memberID   string
	mux        *http.ServeMux
}

func newDirectorySSOFixture(t *testing.T, claim string) *directorySSOFixture {
	t.Helper()
	ctx := context.Background()
	st, _, svc, owner, spaceID, provider := newSSOHTTPFixture(t)
	actor := authorization.WithHumanActor(ctx, owner.ID, "usr_sso_http_owner")
	connection, err := svc.CreateConnection(actor, owner.ID, spaceID, enterprise.ConnectionInput{
		Name: "Directory OIDC", Provider: "oidc", Issuer: provider.issuer, ClientID: "directory-client", ClientSecret: "test-secret",
		RedirectURI: "https://auth.example.test/v1/sso/{connection_id}/callback",
	})
	if err != nil {
		t.Fatal(err)
	}
	directory, err := svc.CreateDirectory(actor, owner.ID, spaceID, enterprise.DirectoryInput{
		Name: "Workforce", SSOConnectionID: connection.ID, SSOIdentityClaim: claim,
	})
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	(HTTP{Enterprise: svc}).Register(mux)
	f := &directorySSOFixture{st: st, svc: svc, provider: provider, owner: owner, spaceID: spaceID, connection: connection, directory: directory, mux: mux}
	request := httptest.NewRequest("POST", "/scim/v2/"+directory.ID+"/Users",
		strings.NewReader(`{"externalId":"Stable-Object-1","userName":"directory-user@example.test","displayName":"Directory Name","active":true}`))
	request.Header.Set("Content-Type", "application/scim+json")
	request.Header.Set("Authorization", "Bearer "+directory.Token.Value())
	response := httptest.NewRecorder()
	mux.ServeHTTP(response, request)
	if response.Code != http.StatusCreated {
		t.Fatalf("SCIM provisioning failed: %d %s", response.Code, response.Body.String())
	}
	if err := json.Unmarshal(response.Body.Bytes(), &f.user); err != nil {
		t.Fatal(err)
	}
	if err := st.Pool.QueryRow(ctx, "SELECT user_id, member_id FROM directory_users WHERE id=$1", f.user.ID).Scan(&f.userID, &f.memberID); err != nil {
		t.Fatal(err)
	}
	return f
}

func (f *directorySSOFixture) login(t *testing.T, subject, email string, extra map[string]any) *httptest.ResponseRecorder {
	t.Helper()
	start := httptest.NewRecorder()
	f.mux.ServeHTTP(start, httptest.NewRequest("GET", "/v1/sso/"+f.connection.ID+"/start", nil))
	if start.Code != http.StatusOK {
		t.Fatalf("SSO start failed: %d %s", start.Code, start.Body.String())
	}
	var result struct{ Data enterprise.StartResult }
	if err := json.Unmarshal(start.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	authURL, err := url.Parse(result.Data.AuthorizationURL)
	if err != nil {
		t.Fatal(err)
	}
	f.provider.addCode(result.Data.State, oidcTestCode{nonce: authURL.Query().Get("nonce"), subject: subject,
		email: email, emailVerified: true, groups: []string{"administrators"}, extra: extra})
	body, err := json.Marshal(map[string]string{"state": result.Data.State, "code": result.Data.State})
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest("POST", "/v1/sso/"+f.connection.ID+"/callback", strings.NewReader(string(body)))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	f.mux.ServeHTTP(response, request)
	return response
}

func requireDirectorySSODenied(t *testing.T, response *httptest.ResponseRecorder) {
	t.Helper()
	if response.Code != http.StatusBadRequest || !strings.Contains(response.Body.String(), "invalid_grant") {
		t.Fatalf("directory SSO should fail closed: %d %s", response.Code, response.Body.String())
	}
}

func TestDirectoryOIDCSSOReusesProvisionedIdentityWithoutEmailOrRoleLinking(t *testing.T) {
	f := newDirectorySSOFixture(t, "oid")
	// A legacy connection's matched role has no verified configurator. A
	// directory-provisioned identity must use its existing grants.
	if _, err := f.st.Pool.Exec(context.Background(), `INSERT INTO roles (id,space_id,name,managed) VALUES ('rol_directory_jit',$1,'Directory mapping',false);
		INSERT INTO role_permissions(role_id,permission_id) SELECT 'rol_directory_jit',id FROM permissions WHERE key='auth.members:read';
		UPDATE sso_connections SET configured_by_member_id=NULL,configured_by_user_id=NULL,
			role_mappings='{"administrators":"rol_directory_jit"}' WHERE id=$2`, pgx.QueryExecModeSimpleProtocol, f.spaceID, f.connection.ID); err != nil {
		t.Fatal(err)
	}
	response := f.login(t, "oidc-subject-1", "different-idp-email@example.test", map[string]any{"oid": "Stable-Object-1"})
	if response.Code != http.StatusOK {
		t.Fatalf("provisioned SSO login failed: %d %s", response.Code, response.Body.String())
	}
	var result struct{ Data account.AuthResult }
	if err := json.Unmarshal(response.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if result.Data.User.ID != f.userID || result.Data.User.Email != "directory-user@example.test" || result.Data.User.DisplayName != "Directory Name" || result.Data.Tokens == nil {
		t.Fatal("SSO did not reuse the exact SCIM user, profile, member and binding")
	}
	var users, members, grants, provenance, audits int
	claims, err := f.svc.Sessions.VerifyAccess(t.Context(), result.Data.Tokens.AccessToken)
	if err != nil || claims.MemberID != f.memberID {
		t.Fatal("SSO token is not bound to the provisioned directory member")
	}
	err = f.st.Pool.QueryRow(context.Background(), `SELECT
		(SELECT count(*) FROM users),
		(SELECT count(*) FROM members WHERE space_id=$1 AND type='human'),
		(SELECT count(*) FROM authorization_grants WHERE grantee_member_id=$2),
		(SELECT count(*) FROM external_identities WHERE user_id=$3 AND directory_user_id=$4),
		(SELECT count(*) FROM audit_logs WHERE action='auth.sso.login' AND metadata->>'directory_user_id'=$4)`,
		f.spaceID, f.memberID, f.userID, f.user.ID).Scan(&users, &members, &grants, &provenance, &audits)
	if err != nil {
		t.Fatal(err)
	}
	if users != 2 || members != 2 || grants != 0 || provenance != 1 || audits != 1 {
		t.Fatalf("login side effects: users=%d members=%d grants=%d provenance=%d audits=%d", users, members, grants, provenance, audits)
	}
}

func TestDirectoryOIDCSSORequiresExactSingleStableClaim(t *testing.T) {
	f := newDirectorySSOFixture(t, "oid")
	for name, value := range map[string]any{
		"missing": nil, "case_mismatch": "stable-object-1", "whitespace": " Stable-Object-1 ",
		"array": []string{"Stable-Object-1"}, "object": map[string]string{"value": "Stable-Object-1"},
		"empty": "", "number": 42, "too_long": strings.Repeat("x", 513),
	} {
		t.Run(name, func(t *testing.T) {
			requireDirectorySSODenied(t, f.login(t, "subject-"+name, "directory-user@example.test", map[string]any{"oid": value}))
		})
	}
	var external int
	if err := f.st.Pool.QueryRow(context.Background(), "SELECT count(*) FROM external_identities").Scan(&external); err != nil || external != 0 {
		t.Fatalf("invalid claims created identities: %d %v", external, err)
	}
}

func TestDirectoryOIDCSSORejectsInactiveFactsAndPreventsJITRecreation(t *testing.T) {
	for name, mutation := range map[string]string{
		"user":            "UPDATE users SET status='disabled', disabled_at=now() WHERE id=$1",
		"member":          "UPDATE members SET status='suspended' WHERE id=$2",
		"binding":         "UPDATE user_members SET status='revoked', revoked_at=now() WHERE user_id=$1 AND member_id=$2",
		"expired_binding": "UPDATE user_members SET expires_at=now()-interval '1 minute' WHERE user_id=$1 AND member_id=$2",
		"directory_user":  "UPDATE directory_users SET active=false WHERE id=$3",
		"tombstone":       "UPDATE directory_users SET active=false, deleted_at=now() WHERE id=$3",
		"directory":       "UPDATE directories SET status='disabled' WHERE id=$4",
		"space":           "UPDATE spaces SET status='suspended' WHERE id=$5",
	} {
		t.Run(name, func(t *testing.T) {
			f := newDirectorySSOFixture(t, "sub")
			if response := f.login(t, "Stable-Object-1", "directory-user@example.test", nil); response.Code != http.StatusOK {
				t.Fatalf("initial login failed: %d", response.Code)
			}
			sql := "WITH facts AS (SELECT $1::text u, $2::text m, $3::text du, $4::text d, $5::text s) " + mutation
			if _, err := f.st.Pool.Exec(context.Background(), sql, f.userID, f.memberID, f.user.ID, f.directory.ID, f.spaceID); err != nil {
				t.Fatal(err)
			}
			requireDirectorySSODenied(t, f.login(t, "Stable-Object-1", "new-email@example.test", nil))
		})
	}
	t.Run("unlink_after_revocation", func(t *testing.T) {
		f := newDirectorySSOFixture(t, "sub")
		if response := f.login(t, "Stable-Object-1", "directory-user@example.test", nil); response.Code != http.StatusOK {
			t.Fatalf("initial login failed: %d", response.Code)
		}
		ctx := context.Background()
		if _, err := f.svc.PatchSCIMUser(ctx, f.directory.ID, f.directory.Token, f.user.ID, enterprise.SCIMUserInput{Active: false, ActiveSet: true}, 1); err != nil {
			t.Fatal(err)
		}
		empty := ""
		actor := authorization.WithHumanActor(ctx, f.owner.ID, "usr_sso_http_owner")
		if _, err := f.svc.UpdateDirectory(actor, f.owner.ID, f.spaceID, f.directory.ID, enterprise.DirectoryUpdate{SSOConnectionID: &empty, SSOIdentityClaim: &empty}, 1); err != nil {
			t.Fatal(err)
		}
		requireDirectorySSODenied(t, f.login(t, "Stable-Object-1", "new-jit-email@example.test", nil))
		var bindings, members int
		if err := f.st.Pool.QueryRow(ctx, "SELECT (SELECT count(*) FROM user_members WHERE user_id=$1 AND status='active'), (SELECT count(*) FROM members WHERE space_id=$2 AND type='human')", f.userID, f.spaceID).Scan(&bindings, &members); err != nil || bindings != 0 || members != 2 {
			t.Fatalf("JIT recreated a revoked binding: bindings=%d members=%d err=%v", bindings, members, err)
		}
	})
}

func TestDirectoryOIDCSSORejectsIdentityTransferAndRollsBackOnAuditFailure(t *testing.T) {
	t.Run("identity_transfer", func(t *testing.T) {
		f := newDirectorySSOFixture(t, "sub")
		_, err := f.st.Pool.Exec(context.Background(), "INSERT INTO external_identities (id,user_id,issuer,subject) VALUES ('ext_owned_elsewhere','usr_sso_http_owner',$1,'Stable-Object-1')", f.provider.issuer)
		if err != nil {
			t.Fatal(err)
		}
		requireDirectorySSODenied(t, f.login(t, "Stable-Object-1", "directory-user@example.test", nil))
	})
	t.Run("audit_failure", func(t *testing.T) {
		f := newDirectorySSOFixture(t, "sub")
		ctx := context.Background()
		if _, err := f.st.Pool.Exec(ctx, `CREATE FUNCTION reject_sso_audit() RETURNS trigger LANGUAGE plpgsql AS $$
		BEGIN IF NEW.action='auth.sso.login' THEN RAISE EXCEPTION 'test audit failure'; END IF; RETURN NEW; END $$;
		CREATE TRIGGER reject_sso_audit BEFORE INSERT ON audit_logs FOR EACH ROW EXECUTE FUNCTION reject_sso_audit()`); err != nil {
			t.Fatal(err)
		}
		if response := f.login(t, "Stable-Object-1", "directory-user@example.test", nil); response.Code < 500 {
			t.Fatalf("audit failure did not fail login: %d", response.Code)
		}
		var external, consumed, sessions int
		if err := f.st.Pool.QueryRow(ctx, `SELECT (SELECT count(*) FROM external_identities),
			(SELECT count(*) FROM sso_states WHERE consumed_at IS NOT NULL), (SELECT count(*) FROM sessions)`).Scan(&external, &consumed, &sessions); err != nil {
			t.Fatal(err)
		}
		if external != 0 || consumed != 0 || sessions != 0 {
			t.Fatalf("failed audit left identities=%d consumed states=%d sessions=%d", external, consumed, sessions)
		}
	})
}

func TestDirectorySSOConfigurationEnforcesTenantAndUniqueActiveConnection(t *testing.T) {
	f := newDirectorySSOFixture(t, "sub")
	ctx := context.Background()
	actor := authorization.WithHumanActor(ctx, f.owner.ID, "usr_sso_http_owner")
	for _, input := range []enterprise.DirectoryInput{
		{Name: "Duplicate", SSOConnectionID: f.connection.ID, SSOIdentityClaim: "sub"},
		{Name: "Email key", SSOConnectionID: f.connection.ID, SSOIdentityClaim: "email"},
		{Name: "Partial", SSOConnectionID: f.connection.ID},
		{Name: "Missing", SSOConnectionID: "con_missing", SSOIdentityClaim: "sub"},
	} {
		if _, err := f.svc.CreateDirectory(actor, f.owner.ID, f.spaceID, input); err == nil {
			t.Fatalf("unsafe directory configuration accepted: %s", input.Name)
		}
	}
	otherSpace, otherOwner, err := f.svc.Authorization.CreateSpace(ctx, "usr_sso_http_owner", "Other Space", "other-directory-space")
	if err != nil {
		t.Fatal(err)
	}
	otherCtx := authorization.WithHumanActor(ctx, otherOwner.ID, "usr_sso_http_owner")
	if _, err := f.svc.CreateDirectory(otherCtx, otherOwner.ID, otherSpace.ID, enterprise.DirectoryInput{
		Name: "Cross Space", SSOConnectionID: f.connection.ID, SSOIdentityClaim: "sub",
	}); err == nil {
		t.Fatal("cross-Space connection association was accepted")
	}
	_, err = f.st.Pool.Exec(ctx, "UPDATE directories SET space_id=$1 WHERE id=$2", otherSpace.ID, f.directory.ID)
	if err == nil {
		t.Fatal("database did not enforce the connection and directory Space constraint")
	}
}

func TestDirectorySSORechecksBindingAndAssociationAfterLockWait(t *testing.T) {
	for _, change := range []string{"binding", "association", "directory", "expired_binding"} {
		t.Run(change, func(t *testing.T) {
			f := newDirectorySSOFixture(t, "sub")
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			locked, release := make(chan struct{}), make(chan struct{})
			writer := make(chan error, 1)
			go func() {
				writer <- f.st.InTx(ctx, func(q *db.Queries) error {
					if _, err := q.LockUserForAuthorization(ctx, db.LockUserForAuthorizationParams{ID: f.userID}); err != nil {
						return err
					}
					close(locked)
					select {
					case <-release:
					case <-ctx.Done():
						return ctx.Err()
					}
					switch change {
					case "expired_binding":
						return nil
					case "binding":
						return q.RevokeUserMember(ctx, db.RevokeUserMemberParams{UserID: f.userID, MemberID: f.memberID})
					case "association":
						_, err := q.UpdateDirectoryConfiguration(ctx, db.UpdateDirectoryConfigurationParams{
							ID: f.directory.ID, Version: 1, Name: "Unlinked", SsoConnectionID: pgtype.Text{}, SsoIdentityClaim: pgtype.Text{},
						})
						return err
					default:
						return q.DisableDirectory(ctx, db.DisableDirectoryParams{ID: f.directory.ID})
					}
				})
			}()
			select {
			case <-locked:
			case <-ctx.Done():
				t.Fatal(ctx.Err())
			}
			result := make(chan *httptest.ResponseRecorder, 1)
			go func() { result <- f.login(t, "Stable-Object-1", "directory-user@example.test", nil) }()
			for {
				var waiting bool
				if err := f.st.Pool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM pg_stat_activity
					WHERE datname=current_database() AND wait_event_type='Lock' AND query LIKE '%users%FOR NO KEY UPDATE%')`).Scan(&waiting); err != nil {
					t.Fatal(err)
				}
				if waiting {
					break
				}
				select {
				case res := <-result:
					t.Fatalf("SSO bypassed the identity lock: %d", res.Code)
				case <-ctx.Done():
					t.Fatal(ctx.Err())
				case <-time.After(10 * time.Millisecond):
				}
			}
			if change == "expired_binding" {
				var expired bool
				err := f.st.Pool.QueryRow(ctx, `UPDATE user_members SET expires_at = (
					SELECT min(xact_start) FROM pg_stat_activity
					WHERE datname=current_database() AND wait_event_type='Lock' AND query LIKE '%users%FOR NO KEY UPDATE%'
				) + interval '1 microsecond' WHERE user_id=$1 AND member_id=$2 RETURNING expires_at < clock_timestamp()`,
					f.userID, f.memberID).Scan(&expired)
				if err != nil || !expired {
					t.Fatalf("did not place expiry between transaction start and lock release: %v", err)
				}
			}
			close(release)
			if err := <-writer; err != nil {
				t.Fatal(err)
			}
			select {
			case res := <-result:
				requireDirectorySSODenied(t, res)
			case <-ctx.Done():
				t.Fatal(ctx.Err())
			}
			var external, consumed int
			if err := f.st.Pool.QueryRow(ctx, "SELECT (SELECT count(*) FROM external_identities), (SELECT count(*) FROM sso_states WHERE consumed_at IS NOT NULL)").Scan(&external, &consumed); err != nil || external != 0 || consumed != 0 {
				t.Fatalf("denied concurrent login changed state: identities=%d states=%d err=%v", external, consumed, err)
			}
		})
	}
}
