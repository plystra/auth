package principal

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/plystra/auth/internal/agent"
	"github.com/plystra/auth/internal/application"
	"github.com/plystra/auth/internal/authorization"
	"github.com/plystra/auth/internal/authz/engine"
	"github.com/plystra/auth/internal/db"
	"github.com/plystra/auth/internal/member"
	"github.com/plystra/auth/internal/security"
	"github.com/plystra/auth/internal/session"
	"github.com/plystra/auth/internal/store"
)

type applicationListsFixture struct {
	store                                *store.Store
	authz                                *authorization.Service
	apps                                 *application.Service
	sessions                             *session.Service
	handler                              http.Handler
	ownerID, actorID, parentID, spaceID  string
	token, userID, appID, installationID string
}

func newApplicationListsFixture(t *testing.T, kind string) applicationListsFixture {
	t.Helper()
	ctx := context.Background()
	st, authz, apps, ownerID, spaceID, sessions, handler, appID := installationFixture(t, []string{"auth.authz:check"})
	installed, err := apps.InstallSpace(ctx, ownerID, appID, spaceID)
	if err != nil {
		t.Fatal(err)
	}
	f := applicationListsFixture{store: st, authz: authz, apps: apps, sessions: sessions, handler: handler,
		ownerID: ownerID, actorID: ownerID, spaceID: spaceID, userID: "usr_principal_actor", appID: appID, installationID: installed.ID}
	if kind == "human" {
		tokens, err := sessions.CreateForMember(ctx, f.userID, ownerID, nil, "test", 1)
		if err != nil {
			t.Fatal(err)
		}
		f.token = tokens.AccessToken
		return f
	}
	// These persisted fixtures exercise management authorization, not the
	// separately gated empty-deployment OAuth delegation scenario.
	agents := &agent.Service{Store: st}
	expiresAt := time.Now().Add(time.Hour).Truncate(time.Second)
	for _, name := range []string{"List manager parent", "List manager caller"} {
		created, _, err := agents.Create(ctx, agent.CreateInput{OwnerMemberID: f.actorID, Name: name, ExpiresAt: expiresAt})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := authz.ReplaceAgentGrants(ctx, f.actorID, spaceID, created.ID, []string{"auth.applications:manage", "auth.members:read"}, "space", spaceID); err != nil {
			t.Fatal(err)
		}
		f.parentID, f.actorID = f.actorID, created.ID
	}
	issued, err := sessions.CreateAgentAccess(ctx, f.actorID, spaceID, security.DefaultApplicationAudience)
	if err != nil {
		t.Fatal(err)
	}
	f.token, f.userID = issued.AccessToken, ""
	return f
}

func (f applicationListsFixture) request(ctx context.Context, list string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, "/v1/spaces/"+f.spaceID+"/"+list, nil).WithContext(ctx)
	req.Header.Set("Authorization", "Bearer "+f.token)
	out := httptest.NewRecorder()
	f.handler.ServeHTTP(out, req)
	return out
}

func applicationListPermission(list string) string {
	if list == "applications" {
		return "auth.applications:manage"
	}
	return "auth.members:read"
}

func TestApplicationListsHTTPUsesCurrentAuthority(t *testing.T) {
	t.Parallel()
	for _, kind := range []string{"human", "agent"} {
		for _, change := range []string{"active", "deprecated", "group_scope", "disabled", "principal_kind", "envelope", "token_scope", "owner_permission", "owner_inactive"} {
			if kind == "human" && slices.Contains([]string{"token_scope", "owner_permission", "owner_inactive"}, change) {
				continue
			}
			t.Run(kind+"/"+change, func(t *testing.T) {
				t.Parallel()
				ctx := context.Background()
				f := newApplicationListsFixture(t, kind)
				var err error
				switch change {
				case "deprecated", "disabled":
					_, err = f.store.Pool.Exec(ctx, `UPDATE permissions SET status = $1 WHERE key IN ('auth.applications:manage', 'auth.members:read')`, change)
				case "principal_kind":
					_, err = f.store.Pool.Exec(ctx, `UPDATE permissions SET principal_kinds = '["application"]' WHERE key IN ('auth.applications:manage', 'auth.members:read')`)
				case "envelope":
					_, err = f.store.Pool.Exec(ctx, `INSERT INTO space_envelopes (space_id) VALUES ($1)`, f.spaceID)
				case "group_scope", "owner_permission":
					id := f.actorID
					var groupID string
					if change == "owner_permission" {
						id = f.ownerID
					} else {
						group, groupErr := f.authz.CreateGroup(ctx, f.ownerID, f.spaceID, "Only this team", "")
						if groupErr != nil {
							t.Fatal(groupErr)
						}
						groupID = group.ID
					}
					_, err = f.store.Pool.Exec(ctx, `UPDATE authorization_grants SET revoked_at = now() WHERE grantee_member_id = $1`, id)
					if err == nil && change == "group_scope" {
						_, err = f.store.Pool.Exec(ctx, `INSERT INTO authorization_grants
							(id, space_id, permission_keys, grantee_member_id, scope, anchor_group_id, granted_by)
							VALUES ('grt_app_lists_group', $1, '["auth.applications:manage","auth.members:read"]', $2, 'group_tree', $3, $4)`, f.spaceID, id, groupID, f.ownerID)
					}
				case "owner_inactive":
					err = f.store.InTx(ctx, func(q *db.Queries) error {
						return q.SetMemberStatus(ctx, db.SetMemberStatusParams{ID: f.ownerID, SpaceID: f.spaceID, Status: "suspended"})
					})
				case "token_scope":
					issued, issueErr := f.sessions.CreateAgentDelegatedAccess(ctx, f.actorID, f.spaceID, security.DefaultApplicationAudience, f.parentID, []string{"auth.authz:check"}, 0)
					err, f.token = issueErr, issued.AccessToken
				}
				if err != nil {
					t.Fatal(err)
				}
				for _, list := range []string{"applications", "installations"} {
					request := authorization.CheckRequest{MemberID: f.actorID, Permission: applicationListPermission(list), ResourceSpace: f.spaceID}
					if change == "token_scope" {
						request.TokenScopes = []string{"auth.authz:check"}
					}
					decision, _, err := f.authz.Check(ctx, request)
					if err != nil {
						t.Fatal(err)
					}
					out := f.request(ctx, list)
					if change == "active" || change == "deprecated" {
						id := f.appID
						if list == "installations" {
							id = f.installationID
						}
						if decision.Effect != engine.Allow || out.Code != http.StatusOK || !strings.Contains(out.Body.String(), id) {
							t.Fatalf("%s active authority denied: check=%s HTTP=%d", list, decision.Code, out.Code)
						}
					} else if decision.Effect != engine.Deny || out.Code != http.StatusForbidden || !strings.Contains(out.Body.String(), `"code":"`+decision.Code+`"`) || strings.Contains(out.Body.String(), `"data"`) {
						t.Fatalf("%s differs from unified check or disclosed data: check=%s HTTP=%d", list, decision.Code, out.Code)
					}
				}
			})
		}
	}
}

func TestApplicationListsHTTPRequiresEachListsOwnPermission(t *testing.T) {
	t.Parallel()
	for _, kind := range []string{"human", "agent"} {
		for _, allowed := range []string{"applications", "installations"} {
			t.Run(kind+"/"+allowed, func(t *testing.T) {
				t.Parallel()
				ctx := context.Background()
				f := newApplicationListsFixture(t, kind)
				if _, err := f.store.Pool.Exec(ctx, `UPDATE authorization_grants SET revoked_at = now() WHERE grantee_member_id = $1`, f.actorID); err != nil {
					t.Fatal(err)
				}
				seedTestInlineGrant(t, f.store, f.spaceID, f.ownerID, f.actorID, applicationListPermission(allowed))
				for _, list := range []string{"applications", "installations"} {
					want := http.StatusForbidden
					if list == allowed {
						want = http.StatusOK
					}
					out := f.request(ctx, list)
					if out.Code != want || want == http.StatusForbidden && strings.Contains(out.Body.String(), `"data"`) {
						t.Fatalf("%s holding only %s: status=%d want=%d", list, applicationListPermission(allowed), out.Code, want)
					}
				}
			})
		}
	}
}

func TestApplicationListsHTTPPreservesConfigurationLifecycle(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	f := newApplicationListsFixture(t, "human")
	public, err := f.apps.Register(ctx, f.ownerID, application.RegisterInput{SpaceID: f.spaceID, Name: "Pending publisher", ManifestPermissions: []string{"auth.authz:check"}, Visibility: "public"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.apps.ChangeInstallationStatus(ctx, f.ownerID, f.spaceID, f.installationID, "suspend"); err != nil {
		t.Fatal(err)
	}
	out := f.request(ctx, "applications")
	var published struct {
		Data []application.PublishedApplication `json:"data"`
	}
	if out.Code != http.StatusOK || json.Unmarshal(out.Body.Bytes(), &published) != nil || !slices.ContainsFunc(published.Data, func(app application.PublishedApplication) bool {
		return app.ID == public.ID && app.ReviewStatus == "pending" && len(app.ManifestPermissions) == 0 && slices.Equal(app.PendingManifestPermissions, []string{"auth.authz:check"})
	}) {
		t.Fatalf("list hid or changed pending publisher configuration: status=%d", out.Code)
	}
	out = f.request(ctx, "installations")
	var installed struct {
		Data []application.Installation `json:"data"`
	}
	if out.Code != http.StatusOK || json.Unmarshal(out.Body.Bytes(), &installed) != nil || len(installed.Data) != 1 || installed.Data[0].ID != f.installationID || installed.Data[0].Status != "suspended" {
		t.Fatalf("list hid suspended installation configuration: status=%d", out.Code)
	}
	if _, err := f.apps.ChangeInstallationStatus(ctx, f.ownerID, f.spaceID, f.installationID, "uninstall"); err != nil {
		t.Fatal(err)
	}
	out = f.request(ctx, "installations")
	if out.Code != http.StatusOK || json.Unmarshal(out.Body.Bytes(), &installed) != nil || installed.Data == nil || len(installed.Data) != 0 {
		t.Fatalf("list retained uninstalled configuration: status=%d", out.Code)
	}
}

func TestApplicationListsHTTPRechecksAuthorityAfterWaiting(t *testing.T) {
	t.Parallel()
	for _, list := range []string{"applications", "installations"} {
		for _, change := range []string{"binding", "account", "owner", "parent", "grant", "owner_grant", "disabled", "expires_after_node_wait"} {
			t.Run(list+"/"+change, func(t *testing.T) {
				t.Parallel()
				ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
				defer cancel()
				kind := "human"
				if slices.Contains([]string{"owner", "parent", "owner_grant"}, change) {
					kind = "agent"
				}
				f := newApplicationListsFixture(t, kind)
				expiresAt := time.Now().UTC().Add(3 * time.Second)
				if change == "expires_after_node_wait" {
					if err := f.store.InTx(ctx, func(q *db.Queries) error {
						return q.BindUserMember(ctx, db.BindUserMemberParams{UserID: f.userID, MemberID: f.actorID, ExpiresAt: pgtype.Timestamptz{Time: expiresAt, Valid: true}})
					}); err != nil {
						t.Fatal(err)
					}
				}
				barrier, err := f.store.BeginIdempotency(ctx)
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = barrier.Rollback(context.Background()) })
				if err := f.store.InTx(barrier.Context(ctx), func(q *db.Queries) error {
					if change == "expires_after_node_wait" {
						_, err := q.LockSpaceForAuthorization(ctx, db.LockSpaceForAuthorizationParams{ID: f.spaceID})
						return err
					}
					if err := member.LockChainsTx(ctx, q, f.actorID); err != nil {
						return err
					}
					switch change {
					case "binding":
						return q.RevokeUserMember(ctx, db.RevokeUserMemberParams{UserID: f.userID, MemberID: f.actorID})
					case "account":
						return q.SetUserStatus(ctx, db.SetUserStatusParams{ID: f.userID, Status: "disabled"})
					case "owner", "parent":
						id := f.ownerID
						if change == "parent" {
							id = f.parentID
						}
						return q.SetMemberStatus(ctx, db.SetMemberStatusParams{ID: id, SpaceID: f.spaceID, Status: "suspended"})
					case "disabled":
						return nil
					default:
						id := f.actorID
						if change == "owner_grant" {
							id = f.ownerID
						}
						grants, err := q.ListMemberAssignments(ctx, db.ListMemberAssignmentsParams{MemberID: pgtype.Text{String: id, Valid: true}})
						if err != nil {
							return err
						}
						for _, grant := range grants {
							if err := q.RevokeGrant(ctx, db.RevokeGrantParams{ID: grant.GrantID}); err != nil {
								return err
							}
						}
						return nil
					}
				}); err != nil {
					t.Fatal(err)
				}
				completed := make(chan error, 1)
				var out *httptest.ResponseRecorder
				go func() {
					out = f.request(ctx, list)
					completed <- fmt.Errorf("HTTP status %d", out.Code)
				}()
				waitForGrantIdentityLock(t, ctx, f.store, completed)
				if change == "disabled" {
					if _, err := f.store.Pool.Exec(ctx, `UPDATE permissions SET status = 'disabled' WHERE key = $1`, applicationListPermission(list)); err != nil {
						t.Fatal(err)
					}
				}
				if change == "expires_after_node_wait" {
					timer := time.NewTimer(time.Until(expiresAt.Add(25 * time.Millisecond)))
					defer timer.Stop()
					select {
					case <-timer.C:
					case <-ctx.Done():
						t.Fatal(ctx.Err())
					}
				}
				if err := barrier.Commit(ctx); err != nil {
					t.Fatal(err)
				}
				select {
				case <-completed:
				case <-ctx.Done():
					t.Fatal(ctx.Err())
				}
				status, code := http.StatusForbidden, "NO_MATCHING_PERMISSION"
				switch change {
				case "binding", "account", "expires_after_node_wait":
					status, code = http.StatusUnauthorized, "UNAUTHENTICATED"
				case "owner", "parent":
					code = "OWNER_INACTIVE"
				case "owner_grant":
					code = "OWNER_ENVELOPE_EXCLUDED"
				case "disabled":
					code = "PERMISSION_DISABLED"
				}
				if out.Code != status || !strings.Contains(out.Body.String(), `"code":"`+code+`"`) || strings.Contains(out.Body.String(), `"data"`) {
					t.Fatalf("%s retained revoked %s authority: status=%d want=%s", list, change, out.Code, code)
				}
			})
		}
	}
}

func TestApplicationListsHTTPRetainsIdentityLocksUntilCommit(t *testing.T) {
	t.Parallel()
	for _, list := range []string{"applications", "installations"} {
		for _, change := range []string{"binding", "account", "owner", "parent"} {
			t.Run(list+"/"+change, func(t *testing.T) {
				t.Parallel()
				ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
				defer cancel()
				kind := "human"
				if change == "owner" || change == "parent" {
					kind = "agent"
				}
				f := newApplicationListsFixture(t, kind)
				read, err := f.store.BeginIdempotency(ctx)
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = read.Rollback(context.Background()) })
				if out := f.request(read.Context(ctx), list); out.Code != http.StatusOK {
					t.Fatalf("valid list denied: status=%d", out.Code)
				}
				writer := make(chan error, 1)
				go func() {
					if change == "binding" {
						writer <- f.authz.RevokeOwnBinding(ctx, f.userID, f.actorID)
						return
					}
					writer <- f.store.InTx(ctx, func(q *db.Queries) error {
						if change == "account" {
							return q.SetUserStatus(ctx, db.SetUserStatusParams{ID: f.userID, Status: "disabled"})
						}
						id := f.ownerID
						if change == "parent" {
							id = f.parentID
						}
						return q.SetMemberStatus(ctx, db.SetMemberStatusParams{ID: id, SpaceID: f.spaceID, Status: "suspended"})
					})
				}()
				waitForGrantIdentityLock(t, ctx, f.store, writer)
				if err := read.Commit(ctx); err != nil {
					t.Fatal(err)
				}
				select {
				case err := <-writer:
					if err != nil {
						t.Fatal(err)
					}
				case <-ctx.Done():
					t.Fatal(ctx.Err())
				}
				out := f.request(ctx, list)
				if out.Code == http.StatusOK || strings.Contains(out.Body.String(), f.appID) || strings.Contains(out.Body.String(), f.installationID) {
					t.Fatalf("next list retained revoked identity: status=%d", out.Code)
				}
			})
		}
	}
}

func TestApplicationListsDomainUsesIdentityAndTokenScope(t *testing.T) {
	t.Parallel()
	for _, kind := range []string{"human", "agent"} {
		changes := []string{"token_scope", "binding", "wrong_user", "missing_authorizer"}
		if kind == "agent" {
			changes = []string{"token_scope", "owner", "missing_authorizer"}
		}
		for _, change := range changes {
			t.Run(kind+"/"+change, func(t *testing.T) {
				t.Parallel()
				ctx := context.Background()
				f := newApplicationListsFixture(t, kind)
				if kind == "human" {
					ctx = authorization.WithHumanActor(ctx, f.actorID, f.userID)
				}
				code := "UNAUTHENTICATED"
				switch change {
				case "token_scope":
					ctx = authorization.WithTokenScopes(ctx, f.actorID, []string{"auth.authz:check"})
					code = "TOKEN_SCOPE_EXCLUDED"
				case "wrong_user":
					ctx = authorization.WithHumanActor(ctx, "mem_different", f.userID)
				case "binding":
					if err := f.authz.RevokeOwnBinding(ctx, f.userID, f.actorID); err != nil {
						t.Fatal(err)
					}
				case "owner":
					if err := f.store.InTx(ctx, func(q *db.Queries) error {
						return q.SetMemberStatus(ctx, db.SetMemberStatusParams{ID: f.ownerID, SpaceID: f.spaceID, Status: "suspended"})
					}); err != nil {
						t.Fatal(err)
					}
					code = "OWNER_INACTIVE"
				case "missing_authorizer":
					f.apps = &application.Service{Store: f.store}
					code = "UNAVAILABLE"
				}
				published, err := f.apps.ListPublished(ctx, f.actorID, f.spaceID)
				assertPrincipalError(t, err, code)
				if published != nil {
					t.Fatal("domain denial returned application data")
				}
				installed, err := f.apps.ListInstallations(ctx, f.actorID, f.spaceID)
				assertPrincipalError(t, err, code)
				if installed != nil {
					t.Fatal("domain denial returned installation data")
				}
			})
		}
	}
}

func TestApplicationListsHTTPKeepsSpaceIsolationAndEmptyArrays(t *testing.T) {
	t.Parallel()
	for _, kind := range []string{"human", "agent"} {
		t.Run(kind, func(t *testing.T) {
			t.Parallel()
			ctx := context.Background()
			f := newApplicationListsFixture(t, kind)
			other, actor, err := f.authz.CreateSpace(ctx, "usr_principal_actor", "Other publisher", "other-publisher")
			if err != nil {
				t.Fatal(err)
			}
			seedTestInlineGrant(t, f.store, other.ID, actor.ID, actor.ID, "auth.applications:manage")
			original := f
			f.spaceID = other.ID
			for _, list := range []string{"applications", "installations"} {
				if out := f.request(ctx, list); out.Code != http.StatusForbidden || strings.Contains(out.Body.String(), `"data"`) {
					t.Fatalf("%s switched to another membership or crossed Space: status=%d", list, out.Code)
				}
			}
			f.token = manifestToken(t, f.sessions, actor.ID)
			for _, list := range []string{"applications", "installations"} {
				out := f.request(ctx, list)
				var response struct {
					Data []json.RawMessage `json:"data"`
				}
				if out.Code != http.StatusOK || json.Unmarshal(out.Body.Bytes(), &response) != nil || response.Data == nil || len(response.Data) != 0 {
					t.Fatalf("authorized empty %s did not return []: status=%d", list, out.Code)
				}
			}
			for _, list := range []string{"applications", "installations"} {
				out := original.request(ctx, list)
				if out.Code != http.StatusOK || !strings.Contains(out.Body.String(), original.appID) {
					t.Fatalf("original authorized %s changed: status=%d", list, out.Code)
				}
			}
		})
	}
}

func TestApplicationListsHTTPFailsClosedOnPersistedDecodeErrors(t *testing.T) {
	t.Parallel()
	for _, field := range []string{"redirects", "manifest", "pending_manifest", "approved_permissions"} {
		t.Run(field, func(t *testing.T) {
			t.Parallel()
			ctx := context.Background()
			f := newApplicationListsFixture(t, "human")
			// A later malformed row must not leak earlier successfully decoded rows.
			second, err := f.apps.Register(ctx, f.ownerID, application.RegisterInput{SpaceID: f.spaceID, Name: "Later app", ManifestPermissions: []string{"auth.authz:check"}})
			if err != nil {
				t.Fatal(err)
			}
			installed, err := f.apps.InstallSpace(ctx, f.ownerID, second.ID, f.spaceID)
			if err != nil {
				t.Fatal(err)
			}
			list := "applications"
			switch field {
			case "redirects":
				_, err = f.store.Pool.Exec(ctx, `UPDATE applications SET redirect_uris = '[1]' WHERE id = $1`, second.ID)
			case "manifest":
				_, err = f.store.Pool.Exec(ctx, `UPDATE applications SET manifest_permissions = '[1]' WHERE id = $1`, second.ID)
			case "pending_manifest":
				_, err = f.store.Pool.Exec(ctx, `UPDATE applications SET visibility = 'public', review_status = 'approved', pending_manifest_permissions = '[1]' WHERE id = $1`, second.ID)
			case "approved_permissions":
				list = "installations"
				_, err = f.store.Pool.Exec(ctx, `UPDATE application_installations SET approved_permissions = '[1]' WHERE id = $1`, installed.ID)
			}
			if err != nil {
				t.Fatal(err)
			}
			out := f.request(ctx, list)
			if out.Code != http.StatusServiceUnavailable || !strings.Contains(out.Body.String(), "UNAVAILABLE") || strings.Contains(out.Body.String(), `"data"`) {
				t.Fatalf("%s returned malformed or partial data: status=%d", list, out.Code)
			}
			if list == "applications" {
				rows, err := f.apps.ListPublished(ctx, f.actorID, f.spaceID)
				if err == nil || rows != nil {
					t.Fatal("application domain returned partial results")
				}
			} else {
				rows, err := f.apps.ListInstallations(ctx, f.actorID, f.spaceID)
				if err == nil || rows != nil {
					t.Fatal("installation domain returned partial results")
				}
			}
		})
	}
}
