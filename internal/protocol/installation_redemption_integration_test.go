package protocol

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/plystra/auth/internal/session"
)

func TestOAuthInstallationLifecycleSerializesWithRedemption(t *testing.T) {
	for _, grant := range []string{"authorization_code", "refresh_token"} {
		for _, action := range []string{"suspend", "uninstall", "suspend_resume"} {
			for _, first := range []string{"Lifecycle", "Redemption"} {
				t.Run(grant+"/"+action+"/"+first+"First", func(t *testing.T) {
					f := newRedemptionFixture(t)
					ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
					defer cancel()
					if _, err := f.store.Pool.Exec(ctx, `INSERT INTO authorization_grants
						(id, space_id, permission_keys, grantee_member_id, scope, anchor_space_id, granted_by)
						VALUES ('grt_redemption_lifecycle', $1, '["auth.applications:manage"]', $2, 'space', $1, $2)`, f.owner.SpaceID, f.owner.ID); err != nil {
						t.Fatal(err)
					}
					mutate := func(ctx context.Context) error {
						operation := action
						if operation == "suspend_resume" {
							operation = "suspend"
						}
						if _, err := f.applications.ChangeInstallationStatus(ctx, f.owner.ID, f.owner.SpaceID, "ins_redemption", operation); err != nil {
							return err
						}
						if action == "suspend_resume" {
							_, err := f.applications.ChangeInstallationStatus(ctx, f.owner.ID, f.owner.SpaceID, "ins_redemption", "resume")
							return err
						}
						return nil
					}
					response := make(chan *httptest.ResponseRecorder, 1)
					if first == "Lifecycle" {
						mutation, err := f.store.BeginIdempotency(ctx)
						if err != nil {
							t.Fatal(err)
						}
						t.Cleanup(func() { _ = mutation.Rollback(context.Background()) })
						if err := mutate(mutation.Context(ctx)); err != nil {
							t.Fatal(err)
						}
						go func() { response <- f.request(ctx, f.form(grant)) }()
						waitForRedemptionLock(t, ctx, f.store, response)
						if err := mutation.Commit(ctx); err != nil {
							t.Fatal(err)
						}
						out := <-response
						if action == "suspend_resume" {
							delegationAuditToken(t, out)
						} else {
							if out.Code != http.StatusBadRequest || !strings.Contains(out.Body.String(), "invalid_grant") || strings.Contains(out.Body.String(), "access_token") {
								t.Fatalf("exchange ignored committed installation %s: status=%d", action, out.Code)
							}
							f.assertUnchanged(t)
						}
						return
					}
					entered, release := make(chan struct{}), make(chan struct{})
					f.sessions.Settings = func(ctx context.Context) (session.Settings, error) {
						close(entered)
						select {
						case <-release:
							return session.Settings{AccessTTL: time.Minute}, nil
						case <-ctx.Done():
							return session.Settings{}, ctx.Err()
						}
					}
					go func() { response <- f.request(ctx, f.form(grant)) }()
					select {
					case <-entered:
					case out := <-response:
						t.Fatalf("exchange failed before the issuance barrier: status=%d", out.Code)
					case <-ctx.Done():
						t.Fatal(ctx.Err())
					}
					changed := make(chan error, 1)
					go func() { changed <- mutate(ctx) }()
					waitForRedemptionLock(t, ctx, f.store, response)
					select {
					case err := <-changed:
						t.Fatalf("installation lifecycle bypassed the signing transaction: error=%v", err)
					default:
					}
					close(release)
					out := <-response
					delegationAuditToken(t, out)
					if err := <-changed; err != nil {
						t.Fatal(err)
					}
					f.sessions.Settings = func(context.Context) (session.Settings, error) {
						return session.Settings{AccessTTL: time.Minute}, nil
					}
					var issued struct {
						Refresh string `json:"refresh_token"`
					}
					if err := json.Unmarshal(out.Body.Bytes(), &issued); err != nil || issued.Refresh == "" {
						t.Fatal("successful exchange omitted the refresh credential")
					}
					if grant == "authorization_code" {
						f.code += "-next"
						f.issueCode(t, "cod_redemption_next")
					} else {
						f.refresh = issued.Refresh
					}
					view := tokenTransportFixture{store: f.store, memberID: f.agent.ID}
					before := view.state(t, ctx)
					next := f.request(ctx, f.form(grant))
					if action == "suspend_resume" {
						delegationAuditToken(t, next)
					} else {
						if next.Code != http.StatusBadRequest || !strings.Contains(next.Body.String(), "invalid_grant") || strings.Contains(next.Body.String(), "access_token") {
							t.Fatalf("subsequent exchange ignored installation %s: status=%d", action, next.Code)
						}
						if diff := cmp.Diff(before, view.state(t, ctx)); diff != "" {
							t.Fatalf("rejected exchange consumed credentials (-before +after):\n%s", diff)
						}
					}
				})
			}
		}
	}
}
