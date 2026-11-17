package agent

import (
	"context"
	"testing"
	"time"

	"github.com/plystra/auth/internal/authorization"
	"github.com/plystra/auth/internal/db"
)

func TestCreatorBindingRevocationSerializesWithAgentCreation(t *testing.T) {
	for _, kind := range []string{"direct", "descendant"} {
		t.Run(kind, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			st, authz, owner, _ := newAgentFixture(t)
			agents := &Service{Store: st}
			input := CreateInput{OwnerMemberID: owner.ID, CreatedByUser: "usr_agent_owner", Name: "concurrent-binding-agent", ExpiresAt: time.Now().Add(time.Hour)}
			var parent Agent
			if kind == "descendant" {
				var err error
				parent, _, err = agents.Create(ctx, input)
				if err != nil {
					t.Fatal(err)
				}
				input.OwnerMemberID, input.CreatedByUser, input.ExpiresAt = parent.ID, "", parent.ExpiresAt
			}
			created, release := make(chan Agent, 1), make(chan struct{})
			creation := make(chan error, 1)
			go func() {
				creation <- st.InTx(ctx, func(q *db.Queries) error {
					item, err := agents.CreateOAuthTx(ctx, q, input)
					if err != nil {
						return err
					}
					created <- item
					select {
					case <-release:
						return nil
					case <-ctx.Done():
						return ctx.Err()
					}
				})
			}()
			var item Agent
			select {
			case item = <-created:
			case err := <-creation:
				t.Fatalf("could not establish creation barrier: %v", err)
			}
			revocation := make(chan error, 1)
			go func() { revocation <- authz.RevokeOwnBinding(ctx, "usr_agent_owner", owner.ID) }()
			for {
				var waiting bool
				if err := st.Pool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM pg_stat_activity WHERE datname = current_database()
					AND wait_event_type = 'Lock' AND query LIKE '%members%FOR UPDATE%')`).Scan(&waiting); err != nil {
					t.Fatal(err)
				}
				if waiting {
					break
				}
				select {
				case err := <-revocation:
					t.Fatalf("binding revocation did not serialize with creation: %v", err)
				case <-ctx.Done():
					t.Fatal(ctx.Err())
				case <-time.After(10 * time.Millisecond):
				}
			}
			close(release)
			if err := <-creation; err != nil {
				t.Fatal(err)
			}
			if err := <-revocation; err != nil {
				t.Fatal(err)
			}
			assertMemberStatus(t, st, item.ID, "suspended")
			if parent.ID != "" {
				assertMemberStatus(t, st, parent.ID, "suspended")
				if _, _, err := agents.Create(ctx, CreateInput{OwnerMemberID: parent.ID, Name: "after-revocation", ExpiresAt: parent.ExpiresAt}); err == nil {
					t.Fatal("suspended creator branch accepted a new child")
				}
			}
			userContext := authorization.WithAgentGrantUser(ctx, owner.ID, "usr_agent_owner")
			if _, _, err := agents.CreateManaged(userContext, CreateInput{OwnerMemberID: owner.ID, CreatedByUser: "usr_agent_owner", Name: "unbound-creator"}, authz); err == nil {
				t.Fatal("unbound creator retained managed Agent creation rights")
			} else {
				assertAgentError(t, err, "UNAUTHENTICATED")
			}
		})
	}
}
