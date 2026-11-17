package authorization

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/plystra/auth/internal/db"
	"github.com/plystra/auth/internal/store"
	"github.com/plystra/auth/migrations"
	"github.com/pressly/goose/v3"
)

func TestStandardRootDatabaseConstraintRejectsDuplicateRoots(t *testing.T) {
	t.Parallel()
	for _, status := range []string{"active", "suspended"} {
		t.Run(status, func(t *testing.T) {
			t.Parallel()
			ctx := context.Background()
			st, _, _, spaceID := newBindingFixture(t)
			if _, err := st.Pool.Exec(ctx, `INSERT INTO groups (id, space_id, name, status)
				VALUES ('grp_root_first', $1, 'First root', $2)`, spaceID, status); err != nil {
				t.Fatal(err)
			}
			_, err := st.Pool.Exec(ctx, `INSERT INTO groups (id, space_id, name)
				VALUES ('grp_root_second', $1, 'Second root')`, spaceID)
			var constraint *pgconn.PgError
			if !errors.As(err, &constraint) || constraint.Code != "23505" || constraint.ConstraintName != "groups_standard_root_unique" {
				t.Fatalf("database accepted a second live standard root: %v", err)
			}
		})
	}
}

func TestStandardRootDatabaseConstraintRejectsPromotionAndRestoration(t *testing.T) {
	t.Parallel()
	for _, change := range []string{"promote_child", "restore_tombstone"} {
		t.Run(change, func(t *testing.T) {
			t.Parallel()
			ctx := context.Background()
			st, _, _, spaceID := newBindingFixture(t)
			if _, err := st.Pool.Exec(ctx, `INSERT INTO groups (id, space_id, name, parent_id, status) VALUES
				('grp_root_live', $1, 'Live root', NULL, 'active'),
				('grp_root_child', $1, 'Child', 'grp_root_live', 'active'),
				('grp_root_removed', $1, 'Removed root', NULL, 'removed')`, spaceID); err != nil {
				t.Fatal(err)
			}
			var err error
			if change == "promote_child" {
				_, err = st.Pool.Exec(ctx, `UPDATE groups SET parent_id = NULL WHERE id = 'grp_root_child'`)
			} else {
				_, err = st.Pool.Exec(ctx, `UPDATE groups SET status = 'active' WHERE id = 'grp_root_removed'`)
			}
			var constraint *pgconn.PgError
			if !errors.As(err, &constraint) || constraint.Code != "23505" || constraint.ConstraintName != "groups_standard_root_unique" {
				t.Fatalf("database accepted a conflicting root mutation: %v", err)
			}
			var childParent, tombstoneStatus string
			if err := st.Pool.QueryRow(ctx, `SELECT
				(SELECT parent_id FROM groups WHERE id = 'grp_root_child'),
				(SELECT status FROM groups WHERE id = 'grp_root_removed')`).Scan(&childParent, &tombstoneStatus); err != nil {
				t.Fatal(err)
			}
			if childParent != "grp_root_live" || tombstoneStatus != "removed" {
				t.Fatal("conflicting mutation changed the persisted tree")
			}
		})
	}
}

func TestStandardRootDatabaseConstraintPreservesOtherTreesAndTombstones(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	st, svc, actor, spaceID := newBindingFixture(t)
	other, _, err := svc.CreateSpace(ctx, "usr_binding_actor", "Other root Space", "other-root-space")
	if err != nil {
		t.Fatal(err)
	}
	second, err := svc.CreateMember(ctx, actor.ID, "", spaceID, "Second Agent owner", "human", "single")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.Pool.Exec(ctx, `INSERT INTO groups (id, space_id, name, parent_id, status) VALUES
		('grp_root_tombstone', $1, 'Old root', NULL, 'removed'),
		('grp_root_current', $1, 'Current root', NULL, 'active'),
		('grp_root_branch_a', $1, 'Branch A', 'grp_root_current', 'active'),
		('grp_root_branch_b', $1, 'Branch B', 'grp_root_current', 'active'),
		('grp_root_other_space', $2, 'Other root', NULL, 'active')`, spaceID, other.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Pool.Exec(ctx, `INSERT INTO groups (id, space_id, name, kind, owner_member_id) VALUES
		('grp_root_agent_a', $1, 'Agent tree A', 'agents', $2),
		('grp_root_agent_b', $1, 'Agent tree B', 'agents', $3)`, spaceID, actor.ID, second.ID); err != nil {
		t.Fatal(err)
	}
	var roots, agentTrees, tombstones int
	if err := st.Pool.QueryRow(ctx, `SELECT
		count(*) FILTER (WHERE kind = 'standard' AND parent_id IS NULL AND status <> 'removed'),
		count(*) FILTER (WHERE kind = 'agents'),
		count(*) FILTER (WHERE status = 'removed') FROM groups WHERE space_id = $1`, spaceID).Scan(&roots, &agentTrees, &tombstones); err != nil {
		t.Fatal(err)
	}
	if roots != 1 || agentTrees != 2 || tombstones != 1 {
		t.Fatalf("root constraint changed independent trees or tombstones: roots=%d agents=%d tombstones=%d", roots, agentTrees, tombstones)
	}
}

func TestStandardRootDatabaseConstraintSerializesDirectWriters(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	st, _, _, spaceID := newBindingFixture(t)
	first, err := st.BeginIdempotency(ctx)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = first.Rollback(context.Background()) })
	if err := st.InTx(first.Context(ctx), func(q *db.Queries) error {
		_, err := q.CreateStandardGroup(ctx, db.CreateStandardGroupParams{ID: "grp_root_writer_a", SpaceID: spaceID, Name: "Writer A"})
		return err
	}); err != nil {
		t.Fatal(err)
	}
	completed := make(chan error, 1)
	go func() {
		_, err := st.Pool.Exec(ctx, `INSERT INTO groups (id, space_id, name) VALUES ('grp_root_writer_b', $1, 'Writer B')`, spaceID)
		completed <- err
	}()
	for {
		var waiting bool
		if err := st.Pool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM pg_stat_activity
			WHERE datname = current_database() AND wait_event_type = 'Lock')`).Scan(&waiting); err != nil {
			t.Fatal(err)
		}
		if waiting {
			break
		}
		select {
		case err := <-completed:
			t.Fatalf("second writer did not wait for the uncommitted root: %v", err)
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		case <-time.After(10 * time.Millisecond):
		}
	}
	if err := first.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-completed:
		var constraint *pgconn.PgError
		if !errors.As(err, &constraint) || constraint.Code != "23505" || constraint.ConstraintName != "groups_standard_root_unique" {
			t.Fatalf("second direct writer created a conflicting root: %v", err)
		}
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	var count int
	if err := st.Pool.QueryRow(ctx, `SELECT count(*) FROM groups WHERE space_id = $1`, spaceID).Scan(&count); err != nil || count != 1 {
		t.Fatalf("direct writers left %d groups: %v", count, err)
	}
}

func TestStandardRootMigrationPreservesDataAndRejectsConflictingHistory(t *testing.T) {
	t.Parallel()
	for _, duplicate := range []bool{false, true} {
		t.Run(fmt.Sprint("duplicates=", duplicate), func(t *testing.T) {
			t.Parallel()
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			database, err := integrationDB.CloneEmpty(ctx)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = database.Close(context.Background()) })
			admin, err := sql.Open("pgx", database.URL)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = admin.Close() })
			if _, err := admin.ExecContext(ctx, `GRANT USAGE, CREATE ON SCHEMA public TO plystra_auth_owner`); err != nil {
				t.Fatal(err)
			}
			owner, err := sql.Open("pgx", database.OwnerURL)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = owner.Close() })
			provider, err := goose.NewProvider(goose.DialectPostgres, owner, migrations.FS)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := provider.UpTo(ctx, 54); err != nil {
				t.Fatal(err)
			}
			if _, err := owner.ExecContext(ctx, `INSERT INTO spaces (id, name, slug) VALUES ('spc_root_upgrade', 'Upgrade', 'root-upgrade');
				INSERT INTO groups (id, space_id, name) VALUES ('grp_root_upgrade_a', 'spc_root_upgrade', 'Original root')`); err != nil {
				t.Fatal(err)
			}
			if duplicate {
				if _, err := owner.ExecContext(ctx, `INSERT INTO groups (id, space_id, name) VALUES ('grp_root_upgrade_b', 'spc_root_upgrade', 'Conflicting root')`); err != nil {
					t.Fatal(err)
				}
			}
			snapshot := func() string {
				t.Helper()
				var out string
				if err := owner.QueryRowContext(ctx, `SELECT jsonb_agg(to_jsonb(g) ORDER BY id)::text FROM groups g`).Scan(&out); err != nil {
					t.Fatal(err)
				}
				return out
			}
			before := snapshot()
			err = store.Migrate(ctx, database.OwnerURL)
			if duplicate {
				var constraint *pgconn.PgError
				if !errors.As(err, &constraint) || constraint.Code != "23505" {
					t.Fatalf("migration accepted conflicting legacy roots: %v", err)
				}
			} else {
				if err != nil {
					t.Fatal(err)
				}
				if err := store.Migrate(ctx, database.OwnerURL); err != nil {
					t.Fatalf("repeat migration failed: %v", err)
				}
			}
			var applied int
			var present bool
			if err := owner.QueryRowContext(ctx, `SELECT
				(SELECT count(*) FROM goose_db_version WHERE version_id = 55 AND is_applied),
				to_regclass('public.groups_standard_root_unique') IS NOT NULL`).Scan(&applied, &present); err != nil {
				t.Fatal(err)
			}
			if duplicate && (applied != 0 || present) || !duplicate && (applied != 1 || !present) || snapshot() != before {
				t.Fatal("migration rewrote group history or left an incorrect schema/version state")
			}
		})
	}
}
