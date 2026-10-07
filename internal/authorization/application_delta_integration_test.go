package authorization

import (
	"context"
	"errors"
	"testing"

	"github.com/plystra/auth/internal/apierr"
)

func TestApplicationGrantPositiveDeltaRemainsRejectedAndUncommitted(t *testing.T) {
	ctx := context.Background()
	st, svc, actor, spaceID := newBindingFixture(t)
	applicationID := "mem_application_delta"
	if _, err := st.Pool.Exec(ctx, `
		INSERT INTO members (id, space_id, name, kind, type, binding_policy, status, version)
		VALUES ($1, $2, 'Installed application', 'service', 'application', 'single', 'active', 1)
	`, applicationID, spaceID); err != nil {
		t.Fatal(err)
	}

	_, err := svc.CreateInlineGrant(ctx, actor.ID, spaceID, applicationID, []string{"auth.members:read"}, "space", spaceID)
	var public *apierr.Error
	if !errors.As(err, &public) || public.Code != "AUTHORITY_DELTA_NOT_COVERED" {
		t.Fatalf("application grant error = %v, want AUTHORITY_DELTA_NOT_COVERED", err)
	}
	var count int
	if err := st.Pool.QueryRow(ctx, `SELECT count(*) FROM authorization_grants WHERE grantee_member_id = $1 AND revoked_at IS NULL`, applicationID).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatalf("rejected application grant persisted %d active rows", count)
	}
}
