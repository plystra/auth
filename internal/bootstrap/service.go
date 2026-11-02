package bootstrap

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/plystra/auth/internal/apierr"
	"github.com/plystra/auth/internal/application"
	"github.com/plystra/auth/internal/db"
	"github.com/plystra/auth/internal/ids"
	"github.com/plystra/auth/internal/store"
)

const (
	DefaultSpaceID       = "spc_01h00000000000000000000000"
	DefaultApplicationID = "app_01h00000000000000000000000"
)

type Result struct {
	SpaceID       string
	ApplicationID string
	APIKey        string
}

// Initialize creates the deployment defaults and one scoped bootstrap API key
// in a single transaction. A second invocation refuses to create another
// bootstrap key because the secret is intentionally only returned once.
func Initialize(ctx context.Context, st *store.Store, hmacKey []byte) (Result, error) {
	if st == nil {
		return Result{}, errors.New("bootstrap store is required")
	}
	rawKey, prefix, hash, err := application.GenerateSecret(hmacKey)
	if err != nil {
		return Result{}, err
	}
	scopes, err := json.Marshal([]string{"auth.authz:check", "auth.tokens:introspect"})
	if err != nil {
		return Result{}, err
	}
	restrictions, err := json.Marshal([]application.KeyRestriction{{SpaceID: DefaultSpaceID}})
	if err != nil {
		return Result{}, err
	}
	result := Result{SpaceID: DefaultSpaceID, ApplicationID: DefaultApplicationID}
	err = st.InTx(ctx, func(q *db.Queries) error {
		if err := q.EnsureDefaultSpace(ctx); err != nil {
			return err
		}
		if err := q.EnsureDefaultApplication(ctx); err != nil {
			return err
		}
		for _, ensure := range []func(context.Context) error{
			q.EnsureDefaultApplicationManifest,
			q.EnsureDefaultApplicationMember,
			q.EnsureDefaultApplicationRole,
			q.EnsureDefaultApplicationRolePermissions,
			q.EnsureDefaultApplicationGrant,
			q.EnsureDefaultApplicationInstallation,
		} {
			if err := ensure(ctx); err != nil {
				return err
			}
		}
		count, err := q.CountAPIKeysForApplication(ctx, db.CountAPIKeysForApplicationParams{ApplicationID: DefaultApplicationID})
		if err != nil {
			return err
		}
		if count != 0 {
			return apierr.New("CONFLICT", "the deployment has already been initialized")
		}
		_, err = q.CreateAPIKey(ctx, db.CreateAPIKeyParams{
			ID:                    string(ids.New[ids.APIKeyID]("key")),
			ApplicationID:         DefaultApplicationID,
			Name:                  "bootstrap",
			Prefix:                prefix,
			SecretHash:            hash,
			Scopes:                scopes,
			RestrictTo:            restrictions,
			ExpiresAt:             pgtype.Timestamptz{Time: time.Now().UTC().Add(365 * 24 * time.Hour), Valid: true},
			AllowSubjectAssertion: false,
		})
		if err != nil {
			return err
		}
		result.APIKey = rawKey
		return nil
	})
	if err != nil {
		return Result{}, err
	}
	return result, nil
}
