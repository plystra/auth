package application

import (
	"context"
	"encoding/json"
	"errors"
	"net/url"
	"slices"
	"strings"
	"unicode/utf8"

	"github.com/jackc/pgx/v5"
	"github.com/plystra/auth/internal/apierr"
	"github.com/plystra/auth/internal/audit"
	"github.com/plystra/auth/internal/authorization"
	"github.com/plystra/auth/internal/authz/engine"
	"github.com/plystra/auth/internal/db"
)

type UpdateInput struct {
	Name                *string
	RedirectURIs        *[]string
	ManifestPermissions *[]string
}

func (s *Service) UpdatePrivate(ctx context.Context, actorMemberID, applicationID string, in UpdateInput) (PublishedApplication, error) {
	if s == nil || s.Store == nil || s.Authorization == nil {
		return PublishedApplication{}, apierr.New("UNAVAILABLE", "application updates are unavailable")
	}
	if in.Name == nil && in.RedirectURIs == nil && in.ManifestPermissions == nil {
		return PublishedApplication{}, apierr.New("VALIDATION_FAILED", "application update has no fields")
	}
	if in.Name != nil {
		name := strings.TrimSpace(*in.Name)
		if name == "" || utf8.RuneCountInString(name) > 120 {
			return PublishedApplication{}, apierr.New("VALIDATION_FAILED", "application name must contain 1 to 120 characters")
		}
		in.Name = &name
	}
	if in.RedirectURIs != nil {
		if len(*in.RedirectURIs) > 20 {
			return PublishedApplication{}, apierr.New("VALIDATION_FAILED", "application has too many redirect URIs")
		}
		for _, raw := range *in.RedirectURIs {
			parsed, err := url.Parse(raw)
			if err != nil || parsed.Host == "" || parsed.Fragment != "" || parsed.User != nil ||
				(parsed.Scheme != "https" && (parsed.Scheme != "http" || !isLoopbackHost(parsed.Hostname()))) {
				return PublishedApplication{}, apierr.New("VALIDATION_FAILED", "redirect URI must use HTTPS or HTTP on a loopback host")
			}
		}
	}
	if in.ManifestPermissions != nil {
		if len(*in.ManifestPermissions) == 0 || len(*in.ManifestPermissions) > 100 {
			return PublishedApplication{}, apierr.New("VALIDATION_FAILED", "application manifest must contain 1 to 100 permissions")
		}
		permissions := slices.Clone(*in.ManifestPermissions)
		slices.Sort(permissions)
		for index, key := range permissions {
			if strings.TrimSpace(key) != key || key == "" || (index > 0 && key == permissions[index-1]) {
				return PublishedApplication{}, apierr.New("VALIDATION_FAILED", "application manifest contains an invalid or duplicate permission")
			}
		}
		in.ManifestPermissions = &permissions
	}
	var out PublishedApplication
	err := s.Store.InTx(ctx, func(q *db.Queries) error {
		row, err := q.LockApplicationForUpdate(ctx, db.LockApplicationForUpdateParams{ApplicationID: applicationID})
		if errors.Is(err, pgx.ErrNoRows) {
			return apierr.New("NOT_FOUND", "application was not found")
		}
		if err != nil {
			return err
		}
		decision, err := s.Authorization.CheckTx(ctx, q, authorization.CheckRequest{
			MemberID: actorMemberID, Permission: "auth.applications:manage", ResourceSpace: row.SpaceID,
		})
		if err != nil {
			return err
		}
		if decision.Effect != engine.Allow {
			return &apierr.Error{Code: decision.Code, Message: "The authorization engine denied this operation."}
		}
		if row.Visibility != "private" {
			return apierr.New("CONFLICT", "public application changes require operator approval")
		}
		var oldRedirects, oldManifest []string
		if err := json.Unmarshal(row.RedirectUris, &oldRedirects); err != nil {
			return err
		}
		if err := json.Unmarshal(row.ManifestPermissions, &oldManifest); err != nil {
			return err
		}
		name, redirects, manifest := row.Name, oldRedirects, oldManifest
		if in.Name != nil {
			name = *in.Name
		}
		if in.RedirectURIs != nil {
			redirects = slices.Clone(*in.RedirectURIs)
		}
		if in.ManifestPermissions != nil {
			manifest = slices.Clone(*in.ManifestPermissions)
			for _, key := range manifest {
				permission, err := q.GetPermissionByKey(ctx, db.GetPermissionByKeyParams{Key: key})
				if errors.Is(err, pgx.ErrNoRows) {
					return apierr.New("VALIDATION_FAILED", "application manifest contains an unknown permission")
				}
				if err != nil {
					return err
				}
				if permission.Status == "disabled" {
					return apierr.New("PERMISSION_DISABLED", "application manifest contains a disabled permission")
				}
			}
		}
		if name == row.Name && slices.Equal(redirects, oldRedirects) && slices.Equal(manifest, oldManifest) {
			out = PublishedApplication{ID: row.ID, SpaceID: row.SpaceID, Name: name, ClientID: row.ClientID,
				RedirectURIs: redirects, ManifestPermissions: manifest, Visibility: row.Visibility,
				Status: row.Status, CreatedAt: row.CreatedAt.Time}
			return nil
		}
		manifestJSON, err := json.Marshal(manifest)
		if err != nil {
			return err
		}
		redirectJSON, err := json.Marshal(redirects)
		if err != nil {
			return err
		}
		removed := false
		for _, key := range oldManifest {
			if !slices.Contains(manifest, key) {
				removed = true
				break
			}
		}
		if removed {
			spaces, err := q.ListCurrentInstallationSpaces(ctx, db.ListCurrentInstallationSpacesParams{ApplicationID: applicationID})
			if err != nil {
				return err
			}
			if err := q.TrimInstallationApprovalsToManifest(ctx, db.TrimInstallationApprovalsToManifestParams{
				ApplicationID: applicationID, ManifestPermissions: manifestJSON,
			}); err != nil {
				return err
			}
			if err := q.TrimInstallationRolePermissionsToManifest(ctx, db.TrimInstallationRolePermissionsToManifestParams{
				ApplicationID: applicationID, ManifestPermissions: manifestJSON,
			}); err != nil {
				return err
			}
			if err := q.TrimAPIKeyGrantsToManifest(ctx, db.TrimAPIKeyGrantsToManifestParams{
				ApplicationID: applicationID, ManifestPermissions: manifestJSON,
			}); err != nil {
				return err
			}
			for _, spaceID := range spaces {
				if _, err := q.BumpPolicyVersion(ctx, db.BumpPolicyVersionParams{ID: spaceID}); err != nil {
					return err
				}
			}
		}
		updated, err := q.UpdatePrivateApplication(ctx, db.UpdatePrivateApplicationParams{
			ApplicationID: applicationID, Name: name, RedirectUris: redirectJSON, ManifestPermissions: manifestJSON,
		})
		if err != nil {
			return err
		}
		if err := audit.Write(ctx, q, "member", actorMemberID, "application.update", applicationID, "success"); err != nil {
			return err
		}
		out = PublishedApplication{ID: updated.ID, SpaceID: updated.SpaceID, Name: updated.Name, ClientID: updated.ClientID,
			RedirectURIs: redirects, ManifestPermissions: manifest, Visibility: updated.Visibility,
			Status: updated.Status, CreatedAt: updated.CreatedAt.Time}
		return nil
	})
	return out, err
}

func (s *Service) ApproveInstallationManifest(ctx context.Context, actorMemberID, spaceID, installationID string) (Installation, error) {
	if s == nil || s.Store == nil || s.Authorization == nil {
		return Installation{}, apierr.New("UNAVAILABLE", "application installation approval is unavailable")
	}
	var out Installation
	err := s.Store.InTx(ctx, func(q *db.Queries) error {
		identity, err := q.GetInstallationApplicationIdentity(ctx, db.GetInstallationApplicationIdentityParams{InstallationID: installationID})
		if errors.Is(err, pgx.ErrNoRows) || (err == nil && identity.SpaceID != spaceID) {
			return apierr.New("NOT_FOUND", "installation was not found in this Space")
		}
		if err != nil {
			return err
		}
		app, err := q.LockApplicationForUpdate(ctx, db.LockApplicationForUpdateParams{ApplicationID: identity.ApplicationID})
		if err != nil {
			return err
		}
		row, err := q.LockInstallationForLifecycle(ctx, db.LockInstallationForLifecycleParams{InstallationID: installationID, SpaceID: spaceID})
		if errors.Is(err, pgx.ErrNoRows) {
			return apierr.New("NOT_FOUND", "installation was not found in this Space")
		}
		if err != nil {
			return err
		}
		decision, err := s.Authorization.CheckTx(ctx, q, authorization.CheckRequest{
			MemberID: actorMemberID, Permission: "auth.applications:manage", ResourceSpace: row.SpaceID,
		})
		if err != nil {
			return err
		}
		if decision.Effect != engine.Allow {
			return &apierr.Error{Code: decision.Code, Message: "The authorization engine denied this operation."}
		}
		if row.ApplicationID != app.ID || row.Status == "uninstalled" || row.MemberStatus == "removed" {
			return apierr.New("NOT_FOUND", "installation was not found")
		}
		if app.Status != "active" {
			return apierr.New("CONFLICT", "application is not active")
		}
		if app.Visibility != "private" {
			return apierr.New("CONFLICT", "public application approval is unavailable")
		}
		var manifest, approved []string
		if err := json.Unmarshal(app.ManifestPermissions, &manifest); err != nil {
			return err
		}
		if err := json.Unmarshal(row.ApprovedPermissions, &approved); err != nil {
			return err
		}
		for _, key := range approved {
			if !slices.Contains(manifest, key) {
				return apierr.New("CONFLICT", "installation approvals are out of sync with the application manifest")
			}
		}
		if slices.Equal(manifest, approved) {
			return installationResult(row, row.Status, &out)
		}
		permissionIDs := make([]string, 0, len(manifest))
		for _, key := range manifest {
			if slices.Contains(approved, key) {
				continue
			}
			permission, err := q.GetPermissionByKey(ctx, db.GetPermissionByKeyParams{Key: key})
			if errors.Is(err, pgx.ErrNoRows) {
				return apierr.New("AUTHORITY_DELTA_NOT_COVERED", "application manifest contains an unknown permission")
			}
			if err != nil {
				return err
			}
			var kinds []string
			if err := json.Unmarshal(permission.PrincipalKinds, &kinds); err != nil {
				return err
			}
			if permission.Status != "active" || !slices.Contains(kinds, "application") {
				return &apierr.Error{Code: "AUTHORITY_DELTA_NOT_COVERED", Message: "The application cannot receive a manifest permission.", Details: map[string]string{"permission": key}}
			}
			permissionIDs = append(permissionIDs, permission.ID)
		}
		if err := s.Authorization.ApproveApplicationRoleTx(ctx, q, actorMemberID, row.MemberID, row.SpaceID, row.RoleID, permissionIDs); err != nil {
			return err
		}
		updated, err := q.SetInstallationApprovedPermissions(ctx, db.SetInstallationApprovedPermissionsParams{
			InstallationID: installationID, ApprovedPermissions: app.ManifestPermissions,
		})
		if err != nil {
			return err
		}
		if updated != 1 {
			return apierr.New("CONFLICT", "installation status changed concurrently")
		}
		if len(permissionIDs) > 0 {
			if _, err := q.BumpPolicyVersion(ctx, db.BumpPolicyVersionParams{ID: row.SpaceID}); err != nil {
				return err
			}
		}
		if err := audit.Write(ctx, q, "member", actorMemberID, "application.installation.approve", installationID, "success"); err != nil {
			return err
		}
		row.ApprovedPermissions = app.ManifestPermissions
		return installationResult(row, row.Status, &out)
	})
	return out, err
}
