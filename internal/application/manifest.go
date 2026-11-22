package application

import (
	"context"
	"encoding/json"
	"errors"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/jackc/pgx/v5"
	"github.com/plystra/auth/internal/apierr"
	"github.com/plystra/auth/internal/audit"
	"github.com/plystra/auth/internal/authorization"
	"github.com/plystra/auth/internal/authz/engine"
	"github.com/plystra/auth/internal/db"
	"github.com/plystra/auth/internal/stepup"
)

type UpdateInput struct {
	Name                *string
	RedirectURIs        *[]string
	ManifestPermissions *[]string
	HumanOIDCEnabled    *bool
}

func (s *Service) Update(ctx context.Context, actorMemberID, applicationID string, in UpdateInput) (PublishedApplication, error) {
	if s == nil || s.Store == nil || s.Authorization == nil {
		return PublishedApplication{}, apierr.New("UNAVAILABLE", "application updates are unavailable")
	}
	if in.Name == nil && in.RedirectURIs == nil && in.ManifestPermissions == nil && in.HumanOIDCEnabled == nil {
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
		if len(*in.ManifestPermissions) > 100 {
			return PublishedApplication{}, apierr.New("VALIDATION_FAILED", "application manifest exceeds 100 permissions")
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
		decision, err := s.Authorization.CheckNodeTx(ctx, q, authorization.CheckRequest{
			MemberID: actorMemberID, Permission: "auth.applications:manage", ResourceSpace: row.SpaceID,
		})
		if err != nil {
			return err
		}
		if decision.Effect != engine.Allow {
			return &apierr.Error{Code: decision.Code, Message: "The authorization engine denied this operation."}
		}
		var oldRedirects, oldManifest, oldPending []string
		if err := json.Unmarshal(row.RedirectUris, &oldRedirects); err != nil {
			return err
		}
		if err := json.Unmarshal(row.ManifestPermissions, &oldManifest); err != nil {
			return err
		}
		if len(row.PendingManifestPermissions) > 0 {
			if err := json.Unmarshal(row.PendingManifestPermissions, &oldPending); err != nil {
				return err
			}
		}
		name, redirects, manifest := row.Name, oldRedirects, oldManifest
		pending, reviewStatus := oldPending, row.ReviewStatus
		humanOIDC := row.HumanOidcEnabled
		if in.HumanOIDCEnabled != nil {
			if _, required := stepup.RequirementFromContext(ctx); required {
				if s.StepUp == nil {
					return apierr.New("UNAVAILABLE", "step-up authentication is unavailable")
				}
				if err := s.StepUp.ConsumeStepUpTx(ctx, q); err != nil {
					return err
				}
			}
			humanOIDC = *in.HumanOIDCEnabled
		}
		if in.Name != nil {
			name = *in.Name
		}
		if in.RedirectURIs != nil {
			redirects = slices.Clone(*in.RedirectURIs)
		}
		if in.ManifestPermissions != nil {
			if len(*in.ManifestPermissions) == 0 && !humanOIDC && !row.HumanOidcEnabled {
				return apierr.New("VALIDATION_FAILED", "an empty manifest requires human OIDC sign-in")
			}
			for _, key := range *in.ManifestPermissions {
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
			if row.Visibility == "private" {
				manifest = slices.Clone(*in.ManifestPermissions)
			} else if !slices.Equal(*in.ManifestPermissions, oldManifest) || oldPending != nil || reviewStatus == "rejected" {
				// Pending review never replaces an already approved runtime manifest.
				pending = slices.Clone(*in.ManifestPermissions)
				if reviewStatus != "approved" {
					reviewStatus = "pending"
				}
			}
		}
		if name == row.Name && slices.Equal(redirects, oldRedirects) && slices.Equal(manifest, oldManifest) &&
			slices.Equal(pending, oldPending) && (pending == nil) == (oldPending == nil) && reviewStatus == row.ReviewStatus && humanOIDC == row.HumanOidcEnabled {
			out = PublishedApplication{ID: row.ID, SpaceID: row.SpaceID, Name: name, ClientID: row.ClientID,
				RedirectURIs: redirects, ManifestPermissions: manifest, Visibility: row.Visibility,
				PendingManifestPermissions: pending, ReviewStatus: reviewStatus, Status: row.Status, CreatedAt: row.CreatedAt.Time, HumanOIDCEnabled: humanOIDC}
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
		if err := NarrowManifestAuthorityTx(ctx, q, applicationID, oldManifest, manifest, audit.SecurityEvent{
			ActorType: "member", ActorID: actorMemberID,
		}); err != nil {
			return err
		}
		var pendingJSON []byte
		if pending != nil {
			pendingJSON, err = json.Marshal(pending)
			if err != nil {
				return err
			}
		}
		updated, err := q.UpdateApplication(ctx, db.UpdateApplicationParams{
			ApplicationID: applicationID, Name: name, RedirectUris: redirectJSON, ManifestPermissions: manifestJSON,
			PendingManifestPermissions: pendingJSON, ReviewStatus: reviewStatus, HumanOidcEnabled: humanOIDC,
		})
		if err != nil {
			return err
		}
		if err := audit.WriteSecurityEvent(ctx, q, audit.SecurityEvent{
			ActorType: "member", ActorID: actorMemberID, MemberID: actorMemberID, ApplicationID: applicationID,
			Action: "application.update", Outcome: "success", Permission: "auth.applications:manage",
			Metadata: map[string]string{"human_oidc_enabled": strconv.FormatBool(humanOIDC)},
			Resource: audit.Resource{Type: "application", ID: applicationID, SpaceID: updated.SpaceID},
		}); err != nil {
			return err
		}
		out = PublishedApplication{ID: updated.ID, SpaceID: updated.SpaceID, Name: updated.Name, ClientID: updated.ClientID,
			RedirectURIs: redirects, ManifestPermissions: manifest, Visibility: updated.Visibility,
			PendingManifestPermissions: pending, ReviewStatus: updated.ReviewStatus, Status: updated.Status, CreatedAt: updated.CreatedAt.Time, HumanOIDCEnabled: updated.HumanOidcEnabled}
		return nil
	})
	return out, err
}

// NarrowManifestAuthorityTx is shared by publisher saves and operator reviews.
// The caller holds the application lock and publishes the new manifest in this
// transaction. Expansion never restores an installation approval or key grant.
func NarrowManifestAuthorityTx(ctx context.Context, q *db.Queries, applicationID string, previous, next []string, actor audit.SecurityEvent) error {
	removed := false
	for _, key := range previous {
		if !slices.Contains(next, key) {
			removed = true
			break
		}
	}
	if !removed {
		return nil
	}
	manifest, err := json.Marshal(next)
	if err != nil {
		return err
	}
	installations, err := q.ListManifestInstallationMembers(ctx, db.ListManifestInstallationMembersParams{ApplicationID: applicationID})
	if err != nil {
		return err
	}
	if err := q.TrimInstallationApprovalsToManifest(ctx, db.TrimInstallationApprovalsToManifestParams{
		ApplicationID: applicationID, ManifestPermissions: manifest,
	}); err != nil {
		return err
	}
	if err := q.TrimInstallationRolePermissionsToManifest(ctx, db.TrimInstallationRolePermissionsToManifestParams{
		ApplicationID: applicationID, ManifestPermissions: manifest,
	}); err != nil {
		return err
	}
	if err := q.TrimAPIKeyGrantsToManifest(ctx, db.TrimAPIKeyGrantsToManifestParams{
		ApplicationID: applicationID, ManifestPermissions: manifest,
	}); err != nil {
		return err
	}
	var previousSpace string
	for _, installation := range installations {
		if installation.SpaceID != previousSpace {
			if _, err := q.BumpPolicyVersion(ctx, db.BumpPolicyVersionParams{ID: installation.SpaceID}); err != nil {
				return err
			}
			previousSpace = installation.SpaceID
		}
		event := actor
		event.Action, event.Outcome = "application.installation.manifest.narrow", "success"
		event.MemberID, event.ApplicationID = installation.MemberID, applicationID
		event.Resource = audit.Resource{Type: "installation", ID: installation.ID, SpaceID: installation.SpaceID, GroupID: installation.AnchorGroupID.String}
		if err := audit.WriteSecurityEvent(ctx, q, event); err != nil {
			return err
		}
	}
	return nil
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
		decision, err := s.Authorization.CheckNodeTx(ctx, q, authorization.CheckRequest{
			MemberID: actorMemberID, Permission: "auth.applications:manage", ResourceSpace: row.SpaceID, ResourceGroup: row.AnchorGroupID.String,
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
		if app.Visibility == "public" && app.ReviewStatus != "approved" {
			return apierr.New("CONFLICT", "public application has no approved manifest")
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
		added := make([]string, 0, len(manifest))
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
			added = append(added, key)
		}
		if err := s.Authorization.CoverApplicationManifestTx(ctx, q, actorMemberID, row.MemberID, row.SpaceID, row.Scope, row.AnchorGroupID.String, added); err != nil {
			return err
		}
		for _, permissionID := range permissionIDs {
			if err := q.GrantRolePermission(ctx, db.GrantRolePermissionParams{RoleID: row.RoleID, PermissionID: permissionID}); err != nil {
				return err
			}
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
		if err := writeInstallationAuditTx(ctx, q, actorMemberID, row.MemberID, row.ApplicationID, row.SpaceID, row.AnchorGroupID.String, installationID, "application.installation.approve"); err != nil {
			return err
		}
		row.ApprovedPermissions = app.ManifestPermissions
		return installationResult(row, row.Status, &out)
	})
	return out, err
}
