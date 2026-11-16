package operator

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/plystra/auth/internal/apierr"
	"github.com/plystra/auth/internal/application"
	"github.com/plystra/auth/internal/audit"
	"github.com/plystra/auth/internal/db"
	"github.com/plystra/auth/internal/member"
)

type PublicApplicationReview struct {
	ID                         string    `json:"id"`
	SpaceID                    string    `json:"space_id"`
	Name                       string    `json:"name"`
	ClientID                   string    `json:"client_id"`
	RedirectURIs               []string  `json:"redirect_uris"`
	ManifestPermissions        []string  `json:"manifest_permissions"`
	PendingManifestPermissions []string  `json:"pending_manifest_permissions,omitempty"`
	ReviewStatus               string    `json:"review_status"`
	Status                     string    `json:"status"`
	CreatedAt                  time.Time `json:"created_at"`
}

func (s *Service) ListPublicApplications(ctx context.Context, raw string) ([]PublicApplicationReview, error) {
	var out []PublicApplicationReview
	err := s.Run(ctx, raw, "ops.applications.list", "ops:applications:manage", nil, func(q *db.Queries, _ Session) error {
		rows, err := q.ListPublicApplicationReviews(ctx)
		if err != nil {
			return err
		}
		out = make([]PublicApplicationReview, 0, len(rows))
		for _, row := range rows {
			item, err := publicApplicationReview(row.ID, row.SpaceID, row.Name, row.ClientID,
				row.RedirectUris, row.ManifestPermissions, row.PendingManifestPermissions, row.ReviewStatus, row.Status, row.CreatedAt.Time)
			if err != nil {
				return err
			}
			out = append(out, item)
		}
		return nil
	})
	return out, err
}

func (s *Service) ApprovePublicApplication(ctx context.Context, raw, applicationID string, permissions []string, digest []byte) (PublicApplicationReview, error) {
	if len(digest) != sha256.Size {
		return PublicApplicationReview{}, apierr.New("STEP_UP_REQUIRED", "Verify MFA for this manifest review.")
	}
	permissions = slices.Clone(permissions)
	if len(permissions) == 0 || len(permissions) > 100 {
		return PublicApplicationReview{}, apierr.New("VALIDATION_FAILED", "approved manifest must contain 1 to 100 permissions")
	}
	slices.Sort(permissions)
	for i, key := range permissions {
		if key == "" || strings.TrimSpace(key) != key || (i > 0 && key == permissions[i-1]) {
			return PublicApplicationReview{}, apierr.New("VALIDATION_FAILED", "approved manifest contains an invalid or duplicate permission")
		}
	}
	approved, err := json.Marshal(permissions)
	if err != nil {
		return PublicApplicationReview{}, err
	}
	var out PublicApplicationReview
	err = s.Run(ctx, raw, "ops.applications.approve", "ops:applications:manage", digest, func(q *db.Queries, current Session) error {
		row, err := q.LockPublicApplicationReview(ctx, db.LockPublicApplicationReviewParams{ApplicationID: applicationID})
		if errors.Is(err, pgx.ErrNoRows) {
			return apierr.New("NOT_FOUND", "public application was not found")
		}
		if err != nil {
			return err
		}
		if len(row.PendingManifestPermissions) == 0 {
			return apierr.New("CONFLICT", "application has no pending manifest review")
		}
		var requested []string
		if err := json.Unmarshal(row.PendingManifestPermissions, &requested); err != nil {
			return err
		}
		var previous []string
		if err := json.Unmarshal(row.ManifestPermissions, &previous); err != nil {
			return err
		}
		for _, key := range permissions {
			if !slices.Contains(requested, key) {
				return apierr.New("VALIDATION_FAILED", "approved manifest must be a subset of the request")
			}
			permission, err := q.GetPermissionByKey(ctx, db.GetPermissionByKeyParams{Key: key})
			if errors.Is(err, pgx.ErrNoRows) || (err == nil && (permission.Status == "disabled" ||
				permission.Status == "deprecated" && !slices.Contains(previous, key))) {
				return apierr.New("PERMISSION_DISABLED", "approved manifest contains an inactive permission")
			}
			if err != nil {
				return err
			}
			var kinds []string
			if err := json.Unmarshal(permission.PrincipalKinds, &kinds); err != nil {
				return err
			}
			if !slices.Contains(kinds, "application") {
				return apierr.New("VALIDATION_FAILED", "approved manifest contains a permission unavailable to applications")
			}
		}
		if err := application.NarrowManifestAuthorityTx(ctx, q, applicationID, previous, permissions, audit.SecurityEvent{
			ActorType: "operator_session", ActorID: current.UserID, UserID: current.UserID,
		}); err != nil {
			return err
		}
		changed, err := q.ApprovePublicApplicationReview(ctx, db.ApprovePublicApplicationReviewParams{
			ApplicationID: applicationID, ManifestPermissions: approved,
		})
		if err != nil {
			return err
		}
		if changed != 1 {
			return apierr.New("CONFLICT", "application review changed")
		}
		if err := audit.Write(ctx, q, "operator_session", current.UserID, "ops.application.approve", applicationID, "success"); err != nil {
			return err
		}
		out, err = publicApplicationReview(row.ID, row.SpaceID, row.Name, row.ClientID,
			row.RedirectUris, approved, nil, "approved", row.Status, row.CreatedAt.Time)
		return err
	})
	return out, err
}

func (s *Service) RejectPublicApplication(ctx context.Context, raw, applicationID string, digest []byte) error {
	if len(digest) != sha256.Size {
		return apierr.New("STEP_UP_REQUIRED", "Verify MFA for this manifest review.")
	}
	return s.Run(ctx, raw, "ops.applications.reject", "ops:applications:manage", digest, func(q *db.Queries, current Session) error {
		row, err := q.LockPublicApplicationReview(ctx, db.LockPublicApplicationReviewParams{ApplicationID: applicationID})
		if errors.Is(err, pgx.ErrNoRows) {
			return apierr.New("NOT_FOUND", "public application was not found")
		}
		if err != nil {
			return err
		}
		if len(row.PendingManifestPermissions) == 0 {
			return apierr.New("CONFLICT", "application has no pending manifest review")
		}
		changed, err := q.RejectPublicApplicationReview(ctx, db.RejectPublicApplicationReviewParams{ApplicationID: applicationID})
		if err != nil {
			return err
		}
		if changed != 1 {
			return apierr.New("CONFLICT", "application review changed")
		}
		return audit.Write(ctx, q, "operator_session", current.UserID, "ops.application.reject", applicationID, "success")
	})
}

// SuspendApplication stops both the OAuth client's delegated identities and
// the application's installation identities across every customer Space.
func (s *Service) SuspendApplication(ctx context.Context, raw, applicationID string, digest []byte) error {
	if len(digest) != sha256.Size {
		return apierr.New("STEP_UP_REQUIRED", "Verify MFA for this application suspension.")
	}
	return s.Run(ctx, raw, "ops.applications.suspend", "ops:applications:manage", digest, func(q *db.Queries, current Session) error {
		app, err := q.LockApplicationForUpdate(ctx, db.LockApplicationForUpdateParams{ApplicationID: applicationID})
		if errors.Is(err, pgx.ErrNoRows) {
			return apierr.New("NOT_FOUND", "application was not found")
		}
		if err != nil {
			return err
		}
		// Consent and installation creation hold the application lock; child
		// creation holds every owner. Read descendants only after acquiring all
		// root chains so a concurrent creation cannot escape this transaction.
		targets, err := q.ListApplicationSuspensionMembers(ctx, db.ListApplicationSuspensionMembersParams{ApplicationID: app.ID, ClientID: nullable(app.ClientID)})
		if err != nil {
			return err
		}
		memberIDs := make([]string, len(targets))
		for i, target := range targets {
			memberIDs[i] = target.ID
		}
		if err := member.LockChainsTx(ctx, q, memberIDs...); err != nil {
			return err
		}
		if err := q.SuspendApplicationGlobally(ctx, db.SuspendApplicationGloballyParams{ApplicationID: app.ID}); err != nil {
			return err
		}
		spaces := map[string]struct{}{}
		for _, target := range targets {
			action := "ops.application.agent.stop"
			if target.Type == "application" {
				if err := q.SuspendApplicationMember(ctx, db.SuspendApplicationMemberParams{MemberID: target.ID}); err != nil {
					return err
				}
				if err := member.SuspendOwnedAgentsTx(ctx, q, target.ID); err != nil {
					return err
				}
				action = "ops.application.installation.suspend"
			} else if err := member.SetAgentSubtreeStatusTx(ctx, q, target.ID, "suspended"); err != nil {
				return err
			}
			spaces[target.SpaceID] = struct{}{}
			if err := audit.WriteSecurityEvent(ctx, q, audit.SecurityEvent{
				ActorType: "operator_session", ActorID: current.UserID, UserID: current.UserID,
				Action: action, Outcome: "success", MemberID: target.ID, ApplicationID: app.ID,
				Metadata: map[string]string{"client_id": app.ClientID},
			}); err != nil {
				return err
			}
		}
		spaceIDs := make([]string, 0, len(spaces))
		for id := range spaces {
			spaceIDs = append(spaceIDs, id)
		}
		slices.Sort(spaceIDs)
		for _, id := range spaceIDs {
			if _, err := q.BumpPolicyVersion(ctx, db.BumpPolicyVersionParams{ID: id}); err != nil {
				return err
			}
		}
		return audit.Write(ctx, q, "operator_session", current.UserID, "ops.application.suspend", app.ID, "success")
	})
}

func publicApplicationReview(id, spaceID, name, clientID string, redirectsJSON, manifestJSON, pendingJSON []byte, reviewStatus, status string, createdAt time.Time) (PublicApplicationReview, error) {
	out := PublicApplicationReview{ID: id, SpaceID: spaceID, Name: name, ClientID: clientID,
		ReviewStatus: reviewStatus, Status: status, CreatedAt: createdAt}
	if err := json.Unmarshal(redirectsJSON, &out.RedirectURIs); err != nil {
		return PublicApplicationReview{}, err
	}
	if err := json.Unmarshal(manifestJSON, &out.ManifestPermissions); err != nil {
		return PublicApplicationReview{}, err
	}
	if len(pendingJSON) > 0 {
		if err := json.Unmarshal(pendingJSON, &out.PendingManifestPermissions); err != nil {
			return PublicApplicationReview{}, err
		}
	}
	return out, nil
}
