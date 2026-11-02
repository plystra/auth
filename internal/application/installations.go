package application

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/plystra/auth/internal/apierr"
	"github.com/plystra/auth/internal/audit"
	"github.com/plystra/auth/internal/authorization"
	"github.com/plystra/auth/internal/authz/engine"
	"github.com/plystra/auth/internal/db"
	"github.com/plystra/auth/internal/ids"
	"github.com/plystra/auth/internal/stepup"
)

type Installation struct {
	ID                  string    `json:"id"`
	ApplicationID       string    `json:"application_id"`
	ApplicationName     string    `json:"application_name"`
	SpaceID             string    `json:"space_id"`
	MemberID            string    `json:"member_id"`
	Scope               string    `json:"scope"`
	ApprovedPermissions []string  `json:"approved_permissions"`
	Status              string    `json:"status"`
	CreatedAt           time.Time `json:"created_at"`
}

// InstallPrivateSpace grants the entire current private manifest to one new
// application member. The installer must cover the positive authority delta.
func (s *Service) InstallPrivateSpace(ctx context.Context, actorMemberID, applicationID, spaceID string) (Installation, error) {
	if s == nil || s.Store == nil || s.Authorization == nil {
		return Installation{}, apierr.New("UNAVAILABLE", "application installation is unavailable")
	}
	var out Installation
	err := s.Store.InTx(ctx, func(q *db.Queries) error {
		decision, err := s.Authorization.CheckTx(ctx, q, authorization.CheckRequest{
			MemberID: actorMemberID, Permission: "auth.applications:manage", ResourceSpace: spaceID,
		})
		if err != nil {
			return err
		}
		if decision.Effect != engine.Allow {
			return &apierr.Error{Code: decision.Code, Message: "The authorization engine denied this operation."}
		}
		app, err := q.GetPrivateApplicationForInstall(ctx, db.GetPrivateApplicationForInstallParams{
			ApplicationID: applicationID, TargetSpaceID: spaceID,
		})
		if errors.Is(err, pgx.ErrNoRows) {
			return apierr.New("NOT_FOUND", "private application was not found in this Space tree")
		}
		if err != nil {
			return err
		}
		var manifest []string
		if err := json.Unmarshal(app.ManifestPermissions, &manifest); err != nil {
			return err
		}
		if len(manifest) == 0 {
			return apierr.New("VALIDATION_FAILED", "application manifest is empty")
		}
		catalogIDs := make([]string, 0, len(manifest))
		for _, key := range manifest {
			permission, err := q.GetPermissionByKey(ctx, db.GetPermissionByKeyParams{Key: key})
			if errors.Is(err, pgx.ErrNoRows) {
				return &apierr.Error{Code: "AUTHORITY_DELTA_NOT_COVERED", Message: "The application manifest contains an unknown permission.", Details: map[string]string{"permission": key}}
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
			catalogIDs = append(catalogIDs, permission.ID)
		}
		if _, required := stepup.RequirementFromContext(ctx); required {
			if s.StepUp == nil {
				return apierr.New("UNAVAILABLE", "step-up authentication is unavailable")
			}
			if err := s.StepUp.ConsumeStepUpTx(ctx, q); err != nil {
				return err
			}
		}
		memberID := string(ids.New[ids.MemberID]("mem"))
		roleID := string(ids.New[ids.RoleID]("rol"))
		installationID := string(ids.New[ids.InstallationID]("ins"))
		if _, err := q.CreateMemberWithPolicy(ctx, db.CreateMemberWithPolicyParams{
			ID: memberID, SpaceID: spaceID, Name: app.Name, Type: "application", BindingPolicy: "single",
		}); err != nil {
			return err
		}
		if _, err := q.CreateRole(ctx, db.CreateRoleParams{
			ID: roleID, SpaceID: spaceID, Name: "application:" + installationID,
			Description: "System-managed installation manifest", Managed: true,
		}); err != nil {
			return err
		}
		for _, permissionID := range catalogIDs {
			if err := q.GrantRolePermission(ctx, db.GrantRolePermissionParams{RoleID: roleID, PermissionID: permissionID}); err != nil {
				return err
			}
		}
		if _, err := q.CreateGrant(ctx, db.CreateGrantParams{
			ID: string(ids.New[ids.GrantID]("grt")), SpaceID: spaceID,
			RoleID:          pgtype.Text{String: roleID, Valid: true},
			GranteeMemberID: pgtype.Text{String: memberID, Valid: true},
			Scope:           "space", AnchorSpaceID: pgtype.Text{String: spaceID, Valid: true},
			GrantedBy: actorMemberID,
		}); err != nil {
			return err
		}
		if err := s.Authorization.CoverApplicationInstallationTx(ctx, q, actorMemberID, memberID, spaceID); err != nil {
			return err
		}
		row, err := q.CreateApplicationInstallation(ctx, db.CreateApplicationInstallationParams{
			ID: installationID, ApplicationID: applicationID, SpaceID: spaceID,
			MemberID: memberID, RoleID: roleID, Scope: "space",
			ApprovedPermissions: app.ManifestPermissions, InstalledBy: pgtype.Text{String: actorMemberID, Valid: true},
		})
		if err != nil {
			var pgErr *pgconn.PgError
			if errors.As(err, &pgErr) && pgErr.Code == "23505" {
				return apierr.New("CONFLICT", "application is already installed in this Space")
			}
			return err
		}
		if err := audit.Write(ctx, q, "member", actorMemberID, "application.install", row.ID, "success"); err != nil {
			return err
		}
		out = Installation{ID: row.ID, ApplicationID: row.ApplicationID, ApplicationName: app.Name,
			SpaceID: row.SpaceID, MemberID: row.MemberID, Scope: row.Scope,
			ApprovedPermissions: manifest, Status: row.Status, CreatedAt: row.CreatedAt.Time}
		return nil
	})
	return out, err
}

func (s *Service) ListInstallations(ctx context.Context, spaceID string) ([]Installation, error) {
	if s == nil || s.Store == nil {
		return nil, apierr.New("UNAVAILABLE", "application installations are unavailable")
	}
	rows, err := s.Store.Queries().ListApplicationInstallationsInSpace(ctx, db.ListApplicationInstallationsInSpaceParams{SpaceID: spaceID})
	if err != nil {
		return nil, err
	}
	installations := make([]Installation, 0, len(rows))
	for _, row := range rows {
		var permissions []string
		if err := json.Unmarshal(row.ApprovedPermissions, &permissions); err != nil {
			return nil, err
		}
		installations = append(installations, Installation{ID: row.ID, ApplicationID: row.ApplicationID,
			ApplicationName: row.ApplicationName, SpaceID: row.SpaceID, MemberID: row.MemberID,
			Scope: row.Scope, ApprovedPermissions: permissions, Status: row.Status, CreatedAt: row.CreatedAt.Time})
	}
	return installations, nil
}

func (s *Service) InstallationSpace(ctx context.Context, installationID string) (string, error) {
	if s == nil || s.Store == nil {
		return "", apierr.New("UNAVAILABLE", "application installations are unavailable")
	}
	spaceID, err := s.Store.Queries().GetInstallationTargetSpace(ctx, db.GetInstallationTargetSpaceParams{InstallationID: installationID})
	if errors.Is(err, pgx.ErrNoRows) {
		return "", apierr.New("NOT_FOUND", "installation was not found")
	}
	return spaceID, err
}

func (s *Service) ChangeInstallationStatus(ctx context.Context, actorMemberID, spaceID, installationID, action string) (Installation, error) {
	if s == nil || s.Store == nil || s.Authorization == nil {
		return Installation{}, apierr.New("UNAVAILABLE", "application installations are unavailable")
	}
	var desiredStatus string
	switch action {
	case "suspend":
		desiredStatus = "suspended"
	case "resume":
		desiredStatus = "active"
	case "uninstall":
		desiredStatus = "uninstalled"
	default:
		return Installation{}, apierr.New("VALIDATION_FAILED", "installation action is invalid")
	}
	var out Installation
	err := s.Store.InTx(ctx, func(q *db.Queries) error {
		row, err := q.LockInstallationForLifecycle(ctx, db.LockInstallationForLifecycleParams{
			InstallationID: installationID, SpaceID: spaceID,
		})
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
		if row.Status == "uninstalled" && action != "uninstall" {
			return apierr.New("NOT_FOUND", "installation was not found")
		}
		if action == "resume" {
			if row.ApplicationStatus != "active" {
				return apierr.New("CONFLICT", "application is not active")
			}
			if row.Status == "active" && row.MemberStatus == "active" {
				return installationResult(row, row.Status, &out)
			}
			if row.Status != "suspended" || row.MemberStatus != "suspended" {
				return apierr.New("CONFLICT", "installation member state is inconsistent")
			}
		}
		if action == "suspend" {
			if row.MemberStatus == "removed" {
				return apierr.New("CONFLICT", "installation member was removed")
			}
			if row.Status == "suspended" && row.MemberStatus == "suspended" {
				return installationResult(row, row.Status, &out)
			}
		}
		if action == "uninstall" && row.Status == "uninstalled" && row.MemberStatus == "removed" {
			return installationResult(row, row.Status, &out)
		}
		memberStatus := desiredStatus
		if action == "uninstall" {
			memberStatus = "removed"
		}
		updated, err := q.SetInstallationMemberStatus(ctx, db.SetInstallationMemberStatusParams{
			MemberID: row.MemberID, NewStatus: memberStatus,
		})
		if err != nil {
			return err
		}
		if row.MemberStatus != memberStatus && updated != 1 {
			return apierr.New("CONFLICT", "installation member state changed concurrently")
		}
		if row.Status != desiredStatus {
			updated, err = q.SetInstallationLifecycleStatus(ctx, db.SetInstallationLifecycleStatusParams{
				InstallationID: installationID, PreviousStatus: row.Status, NewStatus: desiredStatus,
			})
			if err != nil {
				return err
			}
			if updated != 1 {
				return apierr.New("CONFLICT", "installation state changed concurrently")
			}
		}
		if action == "resume" {
			if err := s.Authorization.CoverApplicationInstallationTx(ctx, q, actorMemberID, row.MemberID, row.SpaceID); err != nil {
				return err
			}
		}
		if err := audit.Write(ctx, q, "member", actorMemberID, "application.installation."+action, installationID, "success"); err != nil {
			return err
		}
		return installationResult(row, desiredStatus, &out)
	})
	return out, err
}

func installationResult(row db.LockInstallationForLifecycleRow, status string, out *Installation) error {
	var permissions []string
	if err := json.Unmarshal(row.ApprovedPermissions, &permissions); err != nil {
		return err
	}
	*out = Installation{
		ID: row.ID, ApplicationID: row.ApplicationID, ApplicationName: row.ApplicationName,
		SpaceID: row.SpaceID, MemberID: row.MemberID, Scope: row.Scope,
		ApprovedPermissions: permissions, Status: status, CreatedAt: row.CreatedAt.Time,
	}
	return nil
}
