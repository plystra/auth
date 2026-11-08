package operator

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"regexp"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/jackc/pgx/v5"
	"github.com/plystra/auth/internal/apierr"
	"github.com/plystra/auth/internal/audit"
	"github.com/plystra/auth/internal/db"
	"github.com/plystra/auth/internal/ids"
)

var permissionKeyPattern = regexp.MustCompile(`^[a-z][a-z0-9._-]*:[a-z][a-z0-9._-]*$`)

type CreatePermissionInput struct {
	Key            string   `json:"key"`
	Description    string   `json:"description,omitempty"`
	Risk           string   `json:"risk,omitempty"`
	PrincipalKinds []string `json:"principal_kinds,omitempty"`
	Delegable      *bool    `json:"delegable,omitempty"`
	AgentApproval  string   `json:"agent_approval,omitempty"`
}

type Permission struct {
	ID             string    `json:"id"`
	Key            string    `json:"key"`
	Description    string    `json:"description"`
	Risk           string    `json:"risk"`
	PrincipalKinds []string  `json:"principal_kinds"`
	Delegable      bool      `json:"delegable"`
	AgentApproval  string    `json:"agent_approval"`
	Status         string    `json:"status"`
	CreatedAt      time.Time `json:"created_at"`
}

func (s *Service) CreatePermission(ctx context.Context, raw string, in CreatePermissionInput, digest []byte) (Permission, error) {
	if len(digest) != sha256.Size {
		return Permission{}, apierr.New("VALIDATION_FAILED", "permission creation requires a request-bound step-up digest")
	}
	if len(in.Key) > 128 || !permissionKeyPattern.MatchString(in.Key) || strings.HasPrefix(in.Key, "auth.") {
		return Permission{}, apierr.New("VALIDATION_FAILED", "permission key must be a business resource:action identifier")
	}
	in.Description = strings.TrimSpace(in.Description)
	if utf8.RuneCountInString(in.Description) > 500 {
		return Permission{}, apierr.New("VALIDATION_FAILED", "permission description is too long")
	}
	if in.Risk == "" {
		in.Risk = "low"
	}
	if in.Risk != "low" && in.Risk != "high" && in.Risk != "critical" {
		return Permission{}, apierr.New("VALIDATION_FAILED", "permission risk is invalid")
	}
	if in.PrincipalKinds == nil {
		in.PrincipalKinds = []string{"human", "agent", "application"}
	}
	if len(in.PrincipalKinds) == 0 || len(in.PrincipalKinds) > 3 {
		return Permission{}, apierr.New("VALIDATION_FAILED", "permission principal_kinds must be a nonempty subset")
	}
	slices.Sort(in.PrincipalKinds)
	for index, kind := range in.PrincipalKinds {
		if (kind != "human" && kind != "agent" && kind != "application") || (index > 0 && kind == in.PrincipalKinds[index-1]) {
			return Permission{}, apierr.New("VALIDATION_FAILED", "permission principal_kinds contains an invalid or duplicate kind")
		}
	}
	delegable := in.Delegable == nil || *in.Delegable
	if in.AgentApproval == "" {
		in.AgentApproval = "none"
		if in.Risk == "critical" {
			in.AgentApproval = "required"
		}
	}
	if in.AgentApproval != "none" && in.AgentApproval != "required" {
		return Permission{}, apierr.New("VALIDATION_FAILED", "permission agent_approval is invalid")
	}
	kinds, err := json.Marshal(in.PrincipalKinds)
	if err != nil {
		return Permission{}, err
	}
	var out Permission
	err = s.Run(ctx, raw, "ops.permissions.create", "ops:permissions:manage", digest, func(q *db.Queries, current Session) error {
		row, err := q.CreateCatalogPermission(ctx, db.CreateCatalogPermissionParams{
			ID: string(ids.New[ids.PermissionID]("prm")), Key: in.Key, Description: in.Description,
			Risk: in.Risk, PrincipalKinds: kinds, Delegable: delegable, AgentApproval: in.AgentApproval,
		})
		if errors.Is(err, pgx.ErrNoRows) {
			return apierr.New("CONFLICT", "permission key already exists")
		}
		if err != nil {
			return err
		}
		out, err = permissionFromRow(row.ID, row.Key, row.Description, row.Risk, row.PrincipalKinds, row.Delegable, row.AgentApproval, row.Status, row.CreatedAt.Time)
		if err != nil {
			return err
		}
		return audit.Write(ctx, q, "operator_session", current.UserID, "ops.permission.create", out.ID, "success")
	})
	return out, err
}

func (s *Service) ListPermissions(ctx context.Context, raw string) ([]Permission, error) {
	var out []Permission
	err := s.Run(ctx, raw, "ops.permissions.list", "ops:permissions:manage", nil, func(q *db.Queries, _ Session) error {
		rows, err := q.ListCatalogPermissions(ctx)
		if err != nil {
			return err
		}
		out = make([]Permission, 0, len(rows))
		for _, row := range rows {
			item, err := permissionFromRow(row.ID, row.Key, row.Description, row.Risk, row.PrincipalKinds, row.Delegable, row.AgentApproval, row.Status, row.CreatedAt.Time)
			if err != nil {
				return err
			}
			out = append(out, item)
		}
		return nil
	})
	return out, err
}

func permissionFromRow(id, key, description, risk string, kindsJSON []byte, delegable bool, approval, status string, created time.Time) (Permission, error) {
	var kinds []string
	if err := json.Unmarshal(kindsJSON, &kinds); err != nil {
		return Permission{}, err
	}
	return Permission{ID: id, Key: key, Description: description, Risk: risk, PrincipalKinds: kinds, Delegable: delegable, AgentApproval: approval, Status: status, CreatedAt: created}, nil
}
