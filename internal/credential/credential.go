package credential

import (
	"context"
	"strings"

	"github.com/plystra/auth/internal/agent"
	"github.com/plystra/auth/internal/apierr"
	"github.com/plystra/auth/internal/application"
	"github.com/plystra/auth/internal/enterprise"
	"github.com/plystra/auth/internal/operator"
	"github.com/plystra/auth/internal/route"
	"github.com/plystra/auth/internal/secret"
	"github.com/plystra/auth/internal/session"
)

type PrincipalParser struct {
	Sessions *session.Service
	Agents   *agent.Service
}

func (p PrincipalParser) Parse(ctx context.Context, authorization string) error {
	raw, err := bearer(authorization)
	if err != nil {
		return err
	}
	if err := rejectPrefix("principal", raw); err != nil {
		return err
	}
	if strings.HasPrefix(raw, "ply_ag_") {
		if p.Agents == nil {
			return apierr.New("UNAVAILABLE", "agent credentials are unavailable")
		}
		_, err := p.Agents.AuthenticateKey(ctx, raw)
		return err
	}
	if p.Sessions == nil {
		return apierr.New("UNAVAILABLE", "authentication is unavailable")
	}
	_, active, err := p.Sessions.Introspect(ctx, raw, sessionAudience)
	if err != nil {
		return err
	}
	if !active {
		return apierr.New("UNAUTHENTICATED", "the access token is no longer active")
	}
	return nil
}

type ServerParser struct {
	Applications *application.Service
}

func (p ServerParser) Parse(ctx context.Context, authorization string) error {
	raw, err := bearer(authorization)
	if err != nil {
		return err
	}
	if err := rejectPrefix("server", raw); err != nil {
		return err
	}
	if p.Applications == nil {
		return apierr.New("UNAVAILABLE", "application credentials are unavailable")
	}
	_, err = p.Applications.AuthenticateKey(ctx, raw)
	return err
}

type OpsParser struct {
	Operators *operator.Service
}

func (p OpsParser) Parse(ctx context.Context, authorization string) error {
	raw, err := bearer(authorization)
	if err != nil {
		return err
	}
	if err := rejectPrefix("ops", raw); err != nil {
		return err
	}
	if p.Operators == nil {
		return apierr.New("UNAVAILABLE", "operations credentials are unavailable")
	}
	return p.Operators.Validate(ctx, raw)
}

type Validator struct {
	Principal PrincipalParser
	Server    ServerParser
	Ops       OpsParser
	Directory *enterprise.Service
}

func (v Validator) Validate(ctx context.Context, plane, authorization string) error {
	switch plane {
	case "principal":
		if directory := route.SCIMDirectoryID(ctx); directory != "" {
			raw, err := bearer(authorization)
			if err != nil {
				return err
			}
			if v.Directory == nil {
				return apierr.New("UNAVAILABLE", "directory authentication is unavailable")
			}
			return v.Directory.ValidateDirectoryToken(ctx, directory, secret.New(raw))
		}
		return v.Principal.Parse(ctx, authorization)
	case "server":
		return v.Server.Parse(ctx, authorization)
	case "ops":
		return v.Ops.Parse(ctx, authorization)
	default:
		return apierr.New("CREDENTIAL_PLANE_MISMATCH", "credential plane is not supported")
	}
}

func Kind(authorization string) string {
	parts := strings.Fields(authorization)
	if len(parts) != 2 {
		return "unknown"
	}
	switch {
	case strings.HasPrefix(parts[1], "ply_sk_"):
		return "application_api_key"
	case strings.HasPrefix(parts[1], "ply_ag_"):
		return "agent_key"
	case strings.HasPrefix(parts[1], "ply_ops_"):
		return "operator_session"
	case strings.HasPrefix(parts[1], "ply_rt_"):
		return "refresh_token"
	default:
		return "access_token"
	}
}

func ValidatePrefix(plane, raw string) error {
	return rejectPrefix(plane, raw)
}

func bearer(value string) (string, error) {
	parts := strings.Fields(strings.TrimSpace(value))
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
		return "", apierr.New("UNAUTHENTICATED", "a valid bearer credential is required")
	}
	return parts[1], nil
}

func rejectPrefix(plane, raw string) error {
	switch plane {
	case "principal":
		if strings.HasPrefix(raw, "ply_sk_") {
			return apierr.New("CREDENTIAL_PLANE_MISMATCH", "application API keys are not accepted on the principal plane")
		}
		if strings.HasPrefix(raw, "ply_ops_") {
			return apierr.New("CREDENTIAL_PLANE_MISMATCH", "operations credentials are not accepted on the principal plane")
		}
	case "server":
		if strings.HasPrefix(raw, "ply_ag_") || strings.HasPrefix(raw, "ply_ops_") || strings.HasPrefix(raw, "ply_rt_") {
			return apierr.New("CREDENTIAL_PLANE_MISMATCH", "this credential is not accepted on the server plane")
		}
	case "ops":
		if strings.HasPrefix(raw, "ply_sk_") {
			return apierr.New("CREDENTIAL_PLANE_MISMATCH", "application API keys are not accepted on the operations plane")
		}
		if strings.HasPrefix(raw, "ply_ag_") || strings.HasPrefix(raw, "ply_rt_") {
			return apierr.New("CREDENTIAL_PLANE_MISMATCH", "member credentials are not accepted on the operations plane")
		}
	}
	return nil
}

const sessionAudience = "default"
