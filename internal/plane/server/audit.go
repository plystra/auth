package server

import (
	"context"
	"strings"

	"github.com/plystra/auth/internal/apierr"
	"github.com/plystra/auth/internal/audit"
	"github.com/plystra/auth/internal/authorization"
	"github.com/plystra/auth/internal/authz/engine"
	"github.com/plystra/auth/internal/db"
)

type businessAuditInput struct {
	Authorization string `header:"Authorization"`
	Body          struct {
		Subject       CheckSubject          `json:"subject"`
		Action        string                `json:"action" minLength:"1" maxLength:"128" pattern:"^[a-z][a-z0-9_.:-]{0,127}$"`
		Resource      businessAuditResource `json:"resource"`
		Outcome       string                `json:"outcome" enum:"success,failure,deny"`
		RequestDigest string                `json:"request_digest,omitempty" pattern:"^[a-fA-F0-9]{64}$"`
	}
}

type businessAuditResource struct {
	Type          string `json:"type" minLength:"1" maxLength:"64" pattern:"^[a-z][a-z0-9_.:-]{0,63}$"`
	ID            string `json:"id" minLength:"1" maxLength:"256" pattern:"^[A-Za-z0-9][A-Za-z0-9_.:/@-]{0,255}$"`
	SpaceID       string `json:"space_id,omitempty" maxLength:"128"`
	GroupID       string `json:"group_id,omitempty" maxLength:"128"`
	OwnerMemberID string `json:"owner_member_id,omitempty" maxLength:"128"`
}

type businessAuditOutput struct {
	Body struct {
		Data audit.BusinessReceipt `json:"data"`
	}
}

func (a *API) writeBusinessAudit(ctx context.Context, in *businessAuditInput) (*businessAuditOutput, error) {
	if a.Applications == nil || a.Applications.Store == nil || a.Authorization == nil {
		return nil, apierr.New("UNAVAILABLE", "business audit is unavailable")
	}
	parts := strings.Fields(in.Authorization)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
		return nil, apierr.New("CREDENTIAL_PLANE_MISMATCH", "an application API key is required")
	}
	if len(in.Body.Subject.unknown) != 0 {
		return nil, apierr.New("INLINE_GRANTS_NOT_ALLOWED", "subject attributes must come from Auth state")
	}
	if in.Body.Subject.Token != "" && (in.Body.Subject.MemberID != "" || in.Body.Subject.UserID != "") {
		return nil, apierr.New("VALIDATION_FAILED", "provide either a subject token or a member ID assertion")
	}
	out := &businessAuditOutput{}
	err := a.Applications.Store.InTx(ctx, func(q *db.Queries) error {
		key, err := a.Applications.AuthenticateKeyTx(ctx, q, parts[1])
		if err != nil {
			return err
		}
		if !contains(key.Scopes, "auth.audit:write") {
			return apierr.New("PERMISSION_DENIED", "API key is not scoped for this operation")
		}
		spaceID := strings.TrimSpace(in.Body.Resource.SpaceID)
		checkSpace := func(targetSpace, resourceGroup, resourceOwner string) error {
			memberID, code, err := a.Applications.ResolveKeyInstallationTx(ctx, q, key, targetSpace)
			if err != nil {
				return err
			}
			if code != "" {
				return apierr.New(code, "the application does not cover the business event")
			}
			decision, err := a.Authorization.CheckTx(ctx, q, authorization.CheckRequest{
				MemberID: memberID, Permission: "auth.audit:write", ResourceSpace: targetSpace,
				ResourceGroup: resourceGroup, ResourceOwner: resourceOwner,
			})
			if err != nil {
				return err
			}
			if decision.Effect != engine.Allow {
				return apierr.New(decision.Code, "the authorization engine denied business audit access")
			}
			return nil
		}
		if spaceID != "" {
			if err := checkSpace(spaceID, in.Body.Resource.GroupID, in.Body.Resource.OwnerMemberID); err != nil {
				return err
			}
		}
		subject, err := a.resolveSubject(ctx, key, in.Body.Subject, spaceID)
		if err != nil {
			return err
		}
		if spaceID == "" {
			spaceID = subject.SpaceID
			if err := checkSpace(spaceID, in.Body.Resource.GroupID, in.Body.Resource.OwnerMemberID); err != nil {
				return err
			}
		}
		if subject.SpaceID != spaceID {
			if err := checkSpace(subject.SpaceID, "", ""); err != nil {
				return err
			}
		}
		out.Body.Data, err = audit.AppendBusinessEvent(ctx, q, audit.BusinessEvent{
			ApplicationID: key.ApplicationID, KeyID: key.ID, MemberID: subject.ID, UserID: subject.UserID,
			Asserted: in.Body.Subject.Token == "", Action: in.Body.Action, Outcome: in.Body.Outcome,
			Resource:      audit.Resource{Type: in.Body.Resource.Type, ID: in.Body.Resource.ID, SpaceID: spaceID, GroupID: in.Body.Resource.GroupID},
			RequestDigest: in.Body.RequestDigest,
		})
		return err
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}
