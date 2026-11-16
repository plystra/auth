package audit

import (
	"context"
	"encoding/json"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/plystra/auth/internal/db"
	"github.com/plystra/auth/internal/ids"
	"github.com/plystra/auth/internal/requestinfo"
)

// AuthorizationDecision contains resolved identities, never bearer credentials.
// MemberID must come from the subject resolver, not from unvalidated input.
type AuthorizationDecision struct {
	KeyID         string
	ApplicationID string
	MemberID      string
	UserID        string
	SpaceID       string
	GroupID       string
	ResourceType  string
	ResourceID    string
	Permission    string
	Action        string
	DecisionID    string
	DenyCode      string
	PolicyVersion int64
	Asserted      bool
}

type MemberSnapshot struct {
	MemberID   string `json:"member_id"`
	MemberType string `json:"member_type"`
	SpaceID    string `json:"space_id"`
}

func WriteAuthorizationDecision(ctx context.Context, q *db.Queries, in AuthorizationDecision) error {
	owners := make([]MemberSnapshot, 0)
	memberType := ""
	complete := false
	if in.MemberID != "" {
		chain, err := q.GetAuditMemberChain(ctx, db.GetAuditMemberChainParams{MemberID: in.MemberID})
		if err != nil {
			return err
		}
		if len(chain) > 0 {
			memberType = chain[0].MemberType
			for _, row := range chain[1:] {
				owners = append(owners, MemberSnapshot{MemberID: row.ID, MemberType: row.MemberType, SpaceID: row.SpaceID})
			}
			complete = chain[len(chain)-1].MemberType != "agent"
		} else {
			// A vanished subject cannot be promoted from the request into a fact.
			in.MemberID, in.UserID = "", ""
		}
	}
	info := requestinfo.Get(ctx)
	metadata := map[string]any{
		"plane": info.Plane, "credential_type": "application",
		"owner_chain_complete": complete,
	}
	if in.Asserted {
		metadata["subject_source"] = "application_assertion"
	}
	metadataJSON, err := json.Marshal(metadata)
	if err != nil {
		return err
	}
	ownersJSON, err := json.Marshal(owners)
	if err != nil {
		return err
	}
	return q.AppendAuthorizationDecisionAudit(ctx, db.AppendAuthorizationDecisionAuditParams{
		ID: string(ids.New[ids.AuditID]("aud")), KeyID: auditText(in.KeyID), ApplicationID: auditText(in.ApplicationID),
		Action: in.Action, ResourceType: auditText(in.ResourceType), ResourceID: auditText(in.ResourceID),
		RequestID: auditText(info.ID), Metadata: metadataJSON, Plane: info.Plane,
		SpaceID: auditText(in.SpaceID), ResourceGroupID: auditText(in.GroupID),
		MemberID: auditText(in.MemberID), MemberType: auditText(memberType), UserID: auditText(in.UserID),
		OwnerChain: ownersJSON, DecisionID: auditText(in.DecisionID), DenyCode: auditText(in.DenyCode),
		PermissionKey: auditText(in.Permission), PolicyVersion: pgtype.Int8{Int64: in.PolicyVersion, Valid: true},
	})
}

func auditText(value string) pgtype.Text {
	return pgtype.Text{String: value, Valid: value != ""}
}
