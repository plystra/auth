package audit

import (
	"encoding/json"
	"time"

	"github.com/plystra/auth/internal/db"
)

type Event struct {
	ID              string           `json:"id"`
	OccurredAt      time.Time        `json:"occurred_at"`
	Plane           string           `json:"plane"`
	CredentialType  string           `json:"credential_type"`
	ActorType       string           `json:"actor_type"`
	ActorID         string           `json:"actor_id,omitempty"`
	Action          string           `json:"action"`
	ResourceType    string           `json:"resource_type,omitempty"`
	ResourceID      string           `json:"resource_id,omitempty"`
	Outcome         string           `json:"outcome"`
	RequestID       string           `json:"request_id,omitempty"`
	SpaceID         string           `json:"space_id"`
	ResourceGroupID string           `json:"resource_group_id,omitempty"`
	MemberID        string           `json:"member_id,omitempty"`
	MemberType      string           `json:"member_type,omitempty"`
	UserID          string           `json:"user_id,omitempty"`
	ApplicationID   string           `json:"application_id,omitempty"`
	OwnerChain      []MemberSnapshot `json:"owner_chain"`
	DecisionID      string           `json:"decision_id,omitempty"`
	DenyCode        string           `json:"deny_code,omitempty"`
	PermissionKey   string           `json:"permission_key,omitempty"`
	PolicyVersion   int64            `json:"policy_version,omitempty"`
	Metadata        json.RawMessage  `json:"metadata"`
}

func EventFromRow(row db.AuditLog) (Event, error) {
	owners := make([]MemberSnapshot, 0)
	if err := json.Unmarshal(row.OwnerChain, &owners); err != nil {
		return Event{}, err
	}
	return Event{
		ID: row.ID, OccurredAt: row.OccurredAt.Time, Plane: row.Plane, CredentialType: row.CredentialType,
		ActorType: row.ActorType, ActorID: row.ActorID.String, Action: row.Action,
		ResourceType: row.ResourceType.String, ResourceID: row.ResourceID.String, Outcome: row.Outcome,
		RequestID: row.RequestID.String, SpaceID: row.SpaceID.String, ResourceGroupID: row.ResourceGroupID.String,
		MemberID: row.MemberID.String, MemberType: row.MemberType.String, UserID: row.UserID.String,
		ApplicationID: row.ApplicationID.String, OwnerChain: owners, DecisionID: row.DecisionID.String,
		DenyCode: row.DenyCode.String, PermissionKey: row.PermissionKey.String,
		PolicyVersion: row.PolicyVersion.Int64, Metadata: row.Metadata,
	}, nil
}
