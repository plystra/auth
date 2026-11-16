package audit

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"regexp"
	"strings"
	"time"

	"github.com/plystra/auth/internal/apierr"
	"github.com/plystra/auth/internal/db"
	"github.com/plystra/auth/internal/ids"
	"github.com/plystra/auth/internal/requestinfo"
)

type BusinessEvent struct {
	ApplicationID string
	KeyID         string
	MemberID      string
	UserID        string
	Asserted      bool
	Action        string
	Outcome       string
	Resource      Resource
	RequestDigest string
}

type BusinessReceipt struct {
	ID         string    `json:"id"`
	OccurredAt time.Time `json:"occurred_at"`
}

var businessAction = regexp.MustCompile(`^[a-z][a-z0-9_.:-]{0,127}$`)
var businessResourceType = regexp.MustCompile(`^[a-z][a-z0-9_.:-]{0,63}$`)
var businessResourceID = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.:/@-]{0,255}$`)

// AppendBusinessEvent records application-reported facts. Its caller must
// authorize auth.audit:write in the same transaction; this function never
// promotes a reported outcome into an Auth authorization decision.
func AppendBusinessEvent(ctx context.Context, q *db.Queries, in BusinessEvent) (BusinessReceipt, error) {
	if !businessAction.MatchString(in.Action) || !businessResourceType.MatchString(in.Resource.Type) || !businessResourceID.MatchString(in.Resource.ID) ||
		(in.Outcome != "success" && in.Outcome != "failure" && in.Outcome != "deny") {
		return BusinessReceipt{}, apierr.New("VALIDATION_FAILED", "business event action, outcome and resource identifiers must be valid")
	}
	for _, value := range []string{in.Action, in.Resource.Type, in.Resource.ID} {
		if strings.Contains(value, "ply_") || (strings.HasPrefix(value, "eyJ") && strings.Count(value, ".") == 2) {
			return BusinessReceipt{}, apierr.New("VALIDATION_FAILED", "business event identifiers must not contain credentials")
		}
	}
	if in.RequestDigest != "" {
		digest, err := hex.DecodeString(in.RequestDigest)
		if err != nil || len(digest) != 32 {
			return BusinessReceipt{}, apierr.New("VALIDATION_FAILED", "request_digest must be a SHA-256 hex digest")
		}
	}
	chain, err := q.GetAuditMemberChain(ctx, db.GetAuditMemberChainParams{MemberID: in.MemberID})
	if err != nil {
		return BusinessReceipt{}, err
	}
	if len(chain) == 0 || chain[len(chain)-1].MemberType == "agent" {
		return BusinessReceipt{}, apierr.New("SUBJECT_NOT_FOUND", "the business event subject chain is unavailable")
	}
	owners := make([]MemberSnapshot, 0, len(chain)-1)
	for _, member := range chain[1:] {
		owners = append(owners, MemberSnapshot{MemberID: member.ID, MemberType: member.MemberType, SpaceID: member.SpaceID})
	}
	source := "token"
	if in.Asserted {
		source = "application_assertion"
	}
	metadata := map[string]any{
		"event_source": "application_reported", "subject_source": source, "api_key_id": in.KeyID,
		"plane": "server", "credential_type": "application_api_key",
		"owner_chain_complete": true,
	}
	if in.RequestDigest != "" {
		metadata["request_digest"] = strings.ToLower(in.RequestDigest)
	}
	metadataJSON, err := json.Marshal(metadata)
	if err != nil {
		return BusinessReceipt{}, err
	}
	ownersJSON, err := json.Marshal(owners)
	if err != nil {
		return BusinessReceipt{}, err
	}
	row, err := q.AppendBusinessEventAudit(ctx, db.AppendBusinessEventAuditParams{
		ID: string(ids.New[ids.AuditID]("aud")), ApplicationID: auditText(in.ApplicationID), KeyID: auditText(in.KeyID),
		MemberID: auditText(in.MemberID), MemberType: auditText(chain[0].MemberType), UserID: auditText(in.UserID),
		Action: in.Action, Outcome: in.Outcome, ResourceType: auditText(in.Resource.Type), ResourceID: auditText(in.Resource.ID),
		SpaceID: auditText(in.Resource.SpaceID), ResourceGroupID: auditText(in.Resource.GroupID),
		RequestID: auditText(requestinfo.Get(ctx).ID), Metadata: metadataJSON, OwnerChain: ownersJSON,
	})
	if err != nil {
		return BusinessReceipt{}, err
	}
	return BusinessReceipt{ID: row.ID, OccurredAt: row.OccurredAt.Time}, nil
}
