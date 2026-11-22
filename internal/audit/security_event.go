package audit

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/plystra/auth/internal/db"
	"github.com/plystra/auth/internal/ids"
	"github.com/plystra/auth/internal/requestinfo"
)

// Caller carries authenticated transport identities, never credentials. A
// subject member can differ from its caller (for example, an app requesting
// approval for an Agent or a user revoking an Agent).
type Caller struct {
	UserID         string
	ApplicationID  string
	KeyID          string
	CredentialType string
}

type callerKey struct{}

func WithCaller(ctx context.Context, caller Caller) context.Context {
	return context.WithValue(ctx, callerKey{}, caller)
}

type Resource struct {
	Type    string
	ID      string
	SpaceID string
	GroupID string
}

type SecurityEvent struct {
	ActorType      string
	ActorID        string
	Action         string
	Outcome        string
	MemberID       string
	UserID         string
	ApplicationID  string
	CredentialType string
	Resource       Resource
	Permission     string
	PolicyVersion  int64
	Priority       string
	Metadata       map[string]string
}

// WriteSecurityEvent snapshots the affected member and its owners in the
// mutation's transaction. Resource location is supplied by the operation or
// resolved from the affected member; it never comes from the caller's Space.
func WriteSecurityEvent(ctx context.Context, q *db.Queries, in SecurityEvent) error {
	chain, err := q.GetAuditMemberChain(ctx, db.GetAuditMemberChainParams{MemberID: in.MemberID})
	if err != nil {
		return err
	}
	if len(chain) == 0 {
		return errors.New("audit subject member is unavailable")
	}
	owners := make([]MemberSnapshot, 0, len(chain)-1)
	for _, row := range chain[1:] {
		owners = append(owners, MemberSnapshot{MemberID: row.ID, MemberType: row.MemberType, SpaceID: row.SpaceID})
	}
	if in.Resource.SpaceID == "" {
		location, err := q.GetAuditMemberLocation(ctx, db.GetAuditMemberLocationParams{MemberID: in.MemberID})
		if err != nil {
			return err
		}
		in.Resource.SpaceID = location.SpaceID
		if location.MemberType == "agent" {
			in.Resource.GroupID = location.HomeGroupID.String
		} else {
			groups, err := q.ListMemberGroups(ctx, db.ListMemberGroupsParams{MemberID: in.MemberID, SpaceID: location.SpaceID})
			if err != nil {
				return err
			}
			if len(groups) == 1 {
				in.Resource.GroupID = groups[0].ID
			}
		}
	}
	if in.Resource.Type == "" {
		in.Resource.Type = "member"
	}
	if in.Resource.ID == "" {
		in.Resource.ID = in.MemberID
	}
	return appendSecurityEvent(ctx, q, in, chain[0].MemberType, owners, chain[len(chain)-1].MemberType != "agent")
}

// WriteAccountEvent records an authenticated account operation that has no
// selected member. Require the actual resource location rather than inventing
// a membership or deriving tenant visibility from the account's other bindings.
func WriteAccountEvent(ctx context.Context, q *db.Queries, in SecurityEvent) error {
	if in.ActorType != "user" || in.UserID == "" || in.ActorID != in.UserID || in.MemberID != "" ||
		in.Resource.Type == "" || in.Resource.ID == "" || in.Resource.SpaceID == "" {
		return errors.New("account audit requires a user identity and explicit resource")
	}
	return appendSecurityEvent(ctx, q, in, "", []MemberSnapshot{}, true)
}

// WriteDirectoryEvent records a credential-authenticated directory operation
// without pretending the directory is a member. Its persisted Space controls
// tenant visibility in the same way as other structured security events.
func WriteDirectoryEvent(ctx context.Context, q *db.Queries, in SecurityEvent) error {
	if in.ActorType != "directory" || in.ActorID == "" || in.MemberID != "" ||
		in.Resource.Type == "" || in.Resource.ID == "" || in.Resource.SpaceID == "" {
		return errors.New("directory audit requires a directory identity and explicit resource")
	}
	directory, err := q.GetDirectory(ctx, db.GetDirectoryParams{ID: in.ActorID})
	if err != nil {
		return err
	}
	if directory.SpaceID != in.Resource.SpaceID {
		return errors.New("directory audit resource belongs to another Space")
	}
	return appendSecurityEvent(ctx, q, in, "", []MemberSnapshot{}, true)
}

func appendSecurityEvent(ctx context.Context, q *db.Queries, in SecurityEvent, memberType string, owners []MemberSnapshot, chainComplete bool) error {
	caller, _ := ctx.Value(callerKey{}).(Caller)
	if in.UserID == "" {
		in.UserID = caller.UserID
	}
	if in.ApplicationID == "" {
		in.ApplicationID = caller.ApplicationID
	}
	if in.CredentialType == "" {
		in.CredentialType = caller.CredentialType
	}
	if in.CredentialType == "" {
		in.CredentialType = in.ActorType
	}
	info := requestinfo.Get(ctx)
	if info.Plane == "" && in.ActorType == "system" {
		info.Plane = "system"
	}
	metadata := make(map[string]any, len(in.Metadata)+4)
	for key, value := range in.Metadata {
		metadata[key] = value
	}
	metadata["plane"], metadata["credential_type"] = info.Plane, in.CredentialType
	metadata["owner_chain_complete"] = chainComplete
	if caller.KeyID != "" {
		metadata["api_key_id"] = caller.KeyID
	}
	if in.Priority != "" {
		metadata["priority"] = in.Priority
	}
	metadataJSON, err := json.Marshal(metadata)
	if err != nil {
		return err
	}
	ownersJSON, err := json.Marshal(owners)
	if err != nil {
		return err
	}
	return q.AppendSecurityEventAudit(ctx, db.AppendSecurityEventAuditParams{
		ID: string(ids.New[ids.AuditID]("aud")), ActorType: in.ActorType, ActorID: auditText(in.ActorID),
		Action: in.Action, ResourceType: auditText(in.Resource.Type), ResourceID: auditText(in.Resource.ID), Outcome: in.Outcome,
		RequestID: auditText(info.ID), Metadata: metadataJSON, Plane: info.Plane, CredentialType: in.CredentialType,
		SpaceID: auditText(in.Resource.SpaceID), ResourceGroupID: auditText(in.Resource.GroupID),
		MemberID: auditText(in.MemberID), MemberType: auditText(memberType), UserID: auditText(in.UserID),
		ApplicationID: auditText(in.ApplicationID), OwnerChain: ownersJSON, PermissionKey: auditText(in.Permission),
		PolicyVersion: pgtype.Int8{Int64: in.PolicyVersion, Valid: in.PolicyVersion != 0},
	})
}
