package audit

import (
	"context"
	"encoding/json"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/plystra/auth/internal/db"
	"github.com/plystra/auth/internal/ids"
	"github.com/plystra/auth/internal/requestinfo"
)

func Write(ctx context.Context, q *db.Queries, actorType, actorID, action, target, outcome string) error {
	return write(ctx, q, actorType, actorID, action, target, outcome, "")
}

func WriteWithPriority(ctx context.Context, q *db.Queries, actorType, actorID, action, target, outcome, priority string) error {
	return write(ctx, q, actorType, actorID, action, target, outcome, priority)
}

func WriteWithMetadata(ctx context.Context, q *db.Queries, actorType, actorID, action, target, outcome string, extra map[string]string) error {
	return writeWithMetadata(ctx, q, actorType, actorID, action, target, outcome, "", extra)
}

func write(ctx context.Context, q *db.Queries, actorType, actorID, action, target, outcome, priority string) error {
	return writeWithMetadata(ctx, q, actorType, actorID, action, target, outcome, priority, nil)
}

func writeWithMetadata(ctx context.Context, q *db.Queries, actorType, actorID, action, target, outcome, priority string, extra map[string]string) error {
	info := requestinfo.Get(ctx)
	metadataFields := map[string]string{"plane": info.Plane, "credential_type": actorType}
	if priority != "" {
		metadataFields["priority"] = priority
	}
	for key, value := range extra {
		if key != "" && value != "" {
			metadataFields[key] = value
		}
	}
	metadata, err := json.Marshal(metadataFields)
	if err != nil {
		return err
	}
	return q.AppendAudit(ctx, db.AppendAuditParams{
		ID: string(ids.New[ids.AuditID]("aud")), ActorType: actorType,
		ActorID: pgtype.Text{String: actorID, Valid: actorID != ""},
		Action:  action, ResourceID: pgtype.Text{String: target, Valid: target != ""},
		Outcome: outcome, RequestID: pgtype.Text{String: info.ID, Valid: info.ID != ""}, Metadata: metadata,
		Plane: info.Plane, CredentialType: actorType,
	})
}
