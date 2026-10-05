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
	info := requestinfo.Get(ctx)
	metadata, err := json.Marshal(map[string]string{"plane": info.Plane, "credential_type": actorType})
	if err != nil {
		return err
	}
	return q.AppendAudit(ctx, db.AppendAuditParams{
		ID: string(ids.New[ids.AuditID]("aud")), ActorType: actorType,
		ActorID: pgtype.Text{String: actorID, Valid: actorID != ""},
		Action:  action, ResourceID: pgtype.Text{String: target, Valid: target != ""},
		Outcome: outcome, RequestID: pgtype.Text{String: info.ID, Valid: info.ID != ""}, Metadata: metadata,
	})
}
