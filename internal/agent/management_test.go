package agent

import (
	"context"
	"errors"
	"testing"

	"github.com/plystra/auth/internal/apierr"
)

func TestManagedAgentMutationsRequireAuthorizer(t *testing.T) {
	ctx := context.Background()
	svc := &Service{}
	for _, operation := range []string{"create", "rotate", "stop", "delete", "remove_self"} {
		t.Run(operation, func(t *testing.T) {
			var err error
			switch operation {
			case "create":
				_, _, err = svc.CreateManaged(ctx, CreateInput{}, nil)
			case "rotate":
				_, err = svc.RotateManaged(ctx, "", "", "", nil)
			case "stop":
				err = svc.StopManaged(ctx, "", "", nil)
			case "delete":
				err = svc.DeleteManaged(ctx, "", "", nil)
			case "remove_self":
				err = svc.RemoveSelf(ctx, "", nil)
			}
			var failure *apierr.Error
			if !errors.As(err, &failure) || failure.Code != "UNAVAILABLE" {
				t.Fatalf("missing authorization dependency did not fail closed: %v", err)
			}
		})
	}
}
