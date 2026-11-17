package audit

import (
	"context"
	"testing"
)

func TestAccountEventRejectsInventedMemberOrMissingIdentityAndResource(t *testing.T) {
	valid := SecurityEvent{ActorType: "user", ActorID: "usr_account", UserID: "usr_account",
		Resource: Resource{Type: "application", ID: "app_client", SpaceID: "spc_publisher"}}
	for _, scenario := range []struct {
		name   string
		change func(*SecurityEvent)
	}{
		{"missing_user", func(in *SecurityEvent) { in.UserID = "" }},
		{"different_actor", func(in *SecurityEvent) { in.ActorID = "usr_other" }},
		{"non_user_actor", func(in *SecurityEvent) { in.ActorType = "member" }},
		{"invented_member", func(in *SecurityEvent) { in.MemberID = "mem_unselected" }},
		{"missing_resource_type", func(in *SecurityEvent) { in.Resource.Type = "" }},
		{"missing_resource_id", func(in *SecurityEvent) { in.Resource.ID = "" }},
		{"missing_resource_space", func(in *SecurityEvent) { in.Resource.SpaceID = "" }},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			in := valid
			scenario.change(&in)
			if err := WriteAccountEvent(context.Background(), nil, in); err == nil {
				t.Fatal("incomplete account identity or fabricated membership reached persistence")
			}
		})
	}
}
