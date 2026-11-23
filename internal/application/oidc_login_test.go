package application

import (
	"net/url"
	"testing"
)

func TestOIDCLoginResponseQueryOwnsProtocolFields(t *testing.T) {
	response := url.Values{"error": {"access_denied"}, "state": {"actual state"}}
	const original = "tag=first%20choice&st%61te=registered&tag=second+choice&code=registered&error=registered&invalid=%"
	const want = "tag=first%20choice&tag=second+choice&error=access_denied&state=actual+state"
	if actual := oidcLoginResponseQuery(original, response); actual != want {
		t.Fatal("callback lost a registered field or returned conflicting authorization response fields")
	}
}
