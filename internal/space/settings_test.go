package space

import (
	"errors"
	"testing"
	"time"

	"github.com/plystra/auth/internal/apierr"
)

func TestSettingsValidateAllowsOperationalAccessTTLRangeAndRejectsOutsideIt(t *testing.T) {
	base := InstanceSettings{
		RegistrationMode: "closed", PasswordMinLength: 8,
		AccessTokenTTL: time.Minute, RefreshTokenTTL: 720 * time.Hour, RefreshIdleTTL: 336 * time.Hour,
	}
	for _, ttl := range []time.Duration{60 * time.Second, 300 * time.Second} {
		candidate := base
		candidate.AccessTokenTTL = ttl
		if err := validate(candidate); err != nil {
			t.Fatalf("access TTL %s rejected: %v", ttl, err)
		}
	}
	for _, ttl := range []time.Duration{59 * time.Second, 301 * time.Second, 60*time.Second + 500*time.Millisecond} {
		candidate := base
		candidate.AccessTokenTTL = ttl
		if err := validate(candidate); err == nil {
			t.Fatalf("access TTL %s accepted", ttl)
		} else {
			var public *apierr.Error
			if !errors.As(err, &public) || public.Code != "VALIDATION_FAILED" {
				t.Fatalf("access TTL %s error = %v, want VALIDATION_FAILED", ttl, err)
			}
		}
	}
}
