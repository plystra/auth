package security

import "time"

// OIDCAuthenticationFreshEnough compares the authentication evidence with the
// relying party's original request. Upstream ID Tokens carry whole seconds.
func OIDCAuthenticationFreshEnough(authenticatedAt, requestedAt time.Time, maxAge int32, upstream bool, now time.Time) bool {
	if authenticatedAt.Unix() <= 0 || authenticatedAt.After(now) {
		return false
	}
	cutoff := requestedAt.Add(-time.Duration(maxAge) * time.Second)
	if upstream {
		cutoff = cutoff.Truncate(time.Second)
	}
	return !authenticatedAt.Before(cutoff)
}
