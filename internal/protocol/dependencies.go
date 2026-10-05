package protocol

// The protocol adapters are intentionally kept behind domain interfaces. These
// imports pin the documented implementation stack while the endpoint packages
// evolve independently.
import (
	_ "github.com/coreos/go-oidc/v3/oidc"
	_ "github.com/go-webauthn/webauthn/webauthn"
	_ "github.com/pquerna/otp/totp"
	_ "github.com/riverqueue/river"
	_ "github.com/russellhaering/gosaml2"
	_ "golang.org/x/oauth2"
)
