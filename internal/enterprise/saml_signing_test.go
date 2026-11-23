package enterprise

import (
	"encoding/base64"
	"errors"
	"strings"
	"testing"

	"github.com/plystra/auth/internal/apierr"
)

func FuzzSAMLResponseHints(f *testing.F) {
	const response = `<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:ds="http://www.w3.org/2000/09/xmldsig#" InResponseTo="_login">%s</samlp:Response>`
	for _, xml := range []string{
		strings.Replace(response, "%s", "", 1),
		strings.Replace(response, "%s", `<ds:Signature/>`, 1),
		strings.Replace(response, "%s", `<ds:Signature><ds:KeyInfo/></ds:Signature>`, 1),
		strings.Replace(response, "%s", `<Assertion xmlns="urn:oasis:names:tc:SAML:2.0:assertion"><ds:Signature/></Assertion>`, 1),
		`<Response`,
	} {
		f.Add([]byte(xml), true)
	}
	f.Add([]byte(""), false)
	f.Add([]byte("not Base64"), false)
	f.Fuzz(func(t *testing.T, data []byte, encode bool) {
		input := string(data)
		if encode {
			input = base64.StdEncoding.EncodeToString(data)
		}
		id, needsImplicitKey, err := parseSAMLResponseHints(input)
		if err != nil {
			var public *apierr.Error
			if !errors.As(err, &public) || (public.Code != "invalid_request" && public.Code != "invalid_grant") || id != "" || needsImplicitKey {
				t.Fatal("invalid input must return a public error with no hints")
			}
			return
		}
		if len(input) > maxSAMLResponseSize || strings.TrimSpace(input) == "" {
			t.Fatal("accepted input bypassed the callback bounds")
		}
		decoded, err := base64.StdEncoding.DecodeString(input)
		if err != nil {
			t.Fatal("accepted input did not decode as Base64")
		}
		canonical := base64.StdEncoding.EncodeToString(decoded)
		otherID, otherNeedsImplicitKey, err := parseSAMLResponseHints(canonical)
		if err != nil || otherID != id || otherNeedsImplicitKey != needsImplicitKey {
			t.Fatal("normalizing the input encoding changed the callback hints")
		}
	})
}
