package enterprise

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/beevik/etree"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/plystra/auth/internal/apierr"
	"github.com/plystra/auth/internal/db"
	dsig "github.com/russellhaering/goxmldsig"
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

func FuzzSAMLAssertionVerification(f *testing.F) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		f.Fatal(err)
	}
	metadata, err := parseSAMLMetadata(testSAMLMetadata(f, key))
	if err != nil {
		f.Fatal(err)
	}
	certs, err := currentSAMLSigningCertificates(metadata.Certificate, time.Now())
	if err != nil {
		f.Fatal(err)
	}
	signer, err := dsig.NewSigningContext(key, [][]byte{certs[0].Raw})
	if err != nil {
		f.Fatal(err)
	}
	service := Service{Issuer: "https://auth.example.test"}
	const callback = "https://auth.example.test/v1/sso/connection/callback"
	row := db.SsoConnection{
		ID: "connection", RedirectUri: callback,
		SamlEntityID:       pgtype.Text{String: metadata.EntityID, Valid: true},
		SamlSsoUrl:         pgtype.Text{String: metadata.SSOURL, Valid: true},
		SamlSsoBinding:     pgtype.Text{String: metadata.Binding, Valid: true},
		SamlIdpCertificate: pgtype.Text{String: metadata.Certificate, Valid: true},
	}
	for _, value := range []string{"Engineering", "R&D < Platform", "工程部", "role\tlabel\nnext"} {
		f.Add(value, true)
	}
	f.Add(`<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"/>`, false)
	f.Add(`<broken`, false)
	f.Fuzz(func(t *testing.T, input string, signed bool) {
		if len(input) > 4096 {
			return
		}
		provider, err := service.samlProvider(row)
		if err != nil {
			t.Fatal(err)
		}
		if !signed {
			info, err := provider.verify(t.Context(), base64.StdEncoding.EncodeToString([]byte(input)), false)
			var public *apierr.Error
			if info != nil || !errors.As(err, &public) || public.Code != "invalid_grant" {
				t.Fatal("untrusted XML must fail without an assertion")
			}
			return
		}
		// Keep generated text in XML 1.0 and compare it after line ending normalization.
		input = strings.Map(func(r rune) rune {
			switch {
			case r == '\r':
				return '\n'
			case r < ' ' && r != '\t' && r != '\n', r == 0xfffe, r == 0xffff:
				return -1
			default:
				return r
			}
		}, input)
		issueTime := time.Now().UTC()
		expires := issueTime.Add(time.Minute).Format(time.RFC3339)
		xml := fmt.Sprintf(`<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_response" Version="2.0" IssueInstant="%s" Destination="%s">
		<saml:Issuer>%s</saml:Issuer>
		<samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>
		<saml:Assertion ID="_assertion" Version="2.0" IssueInstant="%s">
		<saml:Issuer>%s</saml:Issuer>
		<saml:Subject><saml:NameID>department-member</saml:NameID><saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
		<saml:SubjectConfirmationData Recipient="%s" NotOnOrAfter="%s"/></saml:SubjectConfirmation></saml:Subject>
		<saml:Conditions NotBefore="%s" NotOnOrAfter="%s"><saml:AudienceRestriction><saml:Audience>%s</saml:Audience></saml:AudienceRestriction></saml:Conditions>
		<saml:AttributeStatement><saml:Attribute Name="department"><saml:AttributeValue/></saml:Attribute></saml:AttributeStatement>
		</saml:Assertion></samlp:Response>`,
			issueTime.Format(time.RFC3339), callback, metadata.EntityID, issueTime.Format(time.RFC3339), metadata.EntityID,
			callback, expires, issueTime.Add(-time.Minute).Format(time.RFC3339), expires, service.samlEntityID(row.ID))
		document := etree.NewDocument()
		if err := document.ReadFromString(xml); err != nil {
			t.Fatal(err)
		}
		document.Root().FindElement("./Assertion/AttributeStatement/Attribute/AttributeValue").SetText(input)
		root, err := signer.SignEnveloped(document.Root())
		if err != nil {
			t.Fatal(err)
		}
		document.SetRoot(root)
		encoded, err := document.WriteToBytes()
		if err != nil {
			t.Fatal(err)
		}
		info, err := provider.verify(t.Context(), base64.StdEncoding.EncodeToString(encoded), false)
		if err != nil {
			t.Fatal(err)
		}
		if !info.ResponseSignatureValidated || info.NameID != "department-member" || len(info.Assertions) != 1 || info.Values.Get("department") != input {
			t.Fatal("signature verification or assertion projection changed the signed identity")
		}
	})
}
