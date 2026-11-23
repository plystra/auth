package enterprise

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"encoding/xml"
	"strings"
	"time"

	"github.com/plystra/auth/internal/apierr"
	saml2 "github.com/russellhaering/gosaml2"
	"github.com/russellhaering/gosaml2/types"
	dsig "github.com/russellhaering/goxmldsig"
)

const maxSAMLResponseSize = 8 * 1024 * 1024

type samlSignatureKeyHint struct {
	KeyInfo *struct{} `xml:"http://www.w3.org/2000/09/xmldsig# KeyInfo"`
}

func (h *samlSignatureKeyHint) missing() bool { return h != nil && h.KeyInfo == nil }

func parseSAMLResponseHints(response string) (inResponseTo string, keyHintMissing bool, err error) {
	if len(response) > maxSAMLResponseSize {
		return "", false, apierr.New("invalid_request", "SAMLResponse is too large")
	}
	if strings.TrimSpace(response) == "" {
		return "", false, apierr.New("invalid_request", "SAMLResponse is required")
	}
	decoded, err := base64.StdEncoding.DecodeString(response)
	if err != nil {
		return "", false, apierr.New("invalid_grant", "the SAML response is invalid")
	}
	var hints struct {
		types.UnverifiedBaseResponse
		Signature  *samlSignatureKeyHint `xml:"http://www.w3.org/2000/09/xmldsig# Signature"`
		Assertions []struct {
			Signature *samlSignatureKeyHint `xml:"http://www.w3.org/2000/09/xmldsig# Signature"`
		} `xml:"urn:oasis:names:tc:SAML:2.0:assertion Assertion"`
	}
	if err := xml.Unmarshal(decoded, &hints); err != nil {
		return "", false, apierr.New("invalid_grant", "the SAML response is invalid")
	}
	keyHintMissing = hints.Signature.missing()
	for _, assertion := range hints.Assertions {
		keyHintMissing = keyHintMissing || assertion.Signature.missing()
	}
	return hints.InResponseTo, keyHintMissing, nil
}

func certificateValidAt(cert *x509.Certificate, now time.Time) bool {
	return !now.Before(cert.NotBefore) && !now.After(cert.NotAfter)
}

func currentSAMLSigningCertificates(value string, now time.Time) ([]*x509.Certificate, error) {
	var active []*x509.Certificate
	rest := bytes.TrimSpace([]byte(value))
	for len(rest) > 0 {
		block, trailing := pem.Decode(rest)
		if block == nil || block.Type != "CERTIFICATE" {
			return nil, apierr.New("temporarily_unavailable", "SAML connection certificate is unavailable")
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, apierr.New("temporarily_unavailable", "SAML connection certificate is unavailable")
		}
		if certificateValidAt(cert, now) {
			active = append(active, cert)
		}
		rest = bytes.TrimSpace(trailing)
	}
	if len(active) == 0 {
		return nil, apierr.New("temporarily_unavailable", "SAML connection certificate is expired")
	}
	return active, nil
}

// Each start or callback constructs its own provider and trust set.
type samlLoginProvider struct {
	*saml2.SAMLServiceProvider
	certs      []*x509.Certificate
	validFrom  time.Time
	validUntil time.Time
}

func (p *samlLoginProvider) setTrust(certs []*x509.Certificate) {
	p.certs = certs
	p.IDPCertificateStore = &dsig.MemoryX509CertificateStore{Roots: certs}
	p.validFrom = certs[0].NotBefore
	p.validUntil = certs[0].NotAfter
	for _, cert := range certs[1:] {
		if cert.NotBefore.After(p.validFrom) {
			p.validFrom = cert.NotBefore
		}
		if cert.NotAfter.Before(p.validUntil) {
			p.validUntil = cert.NotAfter
		}
	}
}

func (p *samlLoginProvider) verify(ctx context.Context, response string, keyHintMissing bool) (*saml2.AssertionInfo, error) {
	validate := func() (*saml2.AssertionInfo, bool) {
		info, err := p.RetrieveAssertionInfo(response)
		return info, err == nil && info != nil && info.WarningInfo != nil && !info.WarningInfo.InvalidTime && !info.WarningInfo.NotInAudience && info.ResponseSignatureValidated
	}
	if info, ok := validate(); ok {
		return info, nil
	}
	// Preserve implicit verification with the first active metadata key.
	// Additional overlapping keys use XMLDSig KeyInfo to identify their certificate.
	if keyHintMissing && len(p.certs) > 1 {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		fullStore := p.IDPCertificateStore
		p.IDPCertificateStore = &dsig.MemoryX509CertificateStore{Roots: p.certs[:1]}
		if info, ok := validate(); ok {
			p.setTrust(p.certs[:1])
			return info, nil
		}
		p.IDPCertificateStore = fullStore
	}
	return nil, apierr.New("invalid_grant", "the SAML assertion is invalid")
}

type samlLoginProof struct {
	provider       *samlLoginProvider
	response       string
	keyHintMissing bool
}

func (p *samlLoginProvider) trustValidAt(now time.Time) bool {
	return !now.Before(p.validFrom) && !now.After(p.validUntil)
}

func (p *samlLoginProof) recheck(ctx context.Context) error {
	now := time.Now()
	if p.provider.trustValidAt(now) {
		return nil
	}
	// An unrelated rollover certificate may have expired during the login.
	// Reverify the same signed message with the still-valid original pins.
	var remaining []*x509.Certificate
	for _, cert := range p.provider.certs {
		if certificateValidAt(cert, now) {
			remaining = append(remaining, cert)
		}
	}
	if len(remaining) > 0 {
		p.provider.setTrust(remaining)
		if _, err := p.provider.verify(ctx, p.response, p.keyHintMissing); err == nil && p.provider.trustValidAt(time.Now()) {
			return nil
		}
	}
	return apierr.New("temporarily_unavailable", "SAML connection certificate is expired")
}
