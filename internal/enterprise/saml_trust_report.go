package enterprise

import (
	"context"
	"crypto/x509"
	"slices"
	"time"

	"github.com/plystra/auth/internal/db"
)

type SAMLTrustReport struct {
	CheckedAt          time.Time        `json:"checked_at"`
	WarningUntil       time.Time        `json:"warning_until"`
	CheckedConnections int              `json:"checked_connections"`
	Issues             []SAMLTrustIssue `json:"issues"`
}

type SAMLTrustIssue struct {
	SpaceID       string     `json:"space_id"`
	ConnectionID  string     `json:"connection_id"`
	Status        string     `json:"status"`
	CoverageUntil *time.Time `json:"coverage_until,omitempty"`
}

func (s *Service) CheckSAMLSigningTrust(ctx context.Context, checkedAt time.Time, within time.Duration) (SAMLTrustReport, error) {
	report := SAMLTrustReport{
		CheckedAt: checkedAt.UTC(), WarningUntil: checkedAt.Add(within).UTC(), Issues: []SAMLTrustIssue{},
	}
	q := s.Store.Queries()
	var afterID string
	for {
		rows, err := q.ListSAMLSigningTrust(ctx, db.ListSAMLSigningTrustParams{AfterID: afterID})
		if err != nil {
			return SAMLTrustReport{}, err
		}
		if len(rows) == 0 {
			return report, nil
		}
		for _, row := range rows {
			afterID = row.ID
			report.CheckedConnections++
			issue := SAMLTrustIssue{SpaceID: row.SpaceID, ConnectionID: row.ID}
			certs, err := parseSAMLSigningCertificates(row.SamlIdpCertificate.String)
			switch {
			case err != nil || len(certs) == 0:
				issue.Status = "invalid_trust"
			default:
				until := contiguousSAMLSigningCoverage(certs, checkedAt)
				switch {
				case until.IsZero():
					issue.Status = "no_current_signer"
				case until.After(report.WarningUntil):
					continue
				default:
					issue.Status = "coverage_ending"
					issue.CoverageUntil = &until
				}
			}
			report.Issues = append(report.Issues, issue)
		}
	}
}

func contiguousSAMLSigningCoverage(certs []*x509.Certificate, now time.Time) time.Time {
	slices.SortFunc(certs, func(a, b *x509.Certificate) int {
		return a.NotBefore.Compare(b.NotBefore)
	})
	end := now
	var covered bool
	for _, cert := range certs {
		if cert.NotBefore.After(end) {
			break
		}
		if cert.NotAfter.Before(now) || cert.NotAfter.Before(cert.NotBefore) {
			continue
		}
		covered = true
		if cert.NotAfter.After(end) {
			end = cert.NotAfter
		}
	}
	if !covered {
		return time.Time{}
	}
	return end.UTC()
}
