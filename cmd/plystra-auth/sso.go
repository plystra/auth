package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/plystra/auth/internal/enterprise"
	"github.com/plystra/auth/internal/store"
	"github.com/spf13/cobra"
)

var errSAMLTrustAttention = errors.New("SAML signing trust requires attention")

func ssoCommand() *cobra.Command {
	var within time.Duration
	var format string
	root := &cobra.Command{Use: "sso", Short: "check deployment SSO configuration"}
	check := &cobra.Command{
		Use:           "check-saml-certificates",
		Short:         "report active SAML connections with signing trust requiring attention",
		Args:          cobra.NoArgs,
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if within <= 0 || within > 8760*time.Hour {
				return errors.New("--within must be greater than zero and at most 8760h")
			}
			if format != "json" && format != "prometheus" {
				return errors.New("--format must be json or prometheus")
			}
			databaseURL := strings.TrimSpace(os.Getenv("PLYSTRA_AUTH_DATABASE_URL"))
			if databaseURL == "" {
				return errors.New("PLYSTRA_AUTH_DATABASE_URL is required")
			}
			ctx, cancel := context.WithTimeout(cmd.Context(), 30*time.Second)
			defer cancel()
			st, err := store.Open(ctx, databaseURL)
			if err != nil {
				return errors.New("could not connect to the SAML certificate check database")
			}
			defer st.Close()
			report, err := (&enterprise.Service{Store: st}).CheckSAMLSigningTrust(ctx, time.Now(), within)
			if err != nil {
				return errors.New("could not read SAML signing trust from the database")
			}
			switch format {
			case "prometheus":
				err = writeSAMLTrustMetrics(cmd.OutOrStdout(), report)
			default:
				err = json.NewEncoder(cmd.OutOrStdout()).Encode(report)
			}
			if err != nil {
				return err
			}
			if len(report.Issues) != 0 {
				return errSAMLTrustAttention
			}
			return nil
		},
	}
	check.Flags().DurationVar(&within, "within", 720*time.Hour, "report signing coverage ending within this duration")
	check.Flags().StringVar(&format, "format", "json", "report format (json or prometheus)")
	root.AddCommand(check)
	return root
}

func writeSAMLTrustMetrics(w io.Writer, report enterprise.SAMLTrustReport) error {
	counts := make(map[string]int)
	for _, issue := range report.Issues {
		counts[issue.Status]++
	}
	_, err := fmt.Fprintf(w, `# HELP plystra_auth_saml_signing_trust_issues Active SAML connections with the specified signing trust issue.
# TYPE plystra_auth_saml_signing_trust_issues gauge
plystra_auth_saml_signing_trust_issues{status="coverage_ending"} %d
plystra_auth_saml_signing_trust_issues{status="no_current_signer"} %d
plystra_auth_saml_signing_trust_issues{status="invalid_trust"} %d
# HELP plystra_auth_saml_signing_trust_checked_at_timestamp_seconds Unix timestamp of the completed SAML signing trust check.
# TYPE plystra_auth_saml_signing_trust_checked_at_timestamp_seconds gauge
plystra_auth_saml_signing_trust_checked_at_timestamp_seconds %d
`, counts["coverage_ending"], counts["no_current_signer"], counts["invalid_trust"], report.CheckedAt.Unix())
	return err
}
