package main

import (
	"context"
	"encoding/json"
	"errors"
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
			if err := json.NewEncoder(cmd.OutOrStdout()).Encode(report); err != nil {
				return err
			}
			if len(report.Issues) != 0 {
				return errSAMLTrustAttention
			}
			return nil
		},
	}
	check.Flags().DurationVar(&within, "within", 720*time.Hour, "report signing coverage ending within this duration")
	root.AddCommand(check)
	return root
}
