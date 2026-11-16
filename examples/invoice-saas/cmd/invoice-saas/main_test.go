package main

import (
	"io"
	"strings"
	"testing"
)

func TestInvoiceSaaSCLIReportsMissingConfiguration(t *testing.T) {
	names := []string{"INVOICE_SAAS_DATABASE_URL", "INVOICE_SAAS_AUTH_ISSUER", "INVOICE_SAAS_AUTH_SERVER_URL", "INVOICE_SAAS_CLIENT_ID", "INVOICE_SAAS_API_KEY"}
	for _, missing := range names {
		t.Run(missing, func(t *testing.T) {
			for _, name := range names {
				t.Setenv(name, "present")
			}
			t.Setenv(missing, "")
			cmd := command()
			cmd.SetArgs([]string{"serve"})
			cmd.SetOut(io.Discard)
			cmd.SetErr(io.Discard)
			err := cmd.Execute()
			if err == nil || !strings.Contains(err.Error(), missing) {
				t.Fatalf("missing configuration error = %v", err)
			}
		})
	}
	for _, args := range [][]string{{"migrate"}, {"seed"}, {"serve", "unexpected"}} {
		t.Setenv("INVOICE_SAAS_DATABASE_URL", "")
		cmd := command()
		cmd.SetArgs(args)
		cmd.SetOut(io.Discard)
		cmd.SetErr(io.Discard)
		if err := cmd.Execute(); err == nil {
			t.Fatalf("CLI accepted incomplete arguments: %v", args)
		}
	}
}
