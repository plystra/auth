package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/plystra/auth/examples/invoice-saas"
	"github.com/plystra/auth/internal/secret"
	"github.com/spf13/cobra"
)

func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	if err := command().ExecuteContext(ctx); err != nil {
		os.Exit(1)
	}
}

func command() *cobra.Command {
	root := &cobra.Command{Use: "invoice-saas", Short: "Invoice SaaS using Plystra Auth over HTTP", SilenceUsage: true}
	root.AddCommand(&cobra.Command{Use: "migrate", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, _ []string) error {
		databaseURL, err := required("INVOICE_SAAS_DATABASE_URL")
		if err != nil {
			return err
		}
		return invoicesaas.Migrate(cmd.Context(), databaseURL)
	}})
	var id, spaceID, groupID, currency string
	var amount int64
	seed := &cobra.Command{Use: "seed", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, _ []string) error {
		if id == "" || spaceID == "" || groupID == "" || amount <= 0 || currency == "" {
			return errors.New("seed requires --id, --space-id, --group-id, --amount-cents and --currency")
		}
		databaseURL, err := required("INVOICE_SAAS_DATABASE_URL")
		if err != nil {
			return err
		}
		store, err := invoicesaas.OpenStore(cmd.Context(), databaseURL)
		if err != nil {
			return err
		}
		defer store.Close()
		if err := store.Seed(cmd.Context(), id, spaceID, groupID, amount, currency); err != nil {
			return err
		}
		_, err = fmt.Fprintln(cmd.OutOrStdout(), "invoice created:", id)
		return err
	}}
	seed.Flags().StringVar(&id, "id", "", "invoice ID with inv_ prefix")
	seed.Flags().StringVar(&spaceID, "space-id", "", "authoritative resource Space ID")
	seed.Flags().StringVar(&groupID, "group-id", "", "authoritative resource group ID")
	seed.Flags().Int64Var(&amount, "amount-cents", 0, "positive amount in minor units")
	seed.Flags().StringVar(&currency, "currency", "", "three-letter uppercase currency")
	var after string
	var limit int
	auditStatus := &cobra.Command{Use: "audit-status", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, _ []string) error {
		databaseURL, err := required("INVOICE_SAAS_DATABASE_URL")
		if err != nil {
			return err
		}
		store, err := invoicesaas.OpenStore(cmd.Context(), databaseURL)
		if err != nil {
			return err
		}
		defer store.Close()
		rows, err := store.AuditStatus(cmd.Context(), after, limit)
		if err != nil {
			return err
		}
		return json.NewEncoder(cmd.OutOrStdout()).Encode(struct {
			Data []invoicesaas.AuditDeliveryStatus `json:"data"`
		}{rows})
	}}
	auditStatus.Flags().StringVar(&after, "after", "", "continue after this event ID")
	auditStatus.Flags().IntVar(&limit, "limit", 50, "number of delivery statuses, from 1 to 100")
	root.AddCommand(seed, auditStatus, &cobra.Command{Use: "serve", Args: cobra.NoArgs, RunE: serve})
	return root
}

func required(name string) (string, error) {
	value := strings.TrimSpace(os.Getenv(name))
	if value == "" {
		return "", fmt.Errorf("missing configuration: %s", name)
	}
	return value, nil
}

func serve(cmd *cobra.Command, _ []string) error {
	names := []string{"INVOICE_SAAS_DATABASE_URL", "INVOICE_SAAS_AUTH_ISSUER", "INVOICE_SAAS_AUTH_SERVER_URL", "INVOICE_SAAS_CLIENT_ID", "INVOICE_SAAS_API_KEY"}
	values := make([]string, len(names))
	for i, name := range names {
		value, err := required(name)
		if err != nil {
			return err
		}
		values[i] = value
	}
	client, err := invoicesaas.NewAuthClient(invoicesaas.AuthConfig{Issuer: values[1], ServerURL: values[2], ClientID: values[3], APIKey: secret.New(values[4]), JWKSURL: os.Getenv("INVOICE_SAAS_AUTH_JWKS_URL")})
	if err != nil {
		return err
	}
	store, err := invoicesaas.OpenStore(cmd.Context(), values[0])
	if err != nil {
		return err
	}
	defer store.Close()
	if err := store.StartAudit(cmd.Context(), client); err != nil {
		return err
	}
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = store.StopAudit(ctx)
	}()
	address := os.Getenv("INVOICE_SAAS_HTTP_ADDR")
	if address == "" {
		address = "127.0.0.1:8090"
	}
	server := &http.Server{Addr: address, Handler: (&invoicesaas.API{Store: store, Auth: client}).Handler(), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second, WriteTimeout: 15 * time.Second, IdleTimeout: time.Minute}
	finished := make(chan error, 1)
	go func() { finished <- server.ListenAndServe() }()
	select {
	case err := <-finished:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return errors.New("invoice SaaS listener failed")
	case <-cmd.Context().Done():
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		return server.Shutdown(ctx)
	}
}
