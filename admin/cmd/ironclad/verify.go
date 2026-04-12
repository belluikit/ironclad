package main

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"
	sdk "github.com/trendvidia/ironclad/sdk"
	"github.com/trendvidia/ironclad/sdk/license"
	"github.com/trendvidia/ironclad/admin/vault"
)

func newVerifyCmd() *cobra.Command {
	var (
		signingKey  string
		envelopeKey string
	)

	cmd := &cobra.Command{
		Use:   "verify <file.tcn>",
		Short: "Verify container signatures and license status",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			c, err := sdk.Open(args[0])
			if err != nil {
				return err
			}

			vc, err := vault.NewClient(vault.Config{Address: vaultAddr, Token: vaultToken})
			if err != nil {
				return fmt.Errorf("connect to vault: %w", err)
			}
			transit := vc.Transit()

			if envelopeKey == "" {
				envelopeKey = signingKey
			}

			ctx := context.Background()
			result, err := sdk.Validate(ctx, c, transit, nil, signingKey, envelopeKey)
			if err != nil {
				return fmt.Errorf("validation failed: %w", err)
			}

			w := cmd.OutOrStdout()
			fmt.Fprintf(w, "Container:  %s\n", args[0])
			fmt.Fprintf(w, "Status:     %s\n", result.Status)
			fmt.Fprintf(w, "Expires:    %s\n", result.ExpiresAt.Format(time.RFC3339))
			fmt.Fprintf(w, "Renewals:   %d\n", result.Terms.RenewalCount)

			if result.Valid {
				fmt.Fprintln(w, "Result:     OK")
				return nil
			}

			fmt.Fprintln(w, "Result:     FAILED")
			switch result.Status {
			case license.StatusInGrace:
				os.Exit(1)
			case license.StatusExpired:
				os.Exit(2)
			}
			return nil
		},
	}

	cmd.Flags().StringVar(&signingKey, "signing-key", "ironclad-sign", "Vault Transit key for signature verification")
	cmd.Flags().StringVar(&envelopeKey, "envelope-key", "", "Vault Transit key for envelope verification (defaults to signing-key)")

	return cmd
}
