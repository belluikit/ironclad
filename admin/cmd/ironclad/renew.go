// SPDX-License-Identifier: MIT
// Copyright (c) 2026 TrendVidia, LLC.

package main

import (
	"context"
	"fmt"
	"time"

	admincontainer "github.com/belluikit/ironclad/admin/container"
	adminlicense "github.com/belluikit/ironclad/admin/license"
	"github.com/belluikit/ironclad/admin/vault"
	sdk "github.com/belluikit/ironclad/sdk"
	"github.com/belluikit/ironclad/sdk/license"
	"github.com/spf13/cobra"
)

func newRenewCmd() *cobra.Command {
	var signingKey string

	cmd := &cobra.Command{
		Use:   "renew <file.tcn>",
		Short: "Renew the license on a container file",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			containerPath := args[0]

			vc, err := vault.NewClient(vault.Config{Address: vaultAddr, Token: vaultToken})
			if err != nil {
				return fmt.Errorf("connect to vault: %w", err)
			}
			transit := vc.Transit()

			c, err := sdk.Open(containerPath)
			if err != nil {
				return err
			}

			ctx := context.Background()
			rc := adminlicense.NewRenewalClient(transit, signingKey)
			renewal, err := rc.Renew(ctx, c)
			if err != nil {
				return fmt.Errorf("renew license: %w", err)
			}

			if err := admincontainer.AppendRenewal(containerPath, *renewal); err != nil {
				return fmt.Errorf("append renewal: %w", err)
			}

			// Read back and show new status
			c, err = sdk.Open(containerPath)
			if err != nil {
				return err
			}

			licenseToken, _ := c.License.Token()
			terms, err := license.EvaluateTerms(licenseToken, c.Renewals)
			if err != nil {
				return err
			}

			w := cmd.OutOrStdout()
			fmt.Fprintf(w, "License renewed successfully.\n")
			fmt.Fprintf(w, "New expiry:     %s\n", terms.ExpiresAt.Format(time.RFC3339))
			fmt.Fprintf(w, "Grace period:   %s\n", time.Duration(terms.GracePeriodSeconds)*time.Second)
			fmt.Fprintf(w, "Total renewals: %d\n", terms.RenewalCount)

			return nil
		},
	}

	cmd.Flags().StringVar(&signingKey, "signing-key", "ironclad-sign", "Vault Transit key for signature verification")

	return cmd
}
