package main

import (
	"fmt"
	"time"

	sdk "github.com/belluikit/ironclad/sdk"
	sdkcontainer "github.com/belluikit/ironclad/sdk/container"
	"github.com/belluikit/ironclad/sdk/license"
	"github.com/spf13/cobra"
)

func newInspectCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "inspect <file.tcn>",
		Short: "Display container metadata without decrypting",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			c, err := sdk.Open(args[0])
			if err != nil {
				return err
			}

			w := cmd.OutOrStdout()
			env := &c.Envelope

			fmt.Fprintf(w, "Container:      %s\n", args[0])
			fmt.Fprintf(w, "Format Version: %d\n", env.FormatVersion)
			fmt.Fprintf(w, "Content ID:     %s\n", env.ContentUUID())
			fmt.Fprintf(w, "Content Type:   %s\n", sdkcontainer.ContentTypeName(env.ContentType))
			fmt.Fprintf(w, "Content Hash:   sha256:%x\n", env.ContentHash)
			fmt.Fprintf(w, "Encryption:     AES-256-GCM\n")
			fmt.Fprintf(w, "Payload Size:   %d bytes\n", len(env.Payload))
			fmt.Fprintf(w, "Developer Cert: %d bytes (DER)\n", len(env.DeveloperCertificate))
			fmt.Fprintf(w, "Distrib. Cert:  %d bytes (DER)\n", len(env.DistributorCertificate))

			licenseToken, err := c.License.Token()
			if err != nil {
				fmt.Fprintf(w, "License:        (parse error: %v)\n", err)
				return nil
			}

			fmt.Fprintf(w, "\nLicense:\n")
			fmt.Fprintf(w, "  License ID:   %s\n", licenseToken.LicenseUUID())
			fmt.Fprintf(w, "  Subject:      %s\n", licenseToken.Subject)
			fmt.Fprintf(w, "  Issued:       %s\n", licenseToken.IssuedAt().Format(time.RFC3339))
			fmt.Fprintf(w, "  Expires:      %s\n", licenseToken.ExpiresAt().Format(time.RFC3339))
			fmt.Fprintf(w, "  Grace Period: %s\n", time.Duration(licenseToken.GracePeriodSeconds)*time.Second)
			if len(licenseToken.Entitlements) > 0 {
				fmt.Fprintf(w, "  Entitlements: %v\n", licenseToken.Entitlements)
			}
			fmt.Fprintf(w, "  Renewal URL:  %s\n", licenseToken.RenewalEndpoint)

			if len(c.Renewals) > 0 {
				fmt.Fprintf(w, "\nRenewals:       %d\n", len(c.Renewals))
				for i, sr := range c.Renewals {
					rt, err := sr.Token()
					if err != nil {
						fmt.Fprintf(w, "  [%d] (parse error: %v)\n", i, err)
						continue
					}
					fmt.Fprintf(w, "  [%d] %s -> extends to %s\n", i,
						rt.IssuedAt().Format("2006-01-02"),
						rt.NewExpiresAt().Format("2006-01-02"))
				}
			}

			terms, err := license.EvaluateTerms(licenseToken, c.Renewals)
			if err != nil {
				fmt.Fprintf(w, "\nStatus:         (error: %v)\n", err)
				return nil
			}

			now := time.Now().UTC()
			status := license.EvaluateStatus(terms, now)
			remaining := time.Until(terms.ExpiresAt).Round(time.Hour)

			fmt.Fprintf(w, "\nStatus:         %s", status)
			if status == license.StatusValid {
				fmt.Fprintf(w, " (expires in %s)", remaining)
			} else if status == license.StatusInGrace {
				graceRemaining := time.Until(terms.GraceDeadline()).Round(time.Hour)
				fmt.Fprintf(w, " (grace ends in %s)", graceRemaining)
			}
			fmt.Fprintln(w)

			return nil
		},
	}
}
