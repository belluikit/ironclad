// SPDX-License-Identifier: MIT
// Copyright (c) 2026 TrendVidia, LLC.

package main

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/belluikit/ironclad/admin/packaging"
	"github.com/belluikit/ironclad/admin/vault"
	sdkcontainer "github.com/belluikit/ironclad/sdk/container"
	"github.com/google/uuid"
	"github.com/spf13/cobra"
)

func newPackCmd() *cobra.Command {
	var (
		output          string
		contentType     string
		contentID       string
		transitKey      string
		signingKey      string
		envelopeKey     string
		licenseSubject  string
		licenseTTL      time.Duration
		gracePeriod     time.Duration
		renewalEndpoint string
		entitlements    []string
	)

	cmd := &cobra.Command{
		Use:   "pack <input-file>",
		Short: "Package a file into an encrypted, signed container",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			input, err := os.Open(args[0])
			if err != nil {
				return fmt.Errorf("open input: %w", err)
			}
			defer input.Close()

			ct, err := sdkcontainer.ParseContentType(contentType)
			if err != nil {
				return err
			}

			var cid uuid.UUID
			if contentID != "" {
				cid, err = uuid.Parse(contentID)
				if err != nil {
					return fmt.Errorf("invalid content-id: %w", err)
				}
			}

			vc, err := vault.NewClient(vault.Config{Address: vaultAddr, Token: vaultToken})
			if err != nil {
				return fmt.Errorf("connect to vault: %w", err)
			}
			transit := vc.Transit()

			if envelopeKey == "" {
				envelopeKey = signingKey
			}

			outputFile, err := os.Create(output)
			if err != nil {
				return fmt.Errorf("create output: %w", err)
			}
			defer outputFile.Close()

			ctx := context.Background()
			p := packaging.NewPackager(transit)
			c, err := p.Pack(ctx, input, outputFile, packaging.PackConfig{
				ContentID:       cid,
				ContentType:     ct,
				DEKKeyName:      transitKey,
				SigningKeyName:  signingKey,
				EnvelopeKeyName: envelopeKey,
				Subject:         licenseSubject,
				ExpiresAt:       time.Now().UTC().Add(licenseTTL),
				GracePeriod:     gracePeriod,
				Entitlements:    entitlements,
				RenewalEndpoint: renewalEndpoint,
			})
			if err != nil {
				os.Remove(output)
				return err
			}

			w := cmd.OutOrStdout()
			fmt.Fprintf(w, "Container created: %s\n", output)
			fmt.Fprintf(w, "Content ID: %s\n", c.Envelope.ContentUUID())
			fmt.Fprintf(w, "Content Type: %s\n", sdkcontainer.ContentTypeName(c.Envelope.ContentType))

			licenseToken, _ := c.License.Token()
			if licenseToken != nil {
				fmt.Fprintf(w, "License ID: %s\n", licenseToken.LicenseUUID())
				fmt.Fprintf(w, "Expires: %s\n", licenseToken.ExpiresAt().Format(time.RFC3339))
				fmt.Fprintf(w, "Grace Period: %s\n", time.Duration(licenseToken.GracePeriodSeconds)*time.Second)
			}

			return nil
		},
	}

	cmd.Flags().StringVarP(&output, "output", "o", "", "Output file path (required)")
	cmd.Flags().StringVar(&contentType, "content-type", "data-file", "Content type (data-file, app-definition, shared-library, executable)")
	cmd.Flags().StringVar(&contentID, "content-id", "", "Content ID (auto-generated if omitted)")
	cmd.Flags().StringVar(&transitKey, "transit-key", "ironclad-dek", "Vault Transit key for DEK wrapping")
	cmd.Flags().StringVar(&signingKey, "signing-key", "ironclad-sign", "Vault Transit key for signing")
	cmd.Flags().StringVar(&envelopeKey, "envelope-key", "", "Vault Transit key for envelope signing (defaults to signing-key)")
	cmd.Flags().StringVar(&licenseSubject, "license-subject", "", "License subject (required)")
	cmd.Flags().DurationVar(&licenseTTL, "license-ttl", 720*time.Hour, "License validity duration")
	cmd.Flags().DurationVar(&gracePeriod, "grace-period", 72*time.Hour, "Grace period after expiry")
	cmd.Flags().StringVar(&renewalEndpoint, "renewal-endpoint", "", "URL for online license renewal (required)")
	cmd.Flags().StringSliceVar(&entitlements, "entitlements", nil, "Entitlement keys")

	cmd.MarkFlagRequired("output")
	cmd.MarkFlagRequired("license-subject")
	cmd.MarkFlagRequired("renewal-endpoint")

	return cmd
}
