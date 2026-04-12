package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var (
	vaultAddr  string
	vaultToken string
)

func main() {
	rootCmd := &cobra.Command{
		Use:   "ironclad",
		Short: "Secure file packaging with encryption, signing, and license management",
		Long: `Ironclad packages files into encrypted, signed containers (.tcn) with
optional license control. Cryptographic operations are backed by
HashiCorp Vault's Transit and PKI engines.`,
	}

	rootCmd.PersistentFlags().StringVar(&vaultAddr, "vault-addr", "", "Vault server address (env: VAULT_ADDR)")
	rootCmd.PersistentFlags().StringVar(&vaultToken, "vault-token", "", "Vault token (env: VAULT_TOKEN)")

	rootCmd.AddCommand(
		newPackCmd(),
		newInspectCmd(),
		newVerifyCmd(),
		newRenewCmd(),
	)

	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
