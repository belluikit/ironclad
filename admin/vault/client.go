// SPDX-License-Identifier: MIT
// Copyright (c) 2026 TrendVidia, LLC.

package vault

import (
	"fmt"

	vaultapi "github.com/hashicorp/vault/api"
)

// Config holds the configuration for connecting to a Vault server.
type Config struct {
	Address string // Vault server URL (e.g., "https://vault:8200")
	Token   string // Vault token for authentication
}

// Client wraps the Vault API client.
type Client struct {
	raw *vaultapi.Client
}

// NewClient creates a new Vault client from the given configuration.
// If Address is empty, it falls back to VAULT_ADDR env var.
// If Token is empty, it falls back to VAULT_TOKEN env var.
func NewClient(cfg Config) (*Client, error) {
	vaultCfg := vaultapi.DefaultConfig()
	if cfg.Address != "" {
		vaultCfg.Address = cfg.Address
	}

	raw, err := vaultapi.NewClient(vaultCfg)
	if err != nil {
		return nil, fmt.Errorf("create vault client: %w", err)
	}

	if cfg.Token != "" {
		raw.SetToken(cfg.Token)
	}

	return &Client{raw: raw}, nil
}

// Raw returns the underlying Vault API client for advanced use cases.
func (c *Client) Raw() *vaultapi.Client {
	return c.raw
}

// Transit returns a TransitClient for cryptographic operations.
// TransitClient implements both verify.SignatureVerifier and verify.DEKUnwrapper
// from the SDK, so it can be passed directly to SDK functions.
func (c *Client) Transit() *TransitClient {
	return &TransitClient{client: c.raw, mount: "transit"}
}

// PKI returns a PKIClient for certificate operations.
func (c *Client) PKI() *PKIClient {
	return &PKIClient{client: c.raw, mount: "pki"}
}
