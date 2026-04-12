package vault

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"time"

	vaultapi "github.com/hashicorp/vault/api"
)

// PKIClient handles certificate operations via Vault's PKI Secrets Engine.
type PKIClient struct {
	client *vaultapi.Client
	mount  string // PKI mount path, defaults to "pki"
}

// PKIOption configures a PKIClient.
type PKIOption func(*PKIClient)

// WithPKIMount sets a non-default mount path for the PKI engine.
func WithPKIMount(mount string) PKIOption {
	return func(pc *PKIClient) {
		pc.mount = mount
	}
}

// NewPKIClient creates a PKIClient from a Vault API client.
func NewPKIClient(client *vaultapi.Client, opts ...PKIOption) *PKIClient {
	pc := &PKIClient{
		client: client,
		mount:  "pki",
	}
	for _, opt := range opts {
		opt(pc)
	}
	return pc
}

// CertificateResult holds the results of a certificate issuance request.
type CertificateResult struct {
	Certificate    *x509.Certificate // parsed certificate
	CertificateDER []byte            // DER-encoded certificate (for storage in container)
	CertificatePEM string            // PEM-encoded certificate
	CAChainPEM     []string          // PEM-encoded CA certificate chain
}

// IssueCertificate requests a new certificate from Vault's PKI engine.
func (pc *PKIClient) IssueCertificate(ctx context.Context, roleName, commonName string, ttl time.Duration) (*CertificateResult, error) {
	path := fmt.Sprintf("%s/issue/%s", pc.mount, roleName)

	secret, err := pc.client.Logical().WriteWithContext(ctx, path, map[string]interface{}{
		"common_name": commonName,
		"ttl":         ttl.String(),
	})
	if err != nil {
		return nil, fmt.Errorf("vault pki issue: %w", err)
	}
	if secret == nil || secret.Data == nil {
		return nil, fmt.Errorf("vault pki issue: empty response")
	}

	certPEM, ok := secret.Data["certificate"].(string)
	if !ok {
		return nil, fmt.Errorf("vault pki issue: missing certificate in response")
	}

	// Parse PEM to DER
	block, _ := pem.Decode([]byte(certPEM))
	if block == nil {
		return nil, fmt.Errorf("vault pki issue: failed to decode certificate PEM")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("vault pki issue: parse certificate: %w", err)
	}

	result := &CertificateResult{
		Certificate:    cert,
		CertificateDER: block.Bytes,
		CertificatePEM: certPEM,
	}

	// Parse CA chain if present
	if caChain, ok := secret.Data["ca_chain"].([]interface{}); ok {
		for _, ca := range caChain {
			if caStr, ok := ca.(string); ok {
				result.CAChainPEM = append(result.CAChainPEM, caStr)
			}
		}
	}

	return result, nil
}

// GetCACertificate fetches the CA certificate from the PKI mount.
func (pc *PKIClient) GetCACertificate(ctx context.Context) (*x509.Certificate, error) {
	path := fmt.Sprintf("%s/ca/pem", pc.mount)
	secret, err := pc.client.Logical().ReadWithContext(ctx, path)
	if err != nil {
		return nil, fmt.Errorf("vault pki ca: %w", err)
	}

	if secret == nil || secret.Data == nil {
		return nil, fmt.Errorf("vault pki ca: empty response")
	}

	caPEM, ok := secret.Data["certificate"].(string)
	if !ok {
		return nil, fmt.Errorf("vault pki ca: missing certificate in response")
	}

	block, _ := pem.Decode([]byte(caPEM))
	if block == nil {
		return nil, fmt.Errorf("vault pki ca: failed to decode PEM")
	}

	return x509.ParseCertificate(block.Bytes)
}
