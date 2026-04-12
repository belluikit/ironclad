package license

import (
	"context"
	"crypto/ecdsa"
	"crypto/x509"
	"fmt"
	"math/big"

	"github.com/trendvidia/ironclad/sdk/container"
	"github.com/trendvidia/ironclad/sdk/verify"
)

// ValidationResult holds the outcome of a full container validation.
type ValidationResult struct {
	Status        Status
	Terms         *EffectiveTerms
	EnvelopeValid bool
	LicenseValid  bool
	RenewalsValid int // number of valid renewals in chain
	Error         error
}

// Validator validates container signatures and license state.
type Validator struct {
	verifier   verify.SignatureVerifier // for distributor sigs (Vault Transit)
	signingKey string                  // key name for license/renewal signatures
	caRoots    *x509.CertPool          // trusted CA roots for developer cert verification
}

// NewValidator creates a new Validator.
// The caRoots pool is used to verify the developer certificate chain.
// The verifier is used for distributor (Vault Transit) signature verification.
func NewValidator(verifier verify.SignatureVerifier, signingKey string, caRoots *x509.CertPool) *Validator {
	return &Validator{
		verifier:   verifier,
		signingKey: signingKey,
		caRoots:    caRoots,
	}
}

// ValidateEnvelope verifies both the developer and distributor signatures.
func (v *Validator) ValidateEnvelope(ctx context.Context, env *container.ContentEnvelope, distributorKeyName string) error {
	// 1. Verify developer certificate chain against trusted CA roots
	if v.caRoots != nil && len(env.DeveloperCertificate) > 0 {
		devCert, err := x509.ParseCertificate(env.DeveloperCertificate)
		if err != nil {
			return fmt.Errorf("parse developer certificate: %w", err)
		}

		if _, err := devCert.Verify(x509.VerifyOptions{Roots: v.caRoots}); err != nil {
			return fmt.Errorf("developer certificate chain invalid: %w", err)
		}

		// 2. Verify developer signature (ECDSA) over developer signable bytes
		devSignable := env.DeveloperSignableBytes()
		if err := verifyECDSA(devCert, devSignable, env.DeveloperSignature); err != nil {
			return fmt.Errorf("developer signature invalid: %w", err)
		}
	}

	// 3. Verify distributor signature (Vault Transit) over distributor signable bytes
	distSignable := env.DistributorSignableBytes()
	valid, err := v.verifier.Verify(ctx, distributorKeyName, distSignable, string(env.DistributorSignature))
	if err != nil {
		return fmt.Errorf("verify distributor signature: %w", err)
	}
	if !valid {
		return fmt.Errorf("distributor envelope signature is invalid")
	}

	return nil
}

// ValidateLicense verifies the license token signature.
func (v *Validator) ValidateLicense(ctx context.Context, license *container.SignedLicense) error {
	valid, err := v.verifier.Verify(ctx, v.signingKey, license.TokenBytes, string(license.Signature))
	if err != nil {
		return fmt.Errorf("verify license signature: %w", err)
	}
	if !valid {
		return fmt.Errorf("license signature is invalid")
	}
	return nil
}

// ValidateRenewalChain verifies each renewal token's signature and
// validates the parent_ref chain integrity.
func (v *Validator) ValidateRenewalChain(ctx context.Context, license *container.LicenseToken, renewals container.RenewalChain) (int, error) {
	expectedParent := license.LicenseID
	validCount := 0

	for i, sr := range renewals {
		valid, err := v.verifier.Verify(ctx, v.signingKey, sr.TokenBytes, string(sr.Signature))
		if err != nil {
			return validCount, fmt.Errorf("verify renewal %d signature: %w", i, err)
		}
		if !valid {
			return validCount, fmt.Errorf("renewal %d signature is invalid", i)
		}

		rt, err := sr.Token()
		if err != nil {
			return validCount, fmt.Errorf("parse renewal %d: %w", i, err)
		}

		if rt.ParentRef != expectedParent {
			return validCount, fmt.Errorf("renewal %d: parent_ref %s does not match expected %s", i, rt.ParentRef, expectedParent)
		}

		if rt.ContentID != license.ContentID {
			return validCount, fmt.Errorf("renewal %d: content_id %s does not match license content_id %s", i, rt.ContentID, license.ContentID)
		}

		expectedParent = rt.RenewalID
		validCount++
	}

	return validCount, nil
}

// ValidateContainer performs full validation of a container:
// envelope signatures (developer + distributor), license signature,
// renewal chain, and license status.
func (v *Validator) ValidateContainer(ctx context.Context, c *container.Container, distributorKeyName string) (*ValidationResult, error) {
	result := &ValidationResult{}

	if err := v.ValidateEnvelope(ctx, &c.Envelope, distributorKeyName); err != nil {
		result.Error = err
		return result, err
	}
	result.EnvelopeValid = true

	if err := v.ValidateLicense(ctx, &c.License); err != nil {
		result.Error = err
		return result, err
	}
	result.LicenseValid = true

	licenseToken, err := c.License.Token()
	if err != nil {
		result.Error = err
		return result, err
	}

	if licenseToken.ContentID != c.Envelope.ContentID {
		err := fmt.Errorf("license content_id %s does not match envelope content_id %s", licenseToken.ContentID, c.Envelope.ContentID)
		result.Error = err
		return result, err
	}

	validRenewals, err := v.ValidateRenewalChain(ctx, licenseToken, c.Renewals)
	result.RenewalsValid = validRenewals
	if err != nil {
		result.Error = err
		return result, err
	}

	terms, err := EvaluateTerms(licenseToken, c.Renewals)
	if err != nil {
		result.Error = err
		return result, err
	}
	result.Terms = terms

	return result, nil
}

// verifyECDSA verifies an ECDSA signature (ASN.1 DER encoded) against data
// using the public key from an X.509 certificate.
func verifyECDSA(cert *x509.Certificate, data, signature []byte) error {
	pubKey, ok := cert.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return fmt.Errorf("developer certificate does not contain an ECDSA public key")
	}

	// Parse ASN.1 DER signature
	var r, s big.Int
	// Try ASN.1 first — standard ECDSA signature format
	if !ecdsa.VerifyASN1(pubKey, data, signature) {
		// Fallback: try raw r||s concatenation
		halfLen := len(signature) / 2
		if halfLen == 0 {
			return fmt.Errorf("signature verification failed")
		}
		r.SetBytes(signature[:halfLen])
		s.SetBytes(signature[halfLen:])
		if !ecdsa.Verify(pubKey, data, &r, &s) {
			return fmt.Errorf("signature verification failed")
		}
	}
	return nil
}
