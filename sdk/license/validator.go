package license

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/x509"
	"fmt"

	"github.com/belluikit/ironclad/sdk/container"
	"github.com/belluikit/ironclad/sdk/verify"
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
	verifier          verify.SignatureVerifier // for distributor sigs (Vault Transit)
	signingKey        string                   // key name for license/renewal signatures
	caRoots           *x509.CertPool           // trusted CA roots for developer cert verification
	revocationChecker verify.RevocationChecker // optional, checks cert revocation
}

// ValidatorOption configures optional validator behavior.
type ValidatorOption func(*Validator)

// WithRevocationChecker adds certificate revocation checking to the validator.
func WithRevocationChecker(rc verify.RevocationChecker) ValidatorOption {
	return func(v *Validator) { v.revocationChecker = rc }
}

// NewValidator creates a new Validator.
func NewValidator(verifier verify.SignatureVerifier, signingKey string, caRoots *x509.CertPool, opts ...ValidatorOption) *Validator {
	v := &Validator{
		verifier:   verifier,
		signingKey: signingKey,
		caRoots:    caRoots,
	}
	for _, opt := range opts {
		opt(v)
	}
	return v
}

// ValidateEnvelope verifies both the developer and distributor signatures.
func (v *Validator) ValidateEnvelope(ctx context.Context, env *container.ContentEnvelope, distributorKeyName string) error {
	// 1. Verify developer certificate chain against trusted CA roots
	if v.caRoots != nil && len(env.DeveloperCertificate) > 0 && len(env.DeveloperManifest) > 0 {
		devCert, err := x509.ParseCertificate(env.DeveloperCertificate)
		if err != nil {
			return fmt.Errorf("parse developer certificate: %w", err)
		}

		if _, err := devCert.Verify(x509.VerifyOptions{Roots: v.caRoots}); err != nil {
			return fmt.Errorf("developer certificate chain invalid: %w", err)
		}

		// 2. Check certificate revocation (if checker configured)
		if v.revocationChecker != nil {
			revoked, err := v.revocationChecker.IsRevoked(ctx, devCert)
			if err != nil {
				return fmt.Errorf("revocation check failed: %w", err)
			}
			if revoked {
				return fmt.Errorf("developer certificate has been revoked")
			}
		}

		// 3. Verify developer signature (ECDSA) over developer manifest bytes
		if err := verifyECDSA(devCert, env.DeveloperManifest, env.DeveloperSignature); err != nil {
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

		if !bytes.Equal(rt.ParentRef, expectedParent) {
			return validCount, fmt.Errorf("renewal %d: parent_ref %x does not match expected %x", i, rt.ParentRef, expectedParent)
		}

		if !bytes.Equal(rt.ContentID, license.ContentID) {
			return validCount, fmt.Errorf("renewal %d: content_id %x does not match license content_id %x", i, rt.ContentID, license.ContentID)
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

	if !bytes.Equal(licenseToken.ContentID, c.Envelope.ContentID) {
		err := fmt.Errorf("license content_id %x does not match envelope content_id %x", licenseToken.ContentID, c.Envelope.ContentID)
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

// verifyECDSA verifies an ECDSA ASN.1 DER signature against data
// using the public key from an X.509 certificate.
func verifyECDSA(cert *x509.Certificate, data, signature []byte) error {
	pubKey, ok := cert.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return fmt.Errorf("developer certificate does not contain an ECDSA public key")
	}
	if !ecdsa.VerifyASN1(pubKey, data, signature) {
		return fmt.Errorf("signature verification failed")
	}
	return nil
}
