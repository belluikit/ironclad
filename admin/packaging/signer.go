package packaging

import (
	"context"
	"crypto/sha256"
	"fmt"

	sdkcontainer "github.com/belluikit/ironclad/sdk/container"
)

// Signer defines the signing operations needed by the packaging module.
type Signer interface {
	Sign(ctx context.Context, keyName string, data []byte) (string, error)
}

// SignDistributorEnvelope signs the envelope with the distributor (platform) key.
// It uses DistributorSignableBytes which covers everything except the
// distributor signature itself and the payload.
func SignDistributorEnvelope(ctx context.Context, signer Signer, keyName string, env *sdkcontainer.ContentEnvelope) error {
	signable := env.DistributorSignableBytes()
	sig, err := signer.Sign(ctx, keyName, signable)
	if err != nil {
		return fmt.Errorf("sign distributor envelope: %w", err)
	}
	env.DistributorSignature = []byte(sig)
	return nil
}

// SignLicense signs a license token.
func SignLicense(ctx context.Context, signer Signer, keyName string, sl *sdkcontainer.SignedLicense) error {
	sig, err := signer.Sign(ctx, keyName, sl.TokenBytes)
	if err != nil {
		return fmt.Errorf("sign license: %w", err)
	}
	sl.Signature = []byte(sig)
	return nil
}

// SignRenewal signs a renewal token.
func SignRenewal(ctx context.Context, signer Signer, keyName string, sr *sdkcontainer.SignedRenewal) error {
	sig, err := signer.Sign(ctx, keyName, sr.TokenBytes)
	if err != nil {
		return fmt.Errorf("sign renewal: %w", err)
	}
	sr.Signature = []byte(sig)
	return nil
}

// ContentHash computes the SHA-256 hash of the plaintext content.
func ContentHash(plaintext []byte) [32]byte {
	return sha256.Sum256(plaintext)
}
