package license

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/google/uuid"
	sdkcontainer "github.com/trendvidia/ironclad/sdk/container"
	"github.com/trendvidia/ironclad/sdk/verify"
)

// RenewalRequest is sent to the renewal endpoint.
type RenewalRequest struct {
	LicenseID       uuid.UUID  `json:"license_id"`
	LatestRenewalID *uuid.UUID `json:"latest_renewal_id,omitempty"`
	ContentID       uuid.UUID  `json:"content_id"`
}

// RenewalResponse is received from the renewal endpoint.
type RenewalResponse struct {
	RenewalToken sdkcontainer.SignedRenewal `json:"renewal_token"`
}

// RenewalClient handles the online license renewal protocol.
type RenewalClient struct {
	httpClient *http.Client
	verifier   verify.SignatureVerifier
	signingKey string
}

// NewRenewalClient creates a new RenewalClient.
func NewRenewalClient(verifier verify.SignatureVerifier, signingKey string) *RenewalClient {
	return &RenewalClient{
		httpClient: &http.Client{Timeout: 30 * time.Second},
		verifier:   verifier,
		signingKey: signingKey,
	}
}

// Renew attempts to renew a license by contacting the renewal endpoint.
func (rc *RenewalClient) Renew(ctx context.Context, c *sdkcontainer.Container) (*sdkcontainer.SignedRenewal, error) {
	licenseToken, err := c.License.Token()
	if err != nil {
		return nil, fmt.Errorf("parse license: %w", err)
	}

	req := RenewalRequest{
		LicenseID: licenseToken.LicenseID,
		ContentID: licenseToken.ContentID,
	}

	if len(c.Renewals) > 0 {
		lastRenewal, err := c.Renewals[len(c.Renewals)-1].Token()
		if err != nil {
			return nil, fmt.Errorf("parse last renewal: %w", err)
		}
		req.LatestRenewalID = &lastRenewal.RenewalID
	}

	body, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("marshal renewal request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, licenseToken.RenewalEndpoint, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("create renewal request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := rc.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("renewal request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return nil, fmt.Errorf("renewal refused (status %d): %s", resp.StatusCode, string(respBody))
	}

	var renewalResp RenewalResponse
	if err := json.NewDecoder(resp.Body).Decode(&renewalResp); err != nil {
		return nil, fmt.Errorf("parse renewal response: %w", err)
	}

	valid, err := rc.verifier.Verify(ctx, rc.signingKey, renewalResp.RenewalToken.TokenBytes, string(renewalResp.RenewalToken.Signature))
	if err != nil {
		return nil, fmt.Errorf("verify renewal token: %w", err)
	}
	if !valid {
		return nil, fmt.Errorf("renewal token signature is invalid")
	}

	rt, err := renewalResp.RenewalToken.Token()
	if err != nil {
		return nil, fmt.Errorf("parse renewal token: %w", err)
	}
	if rt.ContentID != licenseToken.ContentID {
		return nil, fmt.Errorf("renewal token content_id mismatch")
	}

	return &renewalResp.RenewalToken, nil
}
