package verify

import (
	"context"
	"crypto/x509"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"
)

// RevocationChecker checks whether an X.509 certificate has been revoked.
type RevocationChecker interface {
	IsRevoked(ctx context.Context, cert *x509.Certificate) (bool, error)
}

// CRLChecker checks certificate revocation status using CRL distribution
// points embedded in the certificate. CRLs are cached with a configurable TTL.
type CRLChecker struct {
	httpClient *http.Client
	cache      sync.Map // map[string]*cachedCRL
	cacheTTL   time.Duration
}

type cachedCRL struct {
	list      *x509.RevocationList
	fetchedAt time.Time
}

type CRLOption func(*CRLChecker)

// WithCRLCacheTTL sets how long fetched CRLs are cached before re-fetching.
func WithCRLCacheTTL(ttl time.Duration) CRLOption {
	return func(c *CRLChecker) { c.cacheTTL = ttl }
}

// NewCRLChecker creates a CRL-based revocation checker.
func NewCRLChecker(opts ...CRLOption) *CRLChecker {
	c := &CRLChecker{
		httpClient: &http.Client{Timeout: 10 * time.Second},
		cacheTTL:   1 * time.Hour,
	}
	for _, opt := range opts {
		opt(c)
	}
	return c
}

func (c *CRLChecker) IsRevoked(ctx context.Context, cert *x509.Certificate) (bool, error) {
	if len(cert.CRLDistributionPoints) == 0 {
		return false, nil
	}

	var lastErr error
	for _, dp := range cert.CRLDistributionPoints {
		crl, err := c.fetchCRL(ctx, dp)
		if err != nil {
			lastErr = err
			continue
		}
		for _, entry := range crl.RevokedCertificateEntries {
			if entry.SerialNumber.Cmp(cert.SerialNumber) == 0 {
				return true, nil
			}
		}
	}

	if lastErr != nil {
		return false, fmt.Errorf("CRL check: all distribution points failed: %w", lastErr)
	}
	return false, nil
}

func (c *CRLChecker) fetchCRL(ctx context.Context, url string) (*x509.RevocationList, error) {
	// Check cache
	if cached, ok := c.cache.Load(url); ok {
		entry := cached.(*cachedCRL)
		if time.Since(entry.fetchedAt) < c.cacheTTL {
			return entry.list, nil
		}
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("create CRL request: %w", err)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch CRL: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("fetch CRL: status %d", resp.StatusCode)
	}

	data, err := io.ReadAll(io.LimitReader(resp.Body, 10*1024*1024)) // 10MB limit
	if err != nil {
		return nil, fmt.Errorf("read CRL: %w", err)
	}

	crl, err := x509.ParseRevocationList(data)
	if err != nil {
		return nil, fmt.Errorf("parse CRL: %w", err)
	}

	c.cache.Store(url, &cachedCRL{list: crl, fetchedAt: time.Now()})
	return crl, nil
}

// CompositeRevocationChecker tries multiple revocation checking strategies.
// A certificate is considered revoked if ANY checker reports it as revoked.
type CompositeRevocationChecker struct {
	checkers []RevocationChecker
}

// NewCompositeRevocationChecker creates a checker that tries multiple strategies.
func NewCompositeRevocationChecker(checkers ...RevocationChecker) *CompositeRevocationChecker {
	return &CompositeRevocationChecker{checkers: checkers}
}

func (c *CompositeRevocationChecker) IsRevoked(ctx context.Context, cert *x509.Certificate) (bool, error) {
	var lastErr error
	for _, checker := range c.checkers {
		revoked, err := checker.IsRevoked(ctx, cert)
		if err != nil {
			lastErr = err
			continue
		}
		if revoked {
			return true, nil
		}
	}
	if lastErr != nil {
		return false, lastErr
	}
	return false, nil
}
