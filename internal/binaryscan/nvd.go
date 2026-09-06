// Package binaryscan's NVD client queries NIST's National Vulnerability
// Database CPE-based API for known vulnerabilities affecting statically-linked
// libraries detected in a binary. CPE (vendor:product:version) is used, rather
// than an OSV.dev package ecosystem, because statically-linked C/C++ libraries
// aren't distributed through a package manager ecosystem OSV understands --
// CPE is the standard identifier for exactly this "generic software" scenario.
package binaryscan

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"sync"
	"time"

	"github.com/marshal-security/marshal/internal/findings"
)

// nvdAPIBaseURL is overridable in tests to point at a mock server.
var nvdAPIBaseURL = "https://services.nvd.nist.gov"

// nvdAPIKeyEnvVar holds an optional NVD API key, which raises the rate limit
// from 5 requests/30s to 50 requests/30s. See https://nvd.nist.gov/developers/request-an-api-key.
const nvdAPIKeyEnvVar = "MARSHAL_NVD_API_KEY"

// NVDVuln is a normalized vulnerability record returned by the NVD API.
type NVDVuln struct {
	ID          string
	Description string
	Severity    string
}

// NVDClient queries the NVD CPE-based CVE API for known vulnerabilities.
type NVDClient struct {
	httpClient *http.Client
	baseURL    string
	apiKey     string
	maxRetries int
	limiter    *rateLimiter
}

// NewNVDClient constructs an NVDClient with sane default timeout, retry, and
// rate-limiting settings. If the MARSHAL_NVD_API_KEY environment variable is
// set, it's sent with each request to unlock NVD's higher rate limit.
func NewNVDClient() *NVDClient {
	apiKey := os.Getenv(nvdAPIKeyEnvVar)
	maxRequests := 5
	if apiKey != "" {
		maxRequests = 50
	}
	return &NVDClient{
		httpClient: &http.Client{Timeout: 10 * time.Second},
		baseURL:    nvdAPIBaseURL,
		apiKey:     apiKey,
		maxRetries: 1,
		limiter:    newRateLimiter(maxRequests, 30*time.Second),
	}
}

type nvdCVSSData struct {
	BaseScore    float64 `json:"baseScore"`
	BaseSeverity string  `json:"baseSeverity"`
}

type nvdCVSSMetric struct {
	CVSSData     nvdCVSSData `json:"cvssData"`
	BaseSeverity string      `json:"baseSeverity"`
}

type nvdCVE struct {
	ID           string           `json:"id"`
	Descriptions []nvdDescription `json:"descriptions"`
	Metrics      nvdMetrics       `json:"metrics"`
}

type nvdDescription struct {
	Lang  string `json:"lang"`
	Value string `json:"value"`
}

type nvdMetrics struct {
	CvssMetricV31 []nvdCVSSMetric `json:"cvssMetricV31"`
	CvssMetricV30 []nvdCVSSMetric `json:"cvssMetricV30"`
	CvssMetricV2  []nvdCVSSMetric `json:"cvssMetricV2"`
}

type nvdVulnerability struct {
	CVE nvdCVE `json:"cve"`
}

type nvdResponse struct {
	TotalResults    int                `json:"totalResults"`
	Vulnerabilities []nvdVulnerability `json:"vulnerabilities"`
}

// QueryLibraries queries NVD for known vulnerabilities affecting each matched
// library. Matches missing a resolved version or CPE vendor/product are
// skipped, since NVD's cpeName lookup requires an exact CPE match string.
// Network failures for an individual library are non-fatal: they're skipped
// so a scan can proceed with partial CVE enrichment rather than failing outright.
func (c *NVDClient) QueryLibraries(ctx context.Context, matches []LibraryMatch) (map[string][]NVDVuln, error) {
	eligible := make([]LibraryMatch, 0, len(matches))
	for _, m := range matches {
		if m.Version != "" && m.Signature.CPEVendor != "" && m.Signature.CPEProduct != "" {
			eligible = append(eligible, m)
		}
	}
	if len(eligible) == 0 {
		return nil, nil
	}

	results := make(map[string][]NVDVuln, len(eligible))
	for _, m := range eligible {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		c.limiter.wait(ctx)

		vulns, err := c.queryOneWithRetry(ctx, m)
		if err != nil {
			if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
				return nil, err
			}
			// Degrade gracefully: skip this library rather than failing the whole scan.
			continue
		}
		if len(vulns) > 0 {
			results[m.Signature.Name] = vulns
		}
	}
	if len(results) == 0 {
		return nil, nil
	}
	return results, nil
}

func (c *NVDClient) queryOneWithRetry(ctx context.Context, match LibraryMatch) ([]NVDVuln, error) {
	var lastErr error
	for attempt := 0; attempt <= c.maxRetries; attempt++ {
		vulns, err := c.queryOne(ctx, match)
		if err == nil {
			return vulns, nil
		}
		lastErr = err
	}
	return nil, lastErr
}

func (c *NVDClient) queryOne(ctx context.Context, match LibraryMatch) ([]NVDVuln, error) {
	cpeName := fmt.Sprintf("cpe:2.3:a:%s:%s:%s:*:*:*:*:*:*:*",
		match.Signature.CPEVendor, match.Signature.CPEProduct, match.Version)

	reqURL := c.baseURL + "/rest/json/cves/2.0?cpeName=" + url.QueryEscape(cpeName)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return nil, fmt.Errorf("binaryscan: building NVD request: %w", err)
	}
	if c.apiKey != "" {
		req.Header.Set("apiKey", c.apiKey)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("binaryscan: calling NVD API: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("binaryscan: NVD API returned status %d", resp.StatusCode)
	}

	var nvdResp nvdResponse
	if err := json.NewDecoder(resp.Body).Decode(&nvdResp); err != nil {
		return nil, fmt.Errorf("binaryscan: decoding NVD response: %w", err)
	}

	vulns := make([]NVDVuln, 0, len(nvdResp.Vulnerabilities))
	for _, v := range nvdResp.Vulnerabilities {
		vulns = append(vulns, NVDVuln{
			ID:          v.CVE.ID,
			Description: firstDescription(v.CVE.Descriptions),
			Severity:    severityFromNVDMetrics(v.CVE.Metrics),
		})
	}
	return vulns, nil
}

func firstDescription(descriptions []nvdDescription) string {
	for _, d := range descriptions {
		if d.Lang == "en" {
			return d.Value
		}
	}
	if len(descriptions) > 0 {
		return descriptions[0].Value
	}
	return ""
}

// severityFromNVDMetrics returns the highest-fidelity baseSeverity available,
// preferring the newest CVSS version NVD provides for the CVE.
func severityFromNVDMetrics(metrics nvdMetrics) string {
	for _, group := range [][]nvdCVSSMetric{metrics.CvssMetricV31, metrics.CvssMetricV30, metrics.CvssMetricV2} {
		for _, m := range group {
			if m.CVSSData.BaseSeverity != "" {
				return m.CVSSData.BaseSeverity
			}
			if m.BaseSeverity != "" {
				return m.BaseSeverity
			}
		}
	}
	return string(findings.SeverityUnknown)
}

// rateLimiter enforces a sliding-window max-requests-per-window limit,
// matching NVD's published rate limits (5/30s unauthenticated, 50/30s with an API key).
type rateLimiter struct {
	mu          sync.Mutex
	maxRequests int
	window      time.Duration
	timestamps  []time.Time
	now         func() time.Time
	sleep       func(context.Context, time.Duration)
}

func newRateLimiter(maxRequests int, window time.Duration) *rateLimiter {
	return &rateLimiter{
		maxRequests: maxRequests,
		window:      window,
		now:         time.Now,
		sleep: func(ctx context.Context, d time.Duration) {
			t := time.NewTimer(d)
			defer t.Stop()
			select {
			case <-t.C:
			case <-ctx.Done():
			}
		},
	}
}

// wait blocks, if necessary, until issuing another request would stay within
// the configured rate limit, or until ctx is done.
func (r *rateLimiter) wait(ctx context.Context) {
	r.mu.Lock()
	defer r.mu.Unlock()

	now := r.now()
	r.pruneLocked(now)

	if len(r.timestamps) >= r.maxRequests {
		oldest := r.timestamps[0]
		if waitDur := r.window - now.Sub(oldest); waitDur > 0 {
			r.sleep(ctx, waitDur)
		}
		now = r.now()
		r.pruneLocked(now)
	}

	r.timestamps = append(r.timestamps, r.now())
}

func (r *rateLimiter) pruneLocked(now time.Time) {
	cutoff := now.Add(-r.window)
	kept := r.timestamps[:0]
	for _, t := range r.timestamps {
		if t.After(cutoff) {
			kept = append(kept, t)
		}
	}
	r.timestamps = kept
}
