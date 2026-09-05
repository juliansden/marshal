// Package binaryscan's OSV client queries the public OSV.dev API for known
// vulnerabilities affecting statically-linked libraries detected in a binary.
package binaryscan

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

// osvAPIBaseURL is overridable in tests to point at a mock server.
var osvAPIBaseURL = "https://api.osv.dev"

// OSVVuln is a normalized vulnerability record returned by the OSV.dev API.
type OSVVuln struct {
	ID       string
	Summary  string
	Aliases  []string
	Severity string
}

// OSVClient queries the OSV.dev batch query API for known vulnerabilities.
type OSVClient struct {
	httpClient *http.Client
	baseURL    string
	maxRetries int
}

// NewOSVClient constructs an OSVClient with sane default timeout and retry settings.
func NewOSVClient() *OSVClient {
	return &OSVClient{
		httpClient: &http.Client{Timeout: 5 * time.Second},
		baseURL:    osvAPIBaseURL,
		maxRetries: 1,
	}
}

type osvQueryPackage struct {
	Name      string `json:"name"`
	Ecosystem string `json:"ecosystem"`
}

type osvQuery struct {
	Package osvQueryPackage `json:"package"`
	Version string          `json:"version,omitempty"`
}

type osvBatchRequest struct {
	Queries []osvQuery `json:"queries"`
}

type osvVulnResponse struct {
	ID       string   `json:"id"`
	Summary  string   `json:"summary"`
	Aliases  []string `json:"aliases"`
	Severity []struct {
		Type  string `json:"type"`
		Score string `json:"score"`
	} `json:"severity"`
}

type osvBatchResult struct {
	Vulns []osvVulnResponse `json:"vulns"`
}

type osvBatchResponse struct {
	Results []osvBatchResult `json:"results"`
}

// QueryLibraries queries OSV.dev for known vulnerabilities affecting each matched library.
// Matches with an undetermined version are skipped: querying OSV without a version
// returns every historical CVE for the package, which is misleading noise rather
// than a useful finding. Network failures are non-fatal: they produce an empty
// result so a scan can proceed without CVE enrichment rather than failing outright.
func (c *OSVClient) QueryLibraries(ctx context.Context, matches []LibraryMatch) (map[string][]OSVVuln, error) {
	versioned := make([]LibraryMatch, 0, len(matches))
	for _, m := range matches {
		if m.Version != "" {
			versioned = append(versioned, m)
		}
	}
	if len(versioned) == 0 {
		return nil, nil
	}

	req := osvBatchRequest{Queries: make([]osvQuery, len(versioned))}
	for i, m := range versioned {
		req.Queries[i] = osvQuery{
			Package: osvQueryPackage{Name: m.Signature.OSVPackage, Ecosystem: m.Signature.OSVEcosystem},
			Version: m.Version,
		}
	}

	batchResp, err := c.queryBatchWithRetry(ctx, req)
	if err != nil {
		// Degrade gracefully: return no CVE enrichment rather than failing the scan.
		return nil, nil //nolint:nilerr
	}

	results := make(map[string][]OSVVuln, len(versioned))
	for i, m := range versioned {
		if i >= len(batchResp.Results) {
			continue
		}
		for _, v := range batchResp.Results[i].Vulns {
			severity := ""
			if len(v.Severity) > 0 {
				severity = v.Severity[0].Score
			}
			results[m.Signature.Name] = append(results[m.Signature.Name], OSVVuln{
				ID:       v.ID,
				Summary:  v.Summary,
				Aliases:  v.Aliases,
				Severity: severity,
			})
		}
	}
	return results, nil
}

func (c *OSVClient) queryBatchWithRetry(ctx context.Context, req osvBatchRequest) (*osvBatchResponse, error) {
	var lastErr error
	for attempt := 0; attempt <= c.maxRetries; attempt++ {
		resp, err := c.queryBatch(ctx, req)
		if err == nil {
			return resp, nil
		}
		lastErr = err
	}
	return nil, lastErr
}

func (c *OSVClient) queryBatch(ctx context.Context, req osvBatchRequest) (*osvBatchResponse, error) {
	body, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("binaryscan: encoding OSV query: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/v1/querybatch", bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("binaryscan: building OSV request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")

	httpResp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("binaryscan: calling OSV API: %w", err)
	}
	defer httpResp.Body.Close()

	if httpResp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("binaryscan: OSV API returned status %d", httpResp.StatusCode)
	}

	var batchResp osvBatchResponse
	if err := json.NewDecoder(httpResp.Body).Decode(&batchResp); err != nil {
		return nil, fmt.Errorf("binaryscan: decoding OSV response: %w", err)
	}
	return &batchResp, nil
}
