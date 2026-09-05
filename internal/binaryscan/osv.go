// Package binaryscan's OSV client queries the public OSV.dev API for known
// vulnerabilities affecting statically-linked libraries detected in a binary.
package binaryscan

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/marshal-security/marshal/internal/findings"
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
		if m.Version != "" && m.Signature.OSVEcosystem != "" && m.Signature.OSVPackage != "" {
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
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) || ctx.Err() != nil {
			return nil, err
		}
		// Degrade gracefully: return no CVE enrichment rather than failing the scan.
		return nil, nil //nolint:nilerr
	}

	results := make(map[string][]OSVVuln, len(versioned))
	for i, m := range versioned {
		if i >= len(batchResp.Results) {
			continue
		}
		for _, v := range batchResp.Results[i].Vulns {
			results[m.Signature.Name] = append(results[m.Signature.Name], OSVVuln{
				ID:       v.ID,
				Summary:  v.Summary,
				Aliases:  v.Aliases,
				Severity: severityFromOSV(v.Severity),
			})
		}
	}
	return results, nil
}

func severityFromOSV(entries []struct {
	Type  string `json:"type"`
	Score string `json:"score"`
}) string {
	for _, entry := range entries {
		score := strings.TrimSpace(entry.Score)
		if score == "" {
			continue
		}
		if n, err := strconv.ParseFloat(score, 64); err == nil {
			return severityLabelFromCVSS(n)
		}
		switch strings.ToUpper(strings.TrimSpace(entry.Type)) {
		case "CVSS_V3", "CVSS_V3.0", "CVSS_V3.1":
			if n, ok := parseCVSSv3Vector(score); ok {
				return severityLabelFromCVSS(n)
			}
		}
	}
	return string(findings.SeverityUnknown)
}

func severityLabelFromCVSS(score float64) string {
	switch {
	case score >= 9.0:
		return string(findings.SeverityCritical)
	case score >= 7.0:
		return string(findings.SeverityHigh)
	case score >= 4.0:
		return string(findings.SeverityMedium)
	case score > 0:
		return string(findings.SeverityLow)
	default:
		return string(findings.SeverityUnknown)
	}
}

func parseCVSSv3Vector(vector string) (float64, bool) {
	v := strings.TrimPrefix(strings.TrimSpace(vector), "CVSS:3.0/")
	v = strings.TrimPrefix(v, "CVSS:3.1/")
	parts := strings.Split(v, "/")
	metrics := map[string]string{}
	for _, part := range parts {
		kv := strings.SplitN(part, ":", 2)
		if len(kv) != 2 {
			continue
		}
		metrics[kv[0]] = kv[1]
	}

	av, ok := map[string]float64{"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20}[metrics["AV"]]
	if !ok {
		return 0, false
	}
	ac, ok := map[string]float64{"L": 0.77, "H": 0.44}[metrics["AC"]]
	if !ok {
		return 0, false
	}
	ui, ok := map[string]float64{"N": 0.85, "R": 0.62}[metrics["UI"]]
	if !ok {
		return 0, false
	}
	scope, ok := metrics["S"]
	if !ok {
		return 0, false
	}

	var pr float64
	switch scope {
	case "U":
		pr, ok = map[string]float64{"N": 0.85, "L": 0.62, "H": 0.27}[metrics["PR"]]
	case "C":
		pr, ok = map[string]float64{"N": 0.85, "L": 0.68, "H": 0.50}[metrics["PR"]]
	default:
		ok = false
	}
	if !ok {
		return 0, false
	}

	c, ok := map[string]float64{"H": 0.56, "L": 0.22, "N": 0}[metrics["C"]]
	if !ok {
		return 0, false
	}
	i, ok := map[string]float64{"H": 0.56, "L": 0.22, "N": 0}[metrics["I"]]
	if !ok {
		return 0, false
	}
	a, ok := map[string]float64{"H": 0.56, "L": 0.22, "N": 0}[metrics["A"]]
	if !ok {
		return 0, false
	}

	iscBase := 1 - ((1 - c) * (1 - i) * (1 - a))
	var impact float64
	switch scope {
	case "U":
		impact = 6.42 * iscBase
	case "C":
		impact = 7.52*(iscBase-0.029) - 3.25*math.Pow(iscBase-0.02, 15)
	}
	if impact <= 0 {
		return 0, true
	}

	exploitability := 8.22 * av * ac * pr * ui
	base := impact + exploitability
	if scope == "C" {
		base *= 1.08
	}
	if base > 10 {
		base = 10
	}
	return math.Ceil(base*10) / 10, true
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
