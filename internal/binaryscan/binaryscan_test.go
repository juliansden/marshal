package binaryscan

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestScanTargetEndToEnd(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.URL.Query().Get("cpeName"); got != "cpe:2.3:a:openssl:openssl:1.1.1f:*:*:*:*:*:*:*" {
			t.Fatalf("unexpected cpeName query: %s", got)
		}
		resp := nvdResponse{
			Vulnerabilities: []nvdVulnerability{
				{CVE: nvdCVE{
					ID:           "CVE-2021-1234",
					Descriptions: []nvdDescription{{Lang: "en", Value: "Buffer overflow"}},
					Metrics:      nvdMetrics{CvssMetricV31: []nvdCVSSMetric{{CVSSData: nvdCVSSData{BaseSeverity: "HIGH"}}}},
				}},
			},
		}
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(resp); err != nil {
			t.Fatalf("encoding response: %v", err)
		}
	}))
	defer server.Close()

	scanner := &Scanner{
		nvdClient: &NVDClient{httpClient: server.Client(), baseURL: server.URL, maxRetries: 1, limiter: newRateLimiter(1000, 0)},
		parseBinary: func(path string) (*BinaryInfo, error) {
			return &BinaryInfo{Path: path, Format: "elf", Arch: "amd64"}, nil
		},
		matchLibrary: func(BinaryInfo) []LibraryMatch {
			return []LibraryMatch{
				{
					Signature: librarySignature{Name: "openssl", CPEVendor: "openssl", CPEProduct: "openssl"},
					Version:   "1.1.1f",
				},
			}
		},
	}

	results, err := scanner.ScanTarget(context.Background(), "fixture.bin")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(results))
	}
	if results[0].CVE != "CVE-2021-1234" {
		t.Fatalf("expected CVE-2021-1234, got %q", results[0].CVE)
	}
	if results[0].Severity != "HIGH" {
		t.Fatalf("expected HIGH severity, got %q", results[0].Severity)
	}
}

func TestScanTargetNoMatchesReturnsNil(t *testing.T) {
	scanner := NewScanner()

	target := buildFixture(t, "linux", "amd64", "fixture_elf")

	results, err := scanner.ScanTarget(context.Background(), target)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(results) != 0 {
		t.Errorf("expected no findings for a binary with no known signatures, got %d", len(results))
	}
}

func TestScanTargetReportsUnenrichedMatch(t *testing.T) {
	scanner := &Scanner{
		nvdClient: &NVDClient{httpClient: http.DefaultClient, baseURL: "http://127.0.0.1:0", maxRetries: 0, limiter: newRateLimiter(1000, 0)},
		parseBinary: func(path string) (*BinaryInfo, error) {
			return &BinaryInfo{Path: path, Format: "elf", Arch: "amd64"}, nil
		},
		matchLibrary: func(BinaryInfo) []LibraryMatch {
			return []LibraryMatch{{Signature: librarySignature{Name: "zlib"}}}
		},
	}

	results, err := scanner.ScanTarget(context.Background(), "fixture.bin")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(results))
	}
	if results[0].Severity != "INFO" {
		t.Fatalf("expected INFO severity, got %s", results[0].Severity)
	}
}
