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
		var req osvBatchRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Fatalf("decoding request: %v", err)
		}

		results := make([]osvBatchResult, len(req.Queries))
		for i, q := range req.Queries {
			if q.Package.Name == "openssl" {
				results[i] = osvBatchResult{
					Vulns: []osvVulnResponse{
						{ID: "OSV-2021-1234", Summary: "Buffer overflow", Aliases: []string{"CVE-2021-1234"}},
					},
				}
			}
		}
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(osvBatchResponse{Results: results}); err != nil {
			t.Fatalf("encoding response: %v", err)
		}
	}))
	defer server.Close()

	scanner := &Scanner{
		osvClient: &OSVClient{httpClient: server.Client(), baseURL: server.URL, maxRetries: 1},
		parseBinary: func(path string) (*BinaryInfo, error) {
			return &BinaryInfo{Path: path, Format: "elf", Arch: "amd64"}, nil
		},
		matchLibrary: func(BinaryInfo) []LibraryMatch {
			return []LibraryMatch{
				{
					Signature: librarySignature{
						Name:         "openssl",
						OSVEcosystem: "OSS-Fuzz",
						OSVPackage:   "openssl",
					},
					Version: "1.1.1",
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
		t.Fatalf("expected CVE alias, got %q", results[0].CVE)
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
		osvClient: &OSVClient{httpClient: http.DefaultClient, baseURL: "http://127.0.0.1:0", maxRetries: 0},
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
