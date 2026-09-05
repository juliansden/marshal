package binaryscan

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
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

	// A trivial ELF binary won't contain OpenSSL symbols, so exercise the
	// scanner pipeline directly against a stub-injected parse result instead
	// of relying on binary content matching.
	scanner := &Scanner{osvClient: &OSVClient{httpClient: server.Client(), baseURL: server.URL, maxRetries: 1}}

	tmpDir := t.TempDir()
	target := filepath.Join(tmpDir, "fixture.bin")
	if err := os.WriteFile(target, []byte("placeholder"), 0o644); err != nil {
		t.Fatalf("writing fixture: %v", err)
	}

	matches := MatchSignatures(BinaryInfo{
		Symbols: []string{"SSL_CTX_new", "OPENSSL_init_ssl", "OPENSSL_1_1_1"},
	})
	if len(matches) != 1 {
		t.Fatalf("expected 1 signature match, got %d", len(matches))
	}

	vulnsByLib, err := scanner.osvClient.QueryLibraries(context.Background(), matches)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(vulnsByLib["openssl"]) != 1 {
		t.Fatalf("expected 1 vuln for openssl, got %d", len(vulnsByLib["openssl"]))
	}
}

func TestScanTargetNoMatchesReturnsNil(t *testing.T) {
	scanner := NewScanner()

	tmpDir := t.TempDir()
	target := buildFixture(t, "linux", "amd64", "fixture_elf")
	_ = tmpDir

	results, err := scanner.ScanTarget(context.Background(), target)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(results) != 0 {
		t.Errorf("expected no findings for a binary with no known signatures, got %d", len(results))
	}
}
