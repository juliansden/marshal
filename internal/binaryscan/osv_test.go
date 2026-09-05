package binaryscan

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestQueryLibrariesSuccess(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req osvBatchRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Fatalf("decoding request: %v", err)
		}
		if len(req.Queries) != 1 || req.Queries[0].Package.Name != "openssl" {
			t.Fatalf("unexpected request payload: %+v", req)
		}

		resp := osvBatchResponse{
			Results: []osvBatchResult{
				{
					Vulns: []osvVulnResponse{
						{ID: "OSV-2021-1234", Summary: "Buffer overflow", Aliases: []string{"CVE-2021-1234"}},
					},
				},
			},
		}
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(resp); err != nil {
			t.Fatalf("encoding response: %v", err)
		}
	}))
	defer server.Close()

	client := &OSVClient{httpClient: server.Client(), baseURL: server.URL, maxRetries: 1}
	matches := []LibraryMatch{{Signature: librarySignature{Name: "openssl", OSVEcosystem: "OSS-Fuzz", OSVPackage: "openssl"}, Version: "1.1.1"}}

	result, err := client.QueryLibraries(context.Background(), matches)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	vulns := result["openssl"]
	if len(vulns) != 1 {
		t.Fatalf("expected 1 vuln, got %d", len(vulns))
	}
	if vulns[0].ID != "OSV-2021-1234" || vulns[0].Aliases[0] != "CVE-2021-1234" {
		t.Errorf("unexpected vuln contents: %+v", vulns[0])
	}
	if vulns[0].Severity != "UNKNOWN" {
		t.Errorf("expected UNKNOWN severity when OSV response omits severity, got %q", vulns[0].Severity)
	}
}

func TestQueryLibrariesDegradesGracefullyOnNetworkError(t *testing.T) {
	client := &OSVClient{httpClient: http.DefaultClient, baseURL: "http://127.0.0.1:0", maxRetries: 0}
	matches := []LibraryMatch{
		{Signature: librarySignature{Name: "openssl", OSVEcosystem: "OSS-Fuzz", OSVPackage: "openssl"}, Version: "1.1.1"},
	}

	result, err := client.QueryLibraries(context.Background(), matches)
	if err != nil {
		t.Fatalf("expected graceful degradation (nil error), got %v", err)
	}
	if result != nil {
		t.Errorf("expected nil result on network failure, got %+v", result)
	}
}

func TestQueryLibrariesEmptyInput(t *testing.T) {
	client := NewOSVClient()
	result, err := client.QueryLibraries(context.Background(), nil)
	if err != nil || result != nil {
		t.Errorf("expected nil, nil for empty input, got %+v, %v", result, err)
	}
}

func TestQueryLibrariesSkipsUndeterminedVersion(t *testing.T) {
	called := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(osvBatchResponse{}); err != nil {
			t.Fatalf("encoding response: %v", err)
		}
	}))
	defer server.Close()

	client := &OSVClient{httpClient: server.Client(), baseURL: server.URL, maxRetries: 1}
	matches := []LibraryMatch{
		{Signature: librarySignature{Name: "zlib", OSVEcosystem: "OSS-Fuzz", OSVPackage: "zlib"}, Version: ""},
	}

	result, err := client.QueryLibraries(context.Background(), matches)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result != nil {
		t.Errorf("expected nil result when no matches have a determined version, got %+v", result)
	}
	if called {
		t.Errorf("expected OSV API not to be called for unversioned matches")
	}
}

func TestQueryLibrariesPropagatesContextCancellation(t *testing.T) {
	client := &OSVClient{httpClient: http.DefaultClient, baseURL: "http://127.0.0.1:0", maxRetries: 0}
	matches := []LibraryMatch{{Signature: librarySignature{Name: "openssl", OSVEcosystem: "OSS-Fuzz", OSVPackage: "openssl"}, Version: "1.1.1"}}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	result, err := client.QueryLibraries(ctx, matches)
	if err == nil {
		t.Fatalf("expected context cancellation error")
	}
	if result != nil {
		t.Fatalf("expected nil result on cancellation, got %+v", result)
	}
}

func TestQueryLibrariesParsesCVSSVector(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := osvBatchResponse{
			Results: []osvBatchResult{
				{
					Vulns: []osvVulnResponse{
						{
							ID:      "OSV-2026-0001",
							Summary: "Vector severity",
							Severity: []struct {
								Type  string `json:"type"`
								Score string `json:"score"`
							}{
								{Type: "CVSS_V3", Score: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"},
							},
						},
					},
				},
			},
		}
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(resp); err != nil {
			t.Fatalf("encoding response: %v", err)
		}
	}))
	defer server.Close()

	client := &OSVClient{httpClient: server.Client(), baseURL: server.URL, maxRetries: 0}
	matches := []LibraryMatch{{Signature: librarySignature{Name: "openssl", OSVEcosystem: "OSS-Fuzz", OSVPackage: "openssl"}, Version: "1.1.1"}}
	result, err := client.QueryLibraries(context.Background(), matches)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got := result["openssl"][0].Severity; got != "CRITICAL" {
		t.Fatalf("expected CRITICAL severity from CVSS vector, got %q", got)
	}
}
