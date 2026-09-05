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
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	client := &OSVClient{httpClient: server.Client(), baseURL: server.URL, maxRetries: 1}
	matches := []LibraryMatch{
		{Signature: librarySignature{Name: "openssl", OSVEcosystem: "Debian", OSVPackage: "openssl"}, Version: "1.1.1"},
	}

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
}

func TestQueryLibrariesDegradesGracefullyOnNetworkError(t *testing.T) {
	client := &OSVClient{httpClient: http.DefaultClient, baseURL: "http://127.0.0.1:0", maxRetries: 0}
	matches := []LibraryMatch{
		{Signature: librarySignature{Name: "openssl", OSVEcosystem: "Debian", OSVPackage: "openssl"}},
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
		json.NewEncoder(w).Encode(osvBatchResponse{})
	}))
	defer server.Close()

	client := &OSVClient{httpClient: server.Client(), baseURL: server.URL, maxRetries: 1}
	matches := []LibraryMatch{
		{Signature: librarySignature{Name: "zlib", OSVEcosystem: "Debian", OSVPackage: "zlib"}, Version: ""},
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
