package binaryscan

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"
)

func noWaitLimiter() *rateLimiter {
	return newRateLimiter(1000, 0)
}

func TestQueryLibrariesSuccess(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		wantCPE := "cpe:2.3:a:openssl:openssl:1.1.1f:*:*:*:*:*:*:*"
		if got := r.URL.Query().Get("cpeName"); got != wantCPE {
			t.Fatalf("unexpected cpeName: got %q want %q", got, wantCPE)
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

	client := &NVDClient{httpClient: server.Client(), baseURL: server.URL, maxRetries: 1, limiter: noWaitLimiter()}
	matches := []LibraryMatch{{Signature: librarySignature{Name: "openssl", CPEVendor: "openssl", CPEProduct: "openssl"}, Version: "1.1.1f"}}

	result, err := client.QueryLibraries(context.Background(), matches)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	vulns := result["openssl"]
	if len(vulns) != 1 {
		t.Fatalf("expected 1 vuln, got %d", len(vulns))
	}
	if vulns[0].ID != "CVE-2021-1234" || vulns[0].Severity != "HIGH" {
		t.Errorf("unexpected vuln contents: %+v", vulns[0])
	}
}

func TestQueryLibrariesDegradesGracefullyOnNetworkError(t *testing.T) {
	client := &NVDClient{httpClient: http.DefaultClient, baseURL: "http://127.0.0.1:0", maxRetries: 0, limiter: noWaitLimiter()}
	matches := []LibraryMatch{
		{Signature: librarySignature{Name: "openssl", CPEVendor: "openssl", CPEProduct: "openssl"}, Version: "1.1.1f"},
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
	client := NewNVDClient()
	result, err := client.QueryLibraries(context.Background(), nil)
	if err != nil || result != nil {
		t.Errorf("expected nil, nil for empty input, got %+v, %v", result, err)
	}
}

func TestQueryLibrariesSkipsUnresolvedMatches(t *testing.T) {
	called := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(nvdResponse{}); err != nil {
			t.Fatalf("encoding response: %v", err)
		}
	}))
	defer server.Close()

	client := &NVDClient{httpClient: server.Client(), baseURL: server.URL, maxRetries: 1, limiter: noWaitLimiter()}

	cases := []LibraryMatch{
		{Signature: librarySignature{Name: "zlib", CPEVendor: "zlib", CPEProduct: "zlib"}, Version: ""}, // no version
		{Signature: librarySignature{Name: "unknown-lib"}, Version: "1.0.0"},                            // no CPE mapping
	}
	for _, m := range cases {
		result, err := client.QueryLibraries(context.Background(), []LibraryMatch{m})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result != nil {
			t.Errorf("expected nil result for unresolved match %+v, got %+v", m, result)
		}
	}
	if called {
		t.Errorf("expected NVD API not to be called for unresolved matches")
	}
}

func TestQueryLibrariesPropagatesContextCancellation(t *testing.T) {
	client := &NVDClient{httpClient: http.DefaultClient, baseURL: "http://127.0.0.1:0", maxRetries: 0, limiter: noWaitLimiter()}
	matches := []LibraryMatch{{Signature: librarySignature{Name: "openssl", CPEVendor: "openssl", CPEProduct: "openssl"}, Version: "1.1.1f"}}
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

func TestQueryLibrariesContextCanceledWhileRateLimited(t *testing.T) {
	called := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(nvdResponse{}); err != nil {
			t.Fatalf("encoding response: %v", err)
		}
	}))
	defer server.Close()

	ctx, cancel := context.WithCancel(context.Background())
	client := &NVDClient{
		httpClient: server.Client(),
		baseURL:    server.URL,
		maxRetries: 0,
		limiter: &rateLimiter{
			maxRequests: 1,
			window:      time.Minute,
			timestamps:  []time.Time{time.Now()},
			now:         time.Now,
			sleep: func(_ context.Context, _ time.Duration) {
				cancel()
			},
		},
	}

	matches := []LibraryMatch{{Signature: librarySignature{Name: "openssl", CPEVendor: "openssl", CPEProduct: "openssl"}, Version: "1.1.1f"}}
	result, err := client.QueryLibraries(ctx, matches)
	if err == nil {
		t.Fatalf("expected context cancellation error")
	}
	if result != nil {
		t.Fatalf("expected nil result on cancellation, got %+v", result)
	}
	if called {
		t.Fatalf("expected query to stop before HTTP request when context is canceled")
	}
}

func TestQueryLibrariesNoLimiterStillQueries(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(nvdResponse{}); err != nil {
			t.Fatalf("encoding response: %v", err)
		}
	}))
	defer server.Close()

	client := &NVDClient{httpClient: server.Client(), baseURL: server.URL, maxRetries: 0, limiter: nil}
	matches := []LibraryMatch{{Signature: librarySignature{Name: "openssl", CPEVendor: "openssl", CPEProduct: "openssl"}, Version: "1.1.1f"}}

	result, err := client.QueryLibraries(context.Background(), matches)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	vulns, ok := result["openssl"]
	if !ok {
		t.Fatalf("expected result key for queried library")
	}
	if len(vulns) != 0 {
		t.Fatalf("expected no vulns for empty response, got %d", len(vulns))
	}
}

func TestCPENameEscaping(t *testing.T) {
	var gotRaw string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotRaw = r.URL.RawQuery
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(nvdResponse{}); err != nil {
			t.Fatalf("encoding response: %v", err)
		}
	}))
	defer server.Close()

	client := &NVDClient{httpClient: server.Client(), baseURL: server.URL, maxRetries: 0, limiter: noWaitLimiter()}
	matches := []LibraryMatch{{Signature: librarySignature{Name: "libcurl", CPEVendor: "haxx", CPEProduct: "curl"}, Version: "7.68.0"}}
	if _, err := client.QueryLibraries(context.Background(), matches); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	values, err := url.ParseQuery(gotRaw)
	if err != nil {
		t.Fatalf("parsing query: %v", err)
	}
	if got := values.Get("cpeName"); got != "cpe:2.3:a:haxx:curl:7.68.0:*:*:*:*:*:*:*" {
		t.Errorf("unexpected cpeName: %q", got)
	}
}

func TestRateLimiterWaitsWhenWindowExhausted(t *testing.T) {
	var slept time.Duration
	limiter := &rateLimiter{
		maxRequests: 2,
		window:      time.Second,
		now:         time.Now,
		sleep: func(_ context.Context, d time.Duration) {
			slept = d
		},
	}

	ctx := context.Background()
	limiter.wait(ctx)
	limiter.wait(ctx)
	limiter.wait(ctx) // third call within the window should trigger a wait

	if slept <= 0 {
		t.Errorf("expected the limiter to sleep once the window's request budget was exhausted, got %v", slept)
	}
}

func TestRateLimiterDoesNotWaitUnderBudget(t *testing.T) {
	called := false
	limiter := &rateLimiter{
		maxRequests: 5,
		window:      time.Second,
		now:         time.Now,
		sleep: func(_ context.Context, d time.Duration) {
			called = true
		},
	}

	ctx := context.Background()
	for i := 0; i < 5; i++ {
		limiter.wait(ctx)
	}
	if called {
		t.Errorf("expected no sleep while under the request budget")
	}
}
