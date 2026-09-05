package findings

import (
	"encoding/json"
	"testing"
)

func TestLocationString(t *testing.T) {
	fileLoc := Location{
		Type: LocationTypeFile,
		File: &FileLocation{
			Path:      "cmd/marshal/main.go",
			StartLine: 42,
		},
	}
	if got := fileLoc.String(); got != "cmd/marshal/main.go:42" {
		t.Errorf("expected cmd/marshal/main.go:42, got %s", got)
	}

	urlLoc := Location{
		Type: LocationTypeURL,
		URL: &URLLocation{
			URL:    "https://example.com/api/v1/user",
			Method: "POST",
		},
	}
	if got := urlLoc.String(); got != "POST https://example.com/api/v1/user" {
		t.Errorf("expected 'POST https://example.com/api/v1/user', got %s", got)
	}
}

func TestNormalizeSeverity(t *testing.T) {
	tests := []struct {
		input    string
		expected Severity
	}{
		{"critical", SeverityCritical},
		{"ERROR", SeverityHigh},
		{"warning", SeverityMedium},
		{"note", SeverityLow},
		{"info", SeverityInfo},
		{"unknown_val", SeverityUnknown},
	}

	for _, tt := range tests {
		if got := NormalizeSeverity(tt.input); got != tt.expected {
			t.Errorf("NormalizeSeverity(%q) = %v; want %v", tt.input, got, tt.expected)
		}
	}
}

func TestFingerprintDeterministicAndUnique(t *testing.T) {
	base := Finding{
		Engine: EngineSemgrep,
		RuleID: "go.lang.security.audit.sql-injection",
		Title:  "SQL Injection",
		Location: Location{
			Type: LocationTypeFile,
			File: &FileLocation{Path: "internal/db/query.go", StartLine: 10},
		},
	}

	other := base
	other.Location.File = &FileLocation{Path: base.Location.File.Path, StartLine: base.Location.File.StartLine}

	if base.ComputeFingerprint() != other.ComputeFingerprint() {
		t.Errorf("expected identical findings to produce the same fingerprint")
	}

	changedLine := base
	changedLine.Location.File = &FileLocation{Path: base.Location.File.Path, StartLine: 11}
	if base.ComputeFingerprint() == changedLine.ComputeFingerprint() {
		t.Errorf("expected differing location to change the fingerprint")
	}

	changedCol := base
	changedCol.Location.File = &FileLocation{Path: base.Location.File.Path, StartLine: 10, StartCol: 2}
	if base.ComputeFingerprint() == changedCol.ComputeFingerprint() {
		t.Errorf("expected differing file columns to change the fingerprint")
	}

	changedTitleCase := base
	changedTitleCase.Title = "  sql injection  "
	if base.ComputeFingerprint() != changedTitleCase.ComputeFingerprint() {
		t.Errorf("expected title normalization to ignore case/whitespace differences")
	}

	urlBase := Finding{
		Engine: EngineZAP,
		RuleID: "xss",
		Title:  "Reflected XSS",
		Location: Location{
			Type: LocationTypeURL,
			URL:  &URLLocation{URL: "https://example.com/search", Method: "GET", Parameter: "q"},
		},
	}
	urlOtherParam := urlBase
	urlOtherParam.Location.URL = &URLLocation{URL: "https://example.com/search", Method: "GET", Parameter: "sort"}
	if urlBase.ComputeFingerprint() == urlOtherParam.ComputeFingerprint() {
		t.Errorf("expected differing URL parameters to change the fingerprint")
	}
}

func TestLocationJSONRoundTrip(t *testing.T) {
	fileLoc := Location{
		Type: LocationTypeFile,
		File: &FileLocation{Path: "cmd/marshal/main.go", StartLine: 42},
	}
	data, err := json.Marshal(fileLoc)
	if err != nil {
		t.Fatalf("unexpected marshal error: %v", err)
	}
	var roundTripped Location
	if err := json.Unmarshal(data, &roundTripped); err != nil {
		t.Fatalf("unexpected unmarshal error: %v", err)
	}
	if roundTripped.String() != fileLoc.String() {
		t.Errorf("round trip mismatch: got %s, want %s", roundTripped.String(), fileLoc.String())
	}
}

func TestLocationJSONValidation(t *testing.T) {
	// Type says "file" but no File payload is set.
	invalid := Location{Type: LocationTypeFile}
	if _, err := json.Marshal(invalid); err == nil {
		t.Errorf("expected marshal error for file location missing File payload")
	}

	// Type/payload mismatch: URL type with a File payload.
	mismatched := Location{Type: LocationTypeURL, File: &FileLocation{Path: "a.go"}}
	if _, err := json.Marshal(mismatched); err == nil {
		t.Errorf("expected marshal error for url location with file payload set")
	}

	// Malformed JSON: type "url" but only "file" populated.
	badJSON := []byte(`{"type":"url","file":{"path":"a.go"}}`)
	var loc Location
	if err := json.Unmarshal(badJSON, &loc); err == nil {
		t.Errorf("expected unmarshal error for mismatched type/payload JSON")
	}
}
