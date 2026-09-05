package findings

import (
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
