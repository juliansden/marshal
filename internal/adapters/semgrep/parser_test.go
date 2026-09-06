package semgrep

import (
	"context"
	"testing"

	"github.com/marshal-security/marshal/internal/findings"
)

func TestParseSARIF(t *testing.T) {
	report := []byte(`{
  "version": "2.1.0",
  "runs": [{
    "tool": {"driver": {"rules": [{"id": "go.sql-injection", "properties": {"cwe": ["CWE-89"]}}]}},
    "results": [{
      "ruleId": "go.sql-injection",
      "level": "warning",
      "message": {"text": "Unsanitized SQL query"},
      "locations": [{"physicalLocation": {"artifactLocation": {"uri": "internal/db/query.go"}, "region": {"startLine": 12, "endLine": 12, "startColumn": 4, "endColumn": 20}}}]
    }]
  }]
}`)

	results, err := ParseSARIF(report)
	if err != nil {
		t.Fatalf("ParseSARIF: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("expected one finding, got %d", len(results))
	}
	finding := results[0]
	if finding.Engine != findings.EngineSemgrep || finding.RuleID != "go.sql-injection" {
		t.Fatalf("unexpected finding identity: %+v", finding)
	}
	if finding.Severity != findings.SeverityMedium || len(finding.CWE) != 1 || finding.CWE[0] != "CWE-89" {
		t.Fatalf("unexpected finding metadata: %+v", finding)
	}
	if finding.Location.File.Path != "internal/db/query.go" || finding.Location.File.StartCol != 4 {
		t.Fatalf("unexpected location: %+v", finding.Location)
	}
	if finding.Fingerprint == "" {
		t.Fatal("expected fingerprint")
	}
}

func TestAdapterParseNativeJSON(t *testing.T) {
	report := []byte(`{
  "results": [{
    "check_id": "python.xss",
    "path": "app/views.py",
    "start": {"line": 8, "col": 2},
    "end": {"line": 8, "col": 18},
    "extra": {"message": "User input reaches HTML", "severity": "INFO", "metadata": {"cwe": "CWE-79"}, "lines": "return render(user_input)"}
  }]
}`)

	results, err := NewAdapter().ParseReport(context.Background(), report)
	if err != nil {
		t.Fatalf("ParseReport: %v", err)
	}
	if len(results) != 1 || results[0].Severity != findings.SeverityLow {
		t.Fatalf("expected one low-severity finding, got %+v", results)
	}
	if len(results[0].CWE) != 1 || results[0].CWE[0] != "CWE-79" {
		t.Fatalf("unexpected CWE values: %+v", results[0].CWE)
	}
	if results[0].Location.File.Snippet != "return render(user_input)" {
		t.Fatalf("unexpected snippet: %q", results[0].Location.File.Snippet)
	}
}

func TestParseReportRejectsUnsupportedInput(t *testing.T) {
	if _, err := NewAdapter().ParseReport(context.Background(), []byte(`{"unexpected": true}`)); err == nil {
		t.Fatal("expected unsupported format error")
	}
}
