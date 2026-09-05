package report

import (
	"bytes"
	"encoding/json"
	"encoding/xml"
	"strings"
	"testing"

	"github.com/marshal-security/marshal/internal/findings"
)

func sampleFindings() []findings.Finding {
	f1 := findings.Finding{
		Engine:   findings.EngineBinarySCA,
		CVE:      "CVE-2021-1234",
		Severity: findings.SeverityHigh,
		Title:    "Vulnerable statically-linked library: openssl",
		Location: findings.Location{
			Type: findings.LocationTypeFile,
			File: &findings.FileLocation{Path: "bin/myapp", StartLine: 0},
		},
	}
	f1.Fingerprint = f1.ComputeFingerprint()

	f2 := findings.Finding{
		Engine:   findings.EngineZAP,
		Severity: findings.SeverityMedium,
		Title:    "Reflected XSS",
		Location: findings.Location{
			Type: findings.LocationTypeURL,
			URL:  &findings.URLLocation{URL: "https://example.com/search", Method: "GET"},
		},
	}
	f2.Fingerprint = f2.ComputeFingerprint()

	return []findings.Finding{f1, f2}
}

func TestNewExporterUnknownFormat(t *testing.T) {
	if _, err := NewExporter(Format("bogus")); err == nil {
		t.Errorf("expected error for unknown format")
	}
}

func TestSARIFExport(t *testing.T) {
	exp, err := NewExporter(FormatSARIF)
	if err != nil {
		t.Fatalf("NewExporter: %v", err)
	}
	var buf bytes.Buffer
	if err := exp.Export(&buf, sampleFindings()); err != nil {
		t.Fatalf("Export: %v", err)
	}

	var log sarifLog
	if err := json.Unmarshal(buf.Bytes(), &log); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}
	if log.Version != "2.1.0" {
		t.Errorf("expected SARIF version 2.1.0, got %s", log.Version)
	}
	if len(log.Runs) != 1 || len(log.Runs[0].Results) != 2 {
		t.Fatalf("expected 1 run with 2 results, got %+v", log.Runs)
	}
	if log.Runs[0].Results[0].Level != "error" {
		t.Errorf("expected high severity to map to 'error' level, got %s", log.Runs[0].Results[0].Level)
	}
	if log.Runs[0].Results[0].Locations[0].PhysicalLocation.ArtifactLocation.URI != "bin/myapp" {
		t.Errorf("unexpected artifact URI: %+v", log.Runs[0].Results[0].Locations)
	}
}

func TestJSONExport(t *testing.T) {
	exp, err := NewExporter(FormatJSON)
	if err != nil {
		t.Fatalf("NewExporter: %v", err)
	}
	var buf bytes.Buffer
	if err := exp.Export(&buf, sampleFindings()); err != nil {
		t.Fatalf("Export: %v", err)
	}

	var out []findings.Finding
	if err := json.Unmarshal(buf.Bytes(), &out); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}
	if len(out) != 2 {
		t.Fatalf("expected 2 findings, got %d", len(out))
	}
	if out[0].CVE != "CVE-2021-1234" {
		t.Errorf("expected CVE-2021-1234, got %s", out[0].CVE)
	}
}

func TestJSONExportEmptyList(t *testing.T) {
	exp, _ := NewExporter(FormatJSON)
	var buf bytes.Buffer
	if err := exp.Export(&buf, nil); err != nil {
		t.Fatalf("Export: %v", err)
	}
	if strings.TrimSpace(buf.String()) != "[]" {
		t.Errorf("expected empty JSON array, got %q", buf.String())
	}
}

func TestJUnitExport(t *testing.T) {
	exp, err := NewExporter(FormatJUnit)
	if err != nil {
		t.Fatalf("NewExporter: %v", err)
	}
	var buf bytes.Buffer
	if err := exp.Export(&buf, sampleFindings()); err != nil {
		t.Fatalf("Export: %v", err)
	}

	var out junitTestSuites
	if err := xml.Unmarshal(buf.Bytes(), &out); err != nil {
		t.Fatalf("output is not valid XML: %v", err)
	}
	if len(out.Suites) != 2 {
		t.Fatalf("expected 2 testsuites (one per engine), got %d", len(out.Suites))
	}
	if out.Suites[0].Name != string(findings.EngineBinarySCA) {
		t.Errorf("expected first suite to be %s, got %s", findings.EngineBinarySCA, out.Suites[0].Name)
	}
	if out.Suites[0].Cases[0].Failure == nil {
		t.Fatalf("expected a failure element on the testcase")
	}
	if out.Suites[0].Cases[0].Failure.Message != "Vulnerable statically-linked library: openssl" {
		t.Errorf("unexpected failure message: %s", out.Suites[0].Cases[0].Failure.Message)
	}
}
