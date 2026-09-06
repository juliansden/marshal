package semgrep

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/marshal-security/marshal/internal/findings"
)

type sarifReport struct {
	Runs []struct {
		Tool struct {
			Driver struct {
				Rules []sarifRule `json:"rules"`
			} `json:"driver"`
		} `json:"tool"`
		Results []sarifResult `json:"results"`
	} `json:"runs"`
}

type sarifRule struct {
	ID         string         `json:"id"`
	Properties map[string]any `json:"properties"`
}

type sarifResult struct {
	RuleID  string `json:"ruleId"`
	Level   string `json:"level"`
	Message struct {
		Text string `json:"text"`
	} `json:"message"`
	Properties map[string]any `json:"properties"`
	Locations  []struct {
		PhysicalLocation struct {
			ArtifactLocation struct {
				URI string `json:"uri"`
			} `json:"artifactLocation"`
			Region struct {
				StartLine   int `json:"startLine"`
				EndLine     int `json:"endLine"`
				StartColumn int `json:"startColumn"`
				EndColumn   int `json:"endColumn"`
			} `json:"region"`
		} `json:"physicalLocation"`
	} `json:"locations"`
}

type nativeReport struct {
	Results []nativeResult `json:"results"`
}

type nativeResult struct {
	CheckID string `json:"check_id"`
	Path    string `json:"path"`
	Start   struct {
		Line   int `json:"line"`
		Col    int `json:"col"`
		Offset int `json:"offset"`
	} `json:"start"`
	End struct {
		Line   int `json:"line"`
		Col    int `json:"col"`
		Offset int `json:"offset"`
	} `json:"end"`
	Extra struct {
		Message  string         `json:"message"`
		Severity string         `json:"severity"`
		Metadata map[string]any `json:"metadata"`
		Lines    string         `json:"lines"`
	} `json:"extra"`
}

func ParseSARIF(data []byte) ([]findings.Finding, error) {
	var report sarifReport
	if err := json.Unmarshal(data, &report); err != nil {
		return nil, fmt.Errorf("parse Semgrep SARIF: %w", err)
	}
	if len(report.Runs) == 0 {
		return nil, fmt.Errorf("parse Semgrep SARIF: missing runs")
	}
	if len(report.Runs) > 1 {
		return nil, fmt.Errorf("parse Semgrep SARIF: multiple runs are not supported")
	}

	run := report.Runs[0]
	ruleProperties := make(map[string]map[string]any, len(run.Tool.Driver.Rules))
	for _, rule := range run.Tool.Driver.Rules {
		ruleProperties[rule.ID] = rule.Properties
	}

	results := make([]findings.Finding, 0, len(run.Results))
	for _, result := range run.Results {
		if len(result.Locations) == 0 {
			return nil, fmt.Errorf("parse Semgrep SARIF: result %q has no location", result.RuleID)
		}
		location := result.Locations[0].PhysicalLocation
		if location.ArtifactLocation.URI == "" {
			return nil, fmt.Errorf("parse Semgrep SARIF: result %q has no file path", result.RuleID)
		}
		properties := mergeProperties(ruleProperties[result.RuleID], result.Properties)
		finding := newFinding(
			result.RuleID,
			result.Message.Text,
			result.Level,
			location.ArtifactLocation.URI,
			findings.FileLocation{
				Path:      location.ArtifactLocation.URI,
				StartLine: location.Region.StartLine,
				EndLine:   location.Region.EndLine,
				StartCol:  location.Region.StartColumn,
				EndCol:    location.Region.EndColumn,
			},
			properties,
		)
		results = append(results, finding)
	}
	return results, nil
}

func ParseJSON(data []byte) ([]findings.Finding, error) {
	var report nativeReport
	if err := json.Unmarshal(data, &report); err != nil {
		return nil, fmt.Errorf("parse Semgrep JSON: %w", err)
	}

	results := make([]findings.Finding, 0, len(report.Results))
	for _, result := range report.Results {
		if result.CheckID == "" || result.Path == "" {
			return nil, fmt.Errorf("parse Semgrep JSON: result is missing check_id or path")
		}
		finding := newFinding(
			result.CheckID,
			result.Extra.Message,
			result.Extra.Severity,
			result.Path,
			findings.FileLocation{
				Path:      result.Path,
				StartLine: result.Start.Line,
				EndLine:   result.End.Line,
				StartCol:  result.Start.Col,
				EndCol:    result.End.Col,
				Snippet:   result.Extra.Lines,
			},
			result.Extra.Metadata,
		)
		results = append(results, finding)
	}
	return results, nil
}

func newFinding(ruleID, title, severity, path string, fileLocation findings.FileLocation, properties map[string]any) findings.Finding {
	severityValue := findings.NormalizeSeverity(severity)
	if strings.EqualFold(strings.TrimSpace(severity), "INFO") {
		severityValue = findings.SeverityLow
	}
	finding := findings.Finding{
		Engine:   findings.EngineSemgrep,
		ID:       ruleID,
		RuleID:   ruleID,
		Severity: severityValue,
		Title:    title,
		Location: findings.Location{Type: findings.LocationTypeFile, File: &fileLocation},
		Metadata: properties,
	}
	finding.CWE = extractCWE(properties["cwe"])
	finding.Fingerprint = finding.ComputeFingerprint()
	return finding
}

func mergeProperties(base, override map[string]any) map[string]any {
	if len(base) == 0 && len(override) == 0 {
		return nil
	}
	merged := make(map[string]any, len(base)+len(override))
	for key, value := range base {
		merged[key] = value
	}
	for key, value := range override {
		merged[key] = value
	}
	return merged
}

func extractCWE(value any) []string {
	switch value := value.(type) {
	case string:
		if value == "" {
			return nil
		}
		return []string{value}
	case []any:
		cwe := make([]string, 0, len(value))
		for _, item := range value {
			if text, ok := item.(string); ok && text != "" {
				cwe = append(cwe, text)
			}
		}
		return cwe
	case []string:
		cwe := value[:0]
		for _, text := range value {
			if text != "" {
				cwe = append(cwe, text)
			}
		}
		if len(cwe) == 0 {
			return nil
		}
		return cwe
	default:
		return nil
	}
}

func detectFormat(data []byte) (string, error) {
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == 0 {
		return "", fmt.Errorf("Semgrep report is empty")
	}
	var header struct {
		Runs    json.RawMessage `json:"runs"`
		Results json.RawMessage `json:"results"`
	}
	if err := json.Unmarshal(trimmed, &header); err != nil {
		return "", fmt.Errorf("decode Semgrep report: %w", err)
	}
	if len(header.Runs) > 0 && string(header.Runs) != "null" {
		return "sarif", nil
	}
	if len(header.Results) > 0 && string(header.Results) != "null" {
		return "json", nil
	}
	return "", fmt.Errorf("unsupported Semgrep report format")
}
