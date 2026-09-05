package report

import (
	"encoding/json"
	"io"

	"github.com/marshal-security/marshal/internal/findings"
)

const sarifSchemaURI = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"
const sarifVersion = "2.1.0"
const sarifToolName = "marshal"

type sarifLog struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool    sarifTool     `json:"tool"`
	Results []sarifResult `json:"results"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name  string      `json:"name"`
	Rules []sarifRule `json:"rules,omitempty"`
}

type sarifRule struct {
	ID   string `json:"id"`
	Name string `json:"name,omitempty"`
}

type sarifResult struct {
	RuleID       string            `json:"ruleId,omitempty"`
	Level        string            `json:"level"`
	Message      sarifMessage      `json:"message"`
	Locations    []sarifResultLoc  `json:"locations,omitempty"`
	Fingerprints map[string]string `json:"partialFingerprints,omitempty"`
}

type sarifMessage struct {
	Text string `json:"text"`
}

type sarifResultLoc struct {
	PhysicalLocation sarifPhysicalLocation `json:"physicalLocation"`
}

type sarifPhysicalLocation struct {
	ArtifactLocation sarifArtifactLocation `json:"artifactLocation"`
	Region           *sarifRegion          `json:"region,omitempty"`
}

type sarifArtifactLocation struct {
	URI string `json:"uri"`
}

type sarifRegion struct {
	StartLine int `json:"startLine,omitempty"`
	EndLine   int `json:"endLine,omitempty"`
	StartCol  int `json:"startColumn,omitempty"`
	EndCol    int `json:"endColumn,omitempty"`
}

// sarifExporter renders findings as a SARIF v2.1.0 log.
type sarifExporter struct{}

func (sarifExporter) Export(w io.Writer, list []findings.Finding) error {
	log := sarifLog{
		Schema:  sarifSchemaURI,
		Version: sarifVersion,
		Runs: []sarifRun{
			{
				Tool:    sarifTool{Driver: sarifDriver{Name: sarifToolName}},
				Results: make([]sarifResult, len(list)),
			},
		},
	}

	for i, f := range list {
		result := sarifResult{
			RuleID: firstNonEmpty(f.RuleID, f.CVE),
			Level:  severityToSARIFLevel(f.Severity),
			Message: sarifMessage{
				Text: f.String(),
			},
		}
		if f.Fingerprint != "" {
			result.Fingerprints = map[string]string{"marshal/v1": f.Fingerprint}
		}
		if loc, ok := findingToSARIFLocation(f); ok {
			result.Locations = []sarifResultLoc{loc}
		}
		log.Runs[0].Results[i] = result
	}

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(log)
}

func findingToSARIFLocation(f findings.Finding) (sarifResultLoc, bool) {
	switch f.Location.Type {
	case findings.LocationTypeFile:
		if f.Location.File == nil {
			return sarifResultLoc{}, false
		}
		return sarifResultLoc{
			PhysicalLocation: sarifPhysicalLocation{
				ArtifactLocation: sarifArtifactLocation{URI: f.Location.File.Path},
				Region: &sarifRegion{
					StartLine: f.Location.File.StartLine,
					EndLine:   f.Location.File.EndLine,
					StartCol:  f.Location.File.StartCol,
					EndCol:    f.Location.File.EndCol,
				},
			},
		}, true
	case findings.LocationTypeURL:
		if f.Location.URL == nil {
			return sarifResultLoc{}, false
		}
		return sarifResultLoc{
			PhysicalLocation: sarifPhysicalLocation{
				ArtifactLocation: sarifArtifactLocation{URI: f.Location.URL.URL},
			},
		}, true
	default:
		return sarifResultLoc{}, false
	}
}

func severityToSARIFLevel(s findings.Severity) string {
	switch s {
	case findings.SeverityCritical, findings.SeverityHigh:
		return "error"
	case findings.SeverityMedium:
		return "warning"
	case findings.SeverityLow, findings.SeverityInfo:
		return "note"
	default:
		return "none"
	}
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}
