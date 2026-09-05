package findings

import (
	"fmt"
	"strings"
	"time"
)

// EngineType defines the source detection engine that generated the finding.
type EngineType string

const (
	EngineBinarySCA EngineType = "binary_sca"
	EngineSemgrep   EngineType = "semgrep"
	EngineZAP       EngineType = "zap"
	EngineCustom    EngineType = "custom"
)

// Severity represents the impact level of a finding.
type Severity string

const (
	SeverityCritical Severity = "CRITICAL"
	SeverityHigh     Severity = "HIGH"
	SeverityMedium   Severity = "MEDIUM"
	SeverityLow      Severity = "LOW"
	SeverityInfo     Severity = "INFO"
	SeverityUnknown  Severity = "UNKNOWN"
)

// LocationType indicates whether a finding maps to source code/binary file or a network URL/endpoint.
type LocationType string

const (
	LocationTypeFile LocationType = "file"
	LocationTypeURL  LocationType = "url"
)

// FileLocation represents location in a file or binary artifact.
type FileLocation struct {
	Path      string `json:"path"`
	StartLine int    `json:"start_line,omitempty"`
	EndLine   int    `json:"end_line,omitempty"`
	StartCol  int    `json:"start_col,omitempty"`
	EndCol    int    `json:"end_col,omitempty"`
	Snippet   string `json:"snippet,omitempty"`
}

// URLLocation represents location in a web endpoint (used by DAST engines like ZAP).
type URLLocation struct {
	URL        string `json:"url"`
	Method     string `json:"method,omitempty"`
	Parameter  string `json:"parameter,omitempty"`
	Header     string `json:"header,omitempty"`
	StatusCode int    `json:"status_code,omitempty"`
	Evidence   string `json:"evidence,omitempty"`
}

// Location is a flexible container that supports both file-based and URL-based finding targets.
type Location struct {
	Type LocationType  `json:"type"`
	File *FileLocation `json:"file,omitempty"`
	URL  *URLLocation  `json:"url,omitempty"`
}

func (l Location) String() string {
	switch l.Type {
	case LocationTypeFile:
		if l.File == nil {
			return "unknown file"
		}
		if l.File.StartLine > 0 {
			return fmt.Sprintf("%s:%d", l.File.Path, l.File.StartLine)
		}
		return l.File.Path
	case LocationTypeURL:
		if l.URL == nil {
			return "unknown url"
		}
		if l.URL.Method != "" {
			return fmt.Sprintf("%s %s", l.URL.Method, l.URL.URL)
		}
		return l.URL.URL
	default:
		return "unknown location"
	}
}

// TriageVerdict defines the output of the LLM-based reachability/exploitability evaluation (Phase 5).
type TriageVerdict string

const (
	TriageVerdictUnknown       TriageVerdict = "UNKNOWN"
	TriageVerdictReachable     TriageVerdict = "REACHABLE"
	TriageVerdictUnreachable   TriageVerdict = "UNREACHABLE"
	TriageVerdictFalsePositive TriageVerdict = "FALSE_POSITIVE"
	TriageVerdictNeedsReview   TriageVerdict = "NEEDS_REVIEW"
)

// TriageResult holds the assessment produced by the LLM triage layer.
type TriageResult struct {
	Verdict     TriageVerdict `json:"verdict"`
	Confidence  float64       `json:"confidence"` // Normalized between 0.0 and 1.0
	Reasoning   string        `json:"reasoning,omitempty"`
	EvaluatedAt time.Time     `json:"evaluated_at,omitempty"`
	ModelUsed   string        `json:"model_used,omitempty"`
}

// Finding is the core unified vulnerability representation across all engines in Marshal.
type Finding struct {
	ID          string         `json:"id"`
	Engine      EngineType     `json:"engine"`
	RuleID      string         `json:"rule_id,omitempty"`
	CVE         string         `json:"cve,omitempty"`
	CWE         []string       `json:"cwe,omitempty"`
	Severity    Severity       `json:"severity"`
	Title       string         `json:"title"`
	Description string         `json:"description,omitempty"`
	Remediation string         `json:"remediation,omitempty"`
	Location    Location       `json:"location"`
	Triage      *TriageResult  `json:"triage,omitempty"`
	Fingerprint string         `json:"fingerprint,omitempty"` // Unique hash for deduplication/correlation
	Metadata    map[string]any `json:"metadata,omitempty"`
}

// MarshalJSON provides custom formatting if required.
func (f Finding) String() string {
	cveStr := ""
	if f.CVE != "" {
		cveStr = fmt.Sprintf(" [%s]", f.CVE)
	}
	return fmt.Sprintf("[%s][%s]%s %s at %s", f.Engine, f.Severity, cveStr, f.Title, f.Location.String())
}

// NormalizeSeverity returns a standardized severity string.
func NormalizeSeverity(s string) Severity {
	switch strings.ToUpper(strings.TrimSpace(s)) {
	case "CRITICAL":
		return SeverityCritical
	case "HIGH", "ERROR":
		return SeverityHigh
	case "MEDIUM", "WARNING", "WARN":
		return SeverityMedium
	case "LOW", "NOTE":
		return SeverityLow
	case "INFO", "INFORMATIONAL":
		return SeverityInfo
	default:
		return SeverityUnknown
	}
}
