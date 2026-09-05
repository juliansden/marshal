// Package report handles formatting and exporting findings into standard formats (SARIF, JSON, JUnit).
package report

import (
	"io"

	"github.com/marshal-security/marshal/internal/findings"
)

// Format specifies the desired output report format.
type Format string

const (
	FormatSARIF Format = "sarif"
	FormatJSON  Format = "json"
	FormatJUnit Format = "junit"
)

// Exporter writes normalized findings to a target writer in the specified format.
type Exporter interface {
	Export(w io.Writer, list []findings.Finding) error
}

// NewExporter returns an Exporter implementation for the given format.
func NewExporter(fmt Format) (Exporter, error) {
	// TODO: Phase 1 (SARIF/JSON/JUnit exporters)
	return nil, nil
}
