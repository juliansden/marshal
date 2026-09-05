// Package report handles formatting and exporting findings into standard formats (SARIF, JSON, JUnit).
package report

import (
	"fmt"
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
func NewExporter(format Format) (Exporter, error) {
	switch format {
	case FormatSARIF:
		return sarifExporter{}, nil
	case FormatJSON:
		return jsonExporter{}, nil
	case FormatJUnit:
		return junitExporter{}, nil
	default:
		return nil, fmt.Errorf("report: unsupported format %q", format)
	}
}
