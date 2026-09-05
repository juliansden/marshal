// Package semgrep provides an adapter for Semgrep SAST scan results.
// It parses Semgrep's native SARIF or JSON output and maps it into Marshal's shared Finding schema.
package semgrep

import (
	"context"

	"github.com/marshal-security/marshal/internal/findings"
)

// Adapter handles Semgrep execution and output parsing.
type Adapter struct{}

// NewAdapter creates a new Semgrep adapter instance.
func NewAdapter() *Adapter {
	return &Adapter{}
}

// ParseReport converts raw Semgrep SARIF/JSON output into unified Findings.
// TODO: Phase 2 implementation.
func (a *Adapter) ParseReport(ctx context.Context, reportData []byte) ([]findings.Finding, error) {
	return nil, nil
}
