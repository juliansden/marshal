// Package zap provides an adapter for OWASP ZAP DAST scan results.
// It converts URL/endpoint-based dynamic scan findings into Marshal's shared Finding schema.
package zap

import (
	"context"

	"github.com/marshal-security/marshal/internal/findings"
)

// Adapter handles OWASP ZAP report ingestion and schema translation.
type Adapter struct{}

// NewAdapter creates a new ZAP adapter instance.
func NewAdapter() *Adapter {
	return &Adapter{}
}

// ParseReport converts raw OWASP ZAP JSON/XML output into unified Findings.
// TODO: Phase 3 implementation (mapping URL, method, and parameters to LocationTypeURL).
func (a *Adapter) ParseReport(ctx context.Context, reportData []byte) ([]findings.Finding, error) {
	return nil, nil
}
