// Package triage provides LLM-based reachability and exploitability triage for correlated findings.
// Triage is strictly opt-in and operates gracefully as a no-op when unconfigured or disabled.
package triage

import (
	"context"

	"github.com/marshal-security/marshal/internal/findings"
)

// LLMClient defines the provider-agnostic interface for LLM operations.
type LLMClient interface {
	// EvaluateReachability analyzes a finding alongside source context to judge exploitability.
	EvaluateReachability(ctx context.Context, finding findings.Finding, sourceContext string) (*findings.TriageResult, error)
}

// Config controls the behavior of the triage engine.
type Config struct {
	Enabled  bool
	Provider string
	APIKey   string
	Model    string
}

// Engine coordinates the triage process using a configured LLMClient.
type Engine struct {
	config Config
	client LLMClient
}

// NewEngine initializes the triage engine. If disabled or client is nil, operations run as no-ops.
func NewEngine(cfg Config, client LLMClient) *Engine {
	return &Engine{
		config: cfg,
		client: client,
	}
}

// EvaluateAll processes findings through the triage engine. If triage is disabled, findings are returned unmodified.
// TODO: Phase 5 implementation.
func (e *Engine) EvaluateAll(ctx context.Context, input []findings.Finding) ([]findings.Finding, error) {
	if !e.config.Enabled || e.client == nil {
		return input, nil
	}
	return input, nil
}
