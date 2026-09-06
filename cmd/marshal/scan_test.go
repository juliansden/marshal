package main

import (
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

func TestScanDirectoryRequiresSemgrepReport(t *testing.T) {
	dir := t.TempDir()

	prevFormatFlag := formatFlag
	prevOutputFlag := outputFlag
	prevSemgrepFlag := semgrepFlag
	prevEnableTriage := enableTriage
	t.Cleanup(func() {
		formatFlag = prevFormatFlag
		outputFlag = prevOutputFlag
		semgrepFlag = prevSemgrepFlag
		enableTriage = prevEnableTriage
	})

	formatFlag = "json"
	outputFlag = ""
	semgrepFlag = ""
	enableTriage = false

	err := scanCmd.RunE(&cobra.Command{}, []string{dir})
	if err == nil || !strings.Contains(err.Error(), "--semgrep-report") {
		t.Fatalf("expected missing semgrep report error, got %v", err)
	}
}
