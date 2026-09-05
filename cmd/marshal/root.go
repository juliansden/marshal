package main

import (
	"github.com/spf13/cobra"
)

var (
	version = "dev"
)

var rootCmd = &cobra.Command{
	Use:   "marshal",
	Short: "Marshal is a unified vulnerability correlation, triage, and reporting engine",
	Long: `Marshal unifies binary composition analysis (BCA), SAST (Semgrep), and DAST (ZAP)
under a single correlation, LLM-driven triage, and reporting layer.`,
	Version: version,
}

func init() {
	// Global persistent flags can be added here
}
