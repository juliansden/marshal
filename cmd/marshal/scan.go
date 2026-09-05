package main

import (
	"fmt"

	"github.com/spf13/cobra"
)

var (
	formatFlag   string
	outputFlag   string
	enableTriage bool
)

var scanCmd = &cobra.Command{
	Use:   "scan [target]",
	Short: "Run security analysis on target binaries, codebases, or reports",
	Long: `Scan inspects compiled binaries, source code, or adapter inputs, correlates findings,
and optionally performs LLM-based reachability triage.`,
	Args: cobra.MaximumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		target := "."
		if len(args) > 0 {
			target = args[0]
		}

		cmd.Printf("Marshal security scan initiated for target: %s\n", target)
		cmd.Printf("Output format: %s\n", formatFlag)
		if enableTriage {
			cmd.Println("LLM Reachability Triage: Enabled (Opt-in)")
		} else {
			cmd.Println("LLM Reachability Triage: Disabled (Default)")
		}

		// Skeleton notice for v1 scaffold
		fmt.Println("Scan engine initialized. Run phase components will execute here.")
		return nil
	},
}

func init() {
	scanCmd.Flags().StringVarP(&formatFlag, "format", "f", "sarif", "Output format (sarif, json, junit)")
	scanCmd.Flags().StringVarP(&outputFlag, "output", "o", "", "Output file path (default: stdout)")
	scanCmd.Flags().BoolVar(&enableTriage, "triage", false, "Enable opt-in LLM reachability and exploitability triage")

	rootCmd.AddCommand(scanCmd)
}
