package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/marshal-security/marshal/internal/adapters/semgrep"
	"github.com/marshal-security/marshal/internal/binaryscan"
	"github.com/marshal-security/marshal/internal/findings"
	"github.com/marshal-security/marshal/internal/report"
)

var (
	formatFlag   string
	outputFlag   string
	semgrepFlag  string
	enableTriage bool
)

var scanCmd = &cobra.Command{
	Use:     "inspect <target>",
	Aliases: []string{"scan"},
	Short:   "Run security analysis on target binaries, codebases, or reports",
	Long: `Scan inspects compiled binaries, source code, or adapter inputs, correlates findings,
and optionally performs LLM-based reachability triage.`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		target := args[0]

		exporter, err := report.NewExporter(report.Format(formatFlag))
		if err != nil {
			return err
		}

		var results []findings.Finding
		info, err := os.Stat(target)
		if err != nil {
			return fmt.Errorf("stat target: %w", err)
		}
		if !info.IsDir() {
			scanner := binaryscan.NewScanner()
			results, err = scanner.ScanTarget(cmd.Context(), target)
			if err != nil {
				return fmt.Errorf("scan failed: %w", err)
			}
			if len(results) == 0 && semgrepFlag == "" {
				if _, err := fmt.Fprintln(cmd.ErrOrStderr(), "Binary scan completed: no supported library signatures detected"); err != nil {
					return fmt.Errorf("writing scan status: %w", err)
				}
			}
		}

		if semgrepFlag != "" {
			reportData, err := os.ReadFile(semgrepFlag)
			if err != nil {
				return fmt.Errorf("reading Semgrep report: %w", err)
			}
			semgrepFindings, err := semgrep.NewAdapter().ParseReport(cmd.Context(), reportData)
			if err != nil {
				return fmt.Errorf("parsing Semgrep report: %w", err)
			}
			results = append(results, semgrepFindings...)
		}

		if enableTriage {
			if _, err := fmt.Fprintln(cmd.ErrOrStderr(), "LLM Reachability Triage: Enabled (Opt-in) -- not yet implemented, findings unmodified"); err != nil {
				return fmt.Errorf("writing triage status: %w", err)
			}
		}

		out := cmd.OutOrStdout()
		if outputFlag != "" {
			f, err := os.Create(outputFlag)
			if err != nil {
				return fmt.Errorf("creating output file: %w", err)
			}
			defer f.Close()
			out = f
		}

		return exporter.Export(out, results)
	},
}

var musterCmd = &cobra.Command{
	Use:   "muster <binary>",
	Short: "Run binary composition analysis on a compiled binary",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		target := args[0]
		info, err := os.Stat(target)
		if err != nil {
			return fmt.Errorf("stat binary: %w", err)
		}
		if info.IsDir() {
			return fmt.Errorf("muster target must be a file, got directory %q", target)
		}

		results, err := binaryscan.NewScanner().ScanTarget(cmd.Context(), target)
		if err != nil {
			return fmt.Errorf("binary scan failed: %w", err)
		}
		if len(results) == 0 {
			if _, err := fmt.Fprintln(cmd.ErrOrStderr(), "Binary scan completed: no supported library signatures detected"); err != nil {
				return fmt.Errorf("writing scan status: %w", err)
			}
		}
		return exportFindings(cmd, results)
	},
}

var scryCmd = &cobra.Command{
	Use:   "scry <semgrep-report>",
	Short: "Parse a Semgrep SARIF or JSON report",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		reportData, err := os.ReadFile(args[0])
		if err != nil {
			return fmt.Errorf("reading Semgrep report: %w", err)
		}
		results, err := semgrep.NewAdapter().ParseReport(cmd.Context(), reportData)
		if err != nil {
			return fmt.Errorf("parsing Semgrep report: %w", err)
		}
		return exportFindings(cmd, results)
	},
}

func exportFindings(cmd *cobra.Command, results []findings.Finding) error {
	exporter, err := report.NewExporter(report.Format(formatFlag))
	if err != nil {
		return err
	}
	out := cmd.OutOrStdout()
	if outputFlag != "" {
		f, err := os.Create(outputFlag)
		if err != nil {
			return fmt.Errorf("creating output file: %w", err)
		}
		defer f.Close()
		out = f
	}
	return exporter.Export(out, results)
}

func addOutputFlags(cmd *cobra.Command) {
	cmd.Flags().StringVarP(&formatFlag, "format", "f", "sarif", "Output format (sarif, json, junit)")
	cmd.Flags().StringVarP(&outputFlag, "output", "o", "", "Output file path (default: stdout)")
}

func init() {
	addOutputFlags(scanCmd)
	scanCmd.Flags().StringVar(&semgrepFlag, "semgrep-report", "", "Read Semgrep SARIF or JSON report from this path")
	scanCmd.Flags().BoolVar(&enableTriage, "triage", false, "Enable opt-in LLM reachability and exploitability triage")
	addOutputFlags(musterCmd)
	addOutputFlags(scryCmd)

	rootCmd.AddCommand(scanCmd)
	rootCmd.AddCommand(musterCmd)
	rootCmd.AddCommand(scryCmd)
}
