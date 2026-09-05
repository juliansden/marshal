// Package binaryscan provides binary composition analysis (BCA) capabilities.
// It inspects compiled binaries (ELF, Mach-O, PE) using Go standard library debug packages
// to identify statically-linked dependencies and map them to known vulnerabilities.
package binaryscan

import (
	"context"
	"fmt"

	"github.com/marshal-security/marshal/internal/findings"
)

// Scanner performs binary composition analysis on target executable binaries.
type Scanner struct {
	osvClient    *OSVClient
	parseBinary  func(string) (*BinaryInfo, error)
	matchLibrary func(BinaryInfo) []LibraryMatch
}

// NewScanner initializes a new Scanner instance.
func NewScanner() *Scanner {
	return &Scanner{
		osvClient:    NewOSVClient(),
		parseBinary:  ParseBinary,
		matchLibrary: MatchSignatures,
	}
}

// ScanTarget analyzes the specified binary file, fingerprints statically-linked
// libraries, enriches matches with known vulnerabilities via OSV.dev, and
// returns the resulting findings.
func (s *Scanner) ScanTarget(ctx context.Context, targetPath string) ([]findings.Finding, error) {
	if s.parseBinary == nil {
		s.parseBinary = ParseBinary
	}
	if s.matchLibrary == nil {
		s.matchLibrary = MatchSignatures
	}

	info, err := s.parseBinary(targetPath)
	if err != nil {
		return nil, err
	}

	matches := s.matchLibrary(*info)
	if len(matches) == 0 {
		return nil, nil
	}

	vulnsByLib, err := s.osvClient.QueryLibraries(ctx, matches)
	if err != nil {
		return nil, err
	}

	var results []findings.Finding
	for _, match := range matches {
		vulns := vulnsByLib[match.Signature.Name]
		if len(vulns) == 0 {
			results = append(results, unmatchedLibraryFinding(targetPath, *info, match))
			continue
		}
		for _, vuln := range vulns {
			cve := primaryCVEAlias(vuln)
			f := findings.Finding{
				Engine:      findings.EngineBinarySCA,
				ID:          vuln.ID,
				RuleID:      vuln.ID,
				CVE:         cve,
				Severity:    findings.NormalizeSeverity(vuln.Severity),
				Title:       fmt.Sprintf("Vulnerable statically-linked library: %s", match.Signature.Name),
				Description: vuln.Summary,
				Location: findings.Location{
					Type: findings.LocationTypeFile,
					File: &findings.FileLocation{Path: targetPath},
				},
				Metadata: map[string]any{
					"library":     match.Signature.Name,
					"version":     match.Version,
					"osv_id":      vuln.ID,
					"binary_arch": info.Arch,
				},
			}
			f.Fingerprint = f.ComputeFingerprint()
			results = append(results, f)
		}
	}
	return results, nil
}

func unmatchedLibraryFinding(targetPath string, info BinaryInfo, match LibraryMatch) findings.Finding {
	description := "Detected statically-linked library; CVE enrichment unavailable without version and package provenance."
	if match.Version != "" {
		description = "Detected statically-linked library; CVE enrichment unavailable with current ecosystem/package metadata."
	}
	f := findings.Finding{
		ID:          fmt.Sprintf("binaryscan-%s-unenriched", match.Signature.Name),
		RuleID:      fmt.Sprintf("binaryscan-%s-unenriched", match.Signature.Name),
		Engine:      findings.EngineBinarySCA,
		Severity:    findings.SeverityInfo,
		Title:       fmt.Sprintf("Detected statically-linked library: %s", match.Signature.Name),
		Description: description,
		Location: findings.Location{
			Type: findings.LocationTypeFile,
			File: &findings.FileLocation{Path: targetPath},
		},
		Metadata: map[string]any{
			"library":     match.Signature.Name,
			"version":     match.Version,
			"osv_id":      "",
			"binary_arch": info.Arch,
		},
	}
	f.Fingerprint = f.ComputeFingerprint()
	return f
}

// primaryCVEAlias returns the first CVE-formatted alias for a vulnerability.
func primaryCVEAlias(vuln OSVVuln) string {
	for _, alias := range vuln.Aliases {
		if len(alias) > 4 && alias[:4] == "CVE-" {
			return alias
		}
	}
	return ""
}
