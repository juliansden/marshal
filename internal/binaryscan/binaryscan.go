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
	nvdClient    *NVDClient
	parseBinary  func(string) (*BinaryInfo, error)
	matchLibrary func(BinaryInfo) []LibraryMatch
}

// NewScanner initializes a new Scanner instance.
func NewScanner() *Scanner {
	return &Scanner{
		nvdClient:    NewNVDClient(),
		parseBinary:  ParseBinary,
		matchLibrary: MatchSignatures,
	}
}

// ScanTarget analyzes the specified binary file, fingerprints statically-linked
// libraries, enriches matches with known vulnerabilities via NVD's CPE-based
// lookup, and returns the resulting findings.
func (s *Scanner) ScanTarget(ctx context.Context, targetPath string) ([]findings.Finding, error) {
	if s.parseBinary == nil {
		s.parseBinary = ParseBinary
	}
	if s.matchLibrary == nil {
		s.matchLibrary = MatchSignatures
	}
	if s.nvdClient == nil {
		s.nvdClient = NewNVDClient()
	}

	info, err := s.parseBinary(targetPath)
	if err != nil {
		return nil, err
	}

	matches := s.matchLibrary(*info)
	if len(matches) == 0 {
		return nil, nil
	}

	vulnsByLib, err := s.nvdClient.QueryLibraries(ctx, matches)
	if err != nil {
		return nil, err
	}

	var results []findings.Finding
	for _, match := range matches {
		vulns, enriched := vulnsByLib[match.Signature.Name]
		if len(vulns) == 0 {
			results = append(results, unmatchedLibraryFinding(targetPath, *info, match, enriched))
			continue
		}
		for _, vuln := range vulns {
			f := findings.Finding{
				Engine:      findings.EngineBinarySCA,
				ID:          vuln.ID,
				RuleID:      vuln.ID,
				CVE:         vuln.ID,
				Severity:    findings.NormalizeSeverity(vuln.Severity),
				Title:       fmt.Sprintf("Vulnerable statically-linked library: %s", match.Signature.Name),
				Description: vuln.Description,
				Location: findings.Location{
					Type: findings.LocationTypeFile,
					File: &findings.FileLocation{Path: targetPath},
				},
				Metadata: map[string]any{
					"library":     match.Signature.Name,
					"version":     match.Version,
					"cve_id":      vuln.ID,
					"cpe":         fmt.Sprintf("cpe:2.3:a:%s:%s:%s:*:*:*:*:*:*:*", match.Signature.CPEVendor, match.Signature.CPEProduct, match.Version),
					"binary_arch": info.Arch,
				},
			}
			f.Fingerprint = f.ComputeFingerprint()
			results = append(results, f)
		}
	}
	return results, nil
}

func unmatchedLibraryFinding(targetPath string, info BinaryInfo, match LibraryMatch, enriched bool) findings.Finding {
	description := "Detected statically-linked library; CVE enrichment unavailable without a resolved version."
	if enriched {
		description = "Detected statically-linked library; no known CVEs were returned by NVD for this version."
	} else if match.Version != "" {
		description = "Detected statically-linked library; CVE enrichment unavailable via NVD for this version."
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
			"cve_id":      "",
			"binary_arch": info.Arch,
		},
	}
	f.Fingerprint = f.ComputeFingerprint()
	return f
}
