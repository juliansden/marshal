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
	osvClient *OSVClient
}

// NewScanner initializes a new Scanner instance.
func NewScanner() *Scanner {
	return &Scanner{osvClient: NewOSVClient()}
}

// ScanTarget analyzes the specified binary file, fingerprints statically-linked
// libraries, enriches matches with known vulnerabilities via OSV.dev, and
// returns the resulting findings.
func (s *Scanner) ScanTarget(ctx context.Context, targetPath string) ([]findings.Finding, error) {
	info, err := ParseBinary(targetPath)
	if err != nil {
		return nil, err
	}

	matches := MatchSignatures(*info)
	if len(matches) == 0 {
		return nil, nil
	}

	vulnsByLib, err := s.osvClient.QueryLibraries(ctx, matches)
	if err != nil {
		return nil, err
	}

	var results []findings.Finding
	for _, match := range matches {
		for _, vuln := range vulnsByLib[match.Signature.Name] {
			f := findings.Finding{
				Engine:      findings.EngineBinarySCA,
				CVE:         primaryCVEAlias(vuln),
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

// primaryCVEAlias returns the first CVE-formatted alias for a vulnerability, falling
// back to the OSV ID itself if no CVE alias is present.
func primaryCVEAlias(vuln OSVVuln) string {
	for _, alias := range vuln.Aliases {
		if len(alias) > 4 && alias[:4] == "CVE-" {
			return alias
		}
	}
	return vuln.ID
}
