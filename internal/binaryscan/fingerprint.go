package binaryscan

import (
	"os"
	"regexp"
	"strings"
)

// librarySignature describes a known statically-linkable library: how to
// recognize it from the symbol names present in a scanned binary, how to
// extract its embedded version banner (if any), and how to identify it as a
// CPE (vendor:product) for NVD vulnerability lookups.
type librarySignature struct {
	Name string
	// CPEVendor and CPEProduct identify this library in NIST NVD's CPE
	// dictionary (cpe:2.3:a:{vendor}:{product}:{version}), used for CVE lookups.
	CPEVendor  string
	CPEProduct string
	// SymbolMarkers are symbol name substrings that, if all present, indicate
	// the library is statically linked into the binary.
	SymbolMarkers []string
	// VersionPattern matches a version banner string the library embeds
	// verbatim in its compiled output (e.g. copyright/version text required
	// by the library's own license, or returned by its version APIs). The
	// first capture group must be the version number. Best-effort only: if
	// no match is found, the version is left undetermined.
	VersionPattern *regexp.Regexp
}

// knownSignatures is a small, hand-curated set of statically-linkable C/C++
// libraries with a documented history of CVEs. Extend as needed.
var knownSignatures = []librarySignature{
	{
		Name:           "openssl",
		CPEVendor:      "openssl",
		CPEProduct:     "openssl",
		SymbolMarkers:  []string{"SSL_CTX_new", "OPENSSL_init_ssl"},
		VersionPattern: regexp.MustCompile(`OpenSSL (\d+\.\d+\.\d+[a-z]?)`),
	},
	{
		Name:           "zlib",
		CPEVendor:      "zlib",
		CPEProduct:     "zlib",
		SymbolMarkers:  []string{"inflate", "deflate", "zlibVersion"},
		VersionPattern: regexp.MustCompile(`(?:inflate|deflate) (\d+\.\d+\.\d+) Copyright`),
	},
	{
		Name:           "libcurl",
		CPEVendor:      "haxx",
		CPEProduct:     "curl",
		SymbolMarkers:  []string{"curl_easy_init", "curl_easy_perform"},
		VersionPattern: regexp.MustCompile(`libcurl/(\d+\.\d+\.\d+)`),
	},
	{
		Name:           "libxml2",
		CPEVendor:      "xmlsoft",
		CPEProduct:     "libxml2",
		SymbolMarkers:  []string{"xmlParseDocument", "xmlReadMemory"},
		VersionPattern: regexp.MustCompile(`libxml2[ /-](\d+\.\d+\.\d+)`),
	},
	{
		Name:           "libpng",
		CPEVendor:      "libpng",
		CPEProduct:     "libpng",
		SymbolMarkers:  []string{"png_create_read_struct", "png_read_image"},
		VersionPattern: regexp.MustCompile(`libpng version (\d+\.\d+\.\d+)`),
	},
}

// LibraryMatch is a statically-linked library identified within a scanned binary.
type LibraryMatch struct {
	Signature librarySignature
	Version   string // best-effort guess; empty if undetermined
}

// MatchSignatures matches the symbols present in info against the known
// library signature table and returns all libraries detected as statically linked.
func MatchSignatures(info BinaryInfo) []LibraryMatch {
	symbolSet := make(map[string]struct{}, len(info.Symbols))
	for _, s := range info.Symbols {
		symbolSet[s] = struct{}{}
	}

	var matches []LibraryMatch
	var rawData []byte
	var rawLoaded bool
	for _, sig := range knownSignatures {
		if !allMarkersPresent(symbolSet, sig.SymbolMarkers) {
			continue
		}
		if !rawLoaded {
			// Best-effort: a failed read just leaves the version undetermined.
			rawData, _ = os.ReadFile(info.Path)
			rawLoaded = true
		}
		matches = append(matches, LibraryMatch{
			Signature: sig,
			Version:   detectVersion(rawData, sig),
		})
	}
	return matches
}

func allMarkersPresent(symbolSet map[string]struct{}, markers []string) bool {
	if len(markers) == 0 {
		return false
	}
	for _, marker := range markers {
		if !symbolPresent(symbolSet, marker) {
			return false
		}
	}
	return true
}

// symbolPresent checks for an exact match or a symbol containing marker as a substring,
// since compiled symbol names are often decorated (name-mangled, versioned, etc.).
func symbolPresent(symbolSet map[string]struct{}, marker string) bool {
	if _, ok := symbolSet[marker]; ok {
		return true
	}
	for sym := range symbolSet {
		if strings.Contains(sym, marker) {
			return true
		}
	}
	return false
}

func detectVersion(data []byte, sig librarySignature) string {
	if sig.VersionPattern == nil || len(data) == 0 {
		return ""
	}
	m := sig.VersionPattern.FindSubmatch(data)
	if len(m) < 2 {
		return ""
	}
	return string(m[1])
}
