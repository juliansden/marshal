package binaryscan

import "strings"

// librarySignature describes a known statically-linkable library and how to
// recognize it from the symbol names present in a scanned binary, plus how
// to look up its known vulnerabilities via the OSV.dev API.
type librarySignature struct {
	Name         string
	OSVEcosystem string
	OSVPackage   string
	// SymbolMarkers are symbol name substrings that, if all present, indicate
	// the library is statically linked into the binary.
	SymbolMarkers []string
	// VersionSymbols maps a version string to a symbol name unique to that
	// version (e.g. a version-suffixed exported symbol). Best-effort only.
	VersionSymbols map[string]string
}

// knownSignatures is a small, hand-curated set of statically-linkable C/C++
// libraries with a documented history of CVEs. Extend as needed.
var knownSignatures = []librarySignature{
	{
		Name:          "openssl",
		OSVEcosystem:  "Debian",
		OSVPackage:    "openssl",
		SymbolMarkers: []string{"SSL_CTX_new", "OPENSSL_init_ssl"},
		VersionSymbols: map[string]string{
			"1.1.1": "OPENSSL_1_1_1",
			"3.0.0": "OPENSSL_3_0_0",
		},
	},
	{
		Name:          "zlib",
		OSVEcosystem:  "Debian",
		OSVPackage:    "zlib",
		SymbolMarkers: []string{"inflate", "deflate", "zlibVersion"},
	},
	{
		Name:          "libcurl",
		OSVEcosystem:  "Debian",
		OSVPackage:    "curl",
		SymbolMarkers: []string{"curl_easy_init", "curl_easy_perform"},
	},
	{
		Name:          "libxml2",
		OSVEcosystem:  "Debian",
		OSVPackage:    "libxml2",
		SymbolMarkers: []string{"xmlParseDocument", "xmlReadMemory"},
	},
	{
		Name:          "libpng",
		OSVEcosystem:  "Debian",
		OSVPackage:    "libpng",
		SymbolMarkers: []string{"png_create_read_struct", "png_read_image"},
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
	for _, sig := range knownSignatures {
		if !allMarkersPresent(symbolSet, sig.SymbolMarkers) {
			continue
		}
		matches = append(matches, LibraryMatch{
			Signature: sig,
			Version:   guessVersion(symbolSet, sig),
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

func guessVersion(symbolSet map[string]struct{}, sig librarySignature) string {
	for version, marker := range sig.VersionSymbols {
		if symbolPresent(symbolSet, marker) {
			return version
		}
	}
	return ""
}
