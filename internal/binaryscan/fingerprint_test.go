package binaryscan

import "testing"

func TestMatchSignaturesDetectsOpenSSL(t *testing.T) {
	info := BinaryInfo{
		Symbols: []string{"main", "SSL_CTX_new", "OPENSSL_init_ssl", "OPENSSL_1_1_1"},
	}
	matches := MatchSignatures(info)
	if len(matches) != 1 {
		t.Fatalf("expected 1 match, got %d", len(matches))
	}
	if matches[0].Signature.Name != "openssl" {
		t.Errorf("expected openssl match, got %s", matches[0].Signature.Name)
	}
	if matches[0].Version != "" {
		t.Errorf("expected undetermined version, got %q", matches[0].Version)
	}
}

func TestMatchSignaturesNoMatch(t *testing.T) {
	info := BinaryInfo{Symbols: []string{"main", "fmt.Println"}}
	if matches := MatchSignatures(info); len(matches) != 0 {
		t.Errorf("expected no matches, got %d", len(matches))
	}
}

func TestMatchSignaturesRequiresAllMarkers(t *testing.T) {
	// Only one of zlib's two markers present.
	info := BinaryInfo{Symbols: []string{"inflate"}}
	if matches := MatchSignatures(info); len(matches) != 0 {
		t.Errorf("expected no match when not all markers present, got %d", len(matches))
	}
}

func TestMatchSignaturesUnknownVersion(t *testing.T) {
	info := BinaryInfo{Symbols: []string{"inflate", "deflate", "zlibVersion"}}
	matches := MatchSignatures(info)
	if len(matches) != 1 {
		t.Fatalf("expected 1 match, got %d", len(matches))
	}
	if matches[0].Version != "" {
		t.Errorf("expected undetermined version, got %q", matches[0].Version)
	}
}
