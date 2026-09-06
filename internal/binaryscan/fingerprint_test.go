package binaryscan

import (
	"os"
	"path/filepath"
	"testing"
)

func TestMatchSignaturesDetectsOpenSSL(t *testing.T) {
	info := BinaryInfo{
		Symbols: []string{"main", "SSL_CTX_new", "OPENSSL_init_ssl"},
	}
	matches := MatchSignatures(info)
	if len(matches) != 1 {
		t.Fatalf("expected 1 match, got %d", len(matches))
	}
	if matches[0].Signature.Name != "openssl" {
		t.Errorf("expected openssl match, got %s", matches[0].Signature.Name)
	}
	if matches[0].Version != "" {
		t.Errorf("expected undetermined version without a binary to inspect, got %q", matches[0].Version)
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

func writeFixture(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "fixture.bin")
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("writing fixture: %v", err)
	}
	return path
}

func TestMatchSignaturesDetectsVersionFromEmbeddedOpenSSLBanner(t *testing.T) {
	path := writeFixture(t, "noise\x00OpenSSL 1.1.1f  31 Mar 2020\x00noise")
	info := BinaryInfo{Path: path, Symbols: []string{"SSL_CTX_new", "OPENSSL_init_ssl"}}

	matches := MatchSignatures(info)
	if len(matches) != 1 {
		t.Fatalf("expected 1 match, got %d", len(matches))
	}
	if matches[0].Version != "1.1.1f" {
		t.Errorf("expected version 1.1.1f, got %q", matches[0].Version)
	}
}

func TestMatchSignaturesDetectsVersionFromEmbeddedZlibBanner(t *testing.T) {
	path := writeFixture(t, "noise\x00deflate 1.2.11 Copyright 1995-2017 Jean-loup Gailly\x00noise")
	info := BinaryInfo{Path: path, Symbols: []string{"inflate", "deflate", "zlibVersion"}}

	matches := MatchSignatures(info)
	if len(matches) != 1 {
		t.Fatalf("expected 1 match, got %d", len(matches))
	}
	if matches[0].Version != "1.2.11" {
		t.Errorf("expected version 1.2.11, got %q", matches[0].Version)
	}
}

func TestMatchSignaturesDetectsVersionFromEmbeddedCurlBanner(t *testing.T) {
	path := writeFixture(t, "noise\x00libcurl/7.68.0 OpenSSL/1.1.1\x00noise")
	info := BinaryInfo{Path: path, Symbols: []string{"curl_easy_init", "curl_easy_perform"}}

	matches := MatchSignatures(info)
	if len(matches) != 1 {
		t.Fatalf("expected 1 match, got %d", len(matches))
	}
	if matches[0].Version != "7.68.0" {
		t.Errorf("expected version 7.68.0, got %q", matches[0].Version)
	}
}

func TestMatchSignaturesDetectsVersionFromEmbeddedLibpngBanner(t *testing.T) {
	path := writeFixture(t, "noise\x00libpng version 1.6.37 - April 14, 2022\x00noise")
	info := BinaryInfo{Path: path, Symbols: []string{"png_create_read_struct", "png_read_image"}}

	matches := MatchSignatures(info)
	if len(matches) != 1 {
		t.Fatalf("expected 1 match, got %d", len(matches))
	}
	if matches[0].Version != "1.6.37" {
		t.Errorf("expected version 1.6.37, got %q", matches[0].Version)
	}
}

func TestMatchSignaturesDetectsVersionFromEmbeddedLibxml2Banner(t *testing.T) {
	path := writeFixture(t, "noise\x00using libxml2/2.9.10\x00noise")
	info := BinaryInfo{Path: path, Symbols: []string{"xmlParseDocument", "xmlReadMemory"}}

	matches := MatchSignatures(info)
	if len(matches) != 1 {
		t.Fatalf("expected 1 match, got %d", len(matches))
	}
	if matches[0].Version != "2.9.10" {
		t.Errorf("expected version 2.9.10, got %q", matches[0].Version)
	}
}

func TestMatchSignaturesMissingBinaryLeavesVersionUndetermined(t *testing.T) {
	info := BinaryInfo{Path: "/nonexistent/path", Symbols: []string{"SSL_CTX_new", "OPENSSL_init_ssl"}}
	matches := MatchSignatures(info)
	if len(matches) != 1 {
		t.Fatalf("expected 1 match, got %d", len(matches))
	}
	if matches[0].Version != "" {
		t.Errorf("expected undetermined version when binary can't be read, got %q", matches[0].Version)
	}
}
