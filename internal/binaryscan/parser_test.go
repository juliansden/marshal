package binaryscan

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// buildFixture cross-compiles a trivial Go program for the given GOOS/GOARCH
// and returns the path to the resulting binary. Skips the test if the local
// Go toolchain cannot cross-compile for the requested target.
func buildFixture(t *testing.T, goos, goarch, outName string) string {
	t.Helper()

	srcDir := t.TempDir()
	src := filepath.Join(srcDir, "main.go")
	if err := os.WriteFile(src, []byte("package main\nfunc main() {}\n"), 0o644); err != nil {
		t.Fatalf("writing fixture source: %v", err)
	}

	outPath := filepath.Join(t.TempDir(), outName)
	cmd := exec.Command("go", "build", "-o", outPath, src)
	cmd.Env = append(cmd.Environ(), "GOOS="+goos, "GOARCH="+goarch, "CGO_ENABLED=0")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Skipf("cross-compiling %s/%s fixture unavailable: %v\n%s", goos, goarch, err, out)
	}
	return outPath
}

func TestDetectFormatAndParse(t *testing.T) {
	tests := []struct {
		name       string
		goos       string
		goarch     string
		outName    string
		wantFormat string
	}{
		{"elf", "linux", "amd64", "fixture_elf", "elf"},
		{"pe", "windows", "amd64", "fixture_pe.exe", "pe"},
		{"macho", "darwin", "arm64", "fixture_macho", "macho"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := buildFixture(t, tt.goos, tt.goarch, tt.outName)

			format, err := detectFormat(path)
			if err != nil {
				t.Fatalf("detectFormat: %v", err)
			}
			if format != tt.wantFormat {
				t.Errorf("detectFormat() = %q, want %q", format, tt.wantFormat)
			}

			info, err := ParseBinary(path)
			if err != nil {
				t.Fatalf("ParseBinary: %v", err)
			}
			if info.Format != tt.wantFormat {
				t.Errorf("info.Format = %q, want %q", info.Format, tt.wantFormat)
			}
			if info.Arch == "" {
				t.Errorf("expected non-empty Arch")
			}
		})
	}
}
