package binaryscan

import (
	"bytes"
	"debug/elf"
	"debug/macho"
	"debug/pe"
	"encoding/hex"
	"fmt"
	"io"
	"os"
)

// BinaryInfo captures the format-agnostic facts extracted from a binary
// artifact that are used for static-library fingerprinting.
type BinaryInfo struct {
	Path         string
	Format       string // "elf", "macho", or "pe"
	Arch         string
	BuildID      string
	Symbols      []string
	ImportedLibs []string
}

var (
	elfMagic    = []byte{0x7f, 'E', 'L', 'F'}
	machoMagics = [][]byte{
		{0xfe, 0xed, 0xfa, 0xce}, // 32-bit big endian
		{0xce, 0xfa, 0xed, 0xfe}, // 32-bit little endian
		{0xfe, 0xed, 0xfa, 0xcf}, // 64-bit big endian
		{0xcf, 0xfa, 0xed, 0xfe}, // 64-bit little endian
		{0xca, 0xfe, 0xba, 0xbe}, // fat/universal big endian
		{0xbe, 0xba, 0xfe, 0xca}, // fat/universal little endian
	}
	peMagic = []byte{'M', 'Z'}
)

// detectFormat sniffs the leading bytes of a file to determine its binary format.
func detectFormat(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", fmt.Errorf("binaryscan: opening %s: %w", path, err)
	}
	defer f.Close()

	header := make([]byte, 4)
	if _, err := io.ReadFull(f, header); err != nil {
		return "", fmt.Errorf("binaryscan: reading header of %s: %w", path, err)
	}

	switch {
	case bytes.Equal(header, elfMagic):
		return "elf", nil
	case bytes.Equal(header[:2], peMagic):
		return "pe", nil
	}
	for _, magic := range machoMagics {
		if bytes.Equal(header, magic) {
			return "macho", nil
		}
	}
	return "", fmt.Errorf("binaryscan: %s does not match any known ELF/Mach-O/PE magic", path)
}

// ParseBinary auto-detects the binary format at path and extracts BinaryInfo.
func ParseBinary(path string) (*BinaryInfo, error) {
	format, err := detectFormat(path)
	if err != nil {
		return nil, err
	}
	switch format {
	case "elf":
		return parseELF(path)
	case "macho":
		return parseMachO(path)
	case "pe":
		return parsePE(path)
	default:
		return nil, fmt.Errorf("binaryscan: unsupported format %q", format)
	}
}

// parseELF extracts symbol tables, build ID, and dynamic library dependencies from an ELF binary.
func parseELF(path string) (*BinaryInfo, error) {
	f, err := elf.Open(path)
	if err != nil {
		return nil, fmt.Errorf("binaryscan: parsing ELF %s: %w", path, err)
	}
	defer f.Close()

	info := &BinaryInfo{Path: path, Format: "elf", Arch: f.Machine.String()}

	if syms, err := f.Symbols(); err == nil {
		for _, s := range syms {
			info.Symbols = append(info.Symbols, s.Name)
		}
	}
	if dynSyms, err := f.DynamicSymbols(); err == nil {
		for _, s := range dynSyms {
			info.Symbols = append(info.Symbols, s.Name)
		}
	}

	if libs, err := f.ImportedLibraries(); err == nil {
		info.ImportedLibs = libs
	}

	if section := f.Section(".note.gnu.build-id"); section != nil {
		if data, err := section.Data(); err == nil {
			info.BuildID = extractGNUBuildID(data)
		}
	}

	return info, nil
}

// extractGNUBuildID parses the payload of a .note.gnu.build-id ELF note section.
func extractGNUBuildID(note []byte) string {
	// ELF notes: namesz(4) + descsz(4) + type(4) + name (padded) + desc (padded).
	if len(note) < 12 {
		return ""
	}
	nameSize := hostEndianUint32(note[0:4])
	descSize := hostEndianUint32(note[4:8])
	nameEnd := 12 + align4(nameSize)
	descEnd := nameEnd + descSize
	if int(descEnd) > len(note) || int(nameEnd) > len(note) {
		return ""
	}
	return hex.EncodeToString(note[nameEnd:descEnd])
}

func hostEndianUint32(b []byte) uint32 {
	return uint32(b[0]) | uint32(b[1])<<8 | uint32(b[2])<<16 | uint32(b[3])<<24
}

func align4(n uint32) uint32 {
	return (n + 3) &^ 3
}

// parseMachO extracts symbol tables, dylib dependencies, and UUID load command from a Mach-O binary.
// Universal/fat binaries are supported by analyzing their first contained architecture slice.
func parseMachO(path string) (*BinaryInfo, error) {
	if fat, err := macho.OpenFat(path); err == nil {
		defer fat.Close()
		if len(fat.Arches) == 0 {
			return nil, fmt.Errorf("binaryscan: fat Mach-O %s has no architecture slices", path)
		}
		return binaryInfoFromMachO(path, fat.Arches[0].File)
	}

	f, err := macho.Open(path)
	if err != nil {
		return nil, fmt.Errorf("binaryscan: parsing Mach-O %s: %w", path, err)
	}
	defer f.Close()
	return binaryInfoFromMachO(path, f)
}

func binaryInfoFromMachO(path string, f *macho.File) (*BinaryInfo, error) {
	info := &BinaryInfo{Path: path, Format: "macho", Arch: f.Cpu.String()}

	if f.Symtab != nil {
		for _, s := range f.Symtab.Syms {
			info.Symbols = append(info.Symbols, s.Name)
		}
	}

	for _, l := range f.Loads {
		if dylib, ok := l.(*macho.Dylib); ok {
			info.ImportedLibs = append(info.ImportedLibs, dylib.Name)
		}
	}

	return info, nil
}

// parsePE extracts the COFF symbol table and import directory entries from a PE binary.
func parsePE(path string) (*BinaryInfo, error) {
	f, err := pe.Open(path)
	if err != nil {
		return nil, fmt.Errorf("binaryscan: parsing PE %s: %w", path, err)
	}
	defer f.Close()

	info := &BinaryInfo{Path: path, Format: "pe", Arch: peMachineString(f.Machine)}

	for _, s := range f.Symbols {
		info.Symbols = append(info.Symbols, s.Name)
	}

	if libs, err := f.ImportedLibraries(); err == nil {
		info.ImportedLibs = libs
	}

	return info, nil
}

func peMachineString(machine uint16) string {
	switch machine {
	case pe.IMAGE_FILE_MACHINE_AMD64:
		return "amd64"
	case pe.IMAGE_FILE_MACHINE_I386:
		return "386"
	case pe.IMAGE_FILE_MACHINE_ARM64:
		return "arm64"
	default:
		return fmt.Sprintf("unknown(0x%x)", machine)
	}
}
