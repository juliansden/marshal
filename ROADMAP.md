# Marshal Project Roadmap

Marshal is a security analysis and correlation engine that unifies binary composition analysis (BCA), SAST (Semgrep), and DAST (OWASP ZAP) under a shared schema, correlation layer, and opt-in LLM triage.

This roadmap outlines the planned development phases. Each phase is designed to be independently useful upon completion.

---

## Phase 1: Binary Composition Analysis (BCA) Engine & Shared Finding Schema

*Goal*: Build the novel binary composition analysis core using Go standard library debug packages (`debug/elf`, `debug/macho`, `debug/pe`), establish the primary SARIF report exporter, and finalize the foundational `Finding` schema.

### Package & File-Level TODOs

- **`internal/findings/findings.go`**
  - [x] Finalize `Finding`, `Location` (`FileLocation`, `URLLocation`), `Severity`, `EngineType`, and `TriageResult` structs.
  - [x] Implement `ComputeFingerprint()` generation helper (SHA-256 hash of location, rule/CVE ID, and normalized title).
  - [x] Implement JSON marshaling/unmarshaling validation for `Location`.

- **`internal/binaryscan/parser.go`**
  - [x] Implement ELF parser using `debug/elf` to extract embedded symbol tables, `.comment` sections, and build IDs.
  - [x] Implement Mach-O parser using `debug/macho` to inspect load commands and dynamic symbol tables (including fat/universal binaries).
  - [x] Implement PE parser using `debug/pe` to extract COFF headers and export/import directories.

- **`internal/binaryscan/fingerprint.go`**
  - [x] Implement static library fingerprinting algorithm (matching symbol name sets against known static lib signatures).
  - [x] Detect the linked library version via embedded version-banner strings each library compiles in verbatim (e.g. OpenSSL's `OpenSSL 1.1.1f  31 Mar 2020`, zlib's `deflate 1.2.11 Copyright ...`, libcurl's `libcurl/7.68.0`, libpng's `libpng version 1.6.37 ...`), rather than fabricated "version marker" symbols.
  - [x] Integrate CVE lookup via NIST NVD's CPE-based API (`services.nvd.nist.gov/rest/json/cves/2.0?cpeName=...`), keyed by `vendor:product:version` per detected library. NVD's CPE model was chosen over OSV.dev because OSV has no ecosystem for "generic statically-linked C library by upstream version" — only distro package ecosystems (Debian/Alpine) whose versioning doesn't line up with upstream semver, which previously produced no results or inaccurate/unscoped matches. Requests respect NVD's published rate limits (5/30s unauthenticated, 50/30s with `MARSHAL_NVD_API_KEY` set) and degrade gracefully (skip enrichment, don't fail the scan) on network errors. Queries are skipped entirely when a version can't be determined.

- **`internal/binaryscan/binaryscan.go`**
  - [x] Wire parsers and fingerprinting into `Scanner.ScanTarget(ctx, binaryPath)`.
  - [x] Map detected vulnerable library symbols to `findings.Finding` instances with `EngineBinarySCA`.

- **`internal/report/sarif.go`**
  - [x] Implement SARIF v2.1.0 exporter (`OASIS SARIF` spec) converting `[]findings.Finding` to standard SARIF log format for GitHub Code Scanning / VS Code Problems panel integration.

- **`internal/report/json.go` & `internal/report/junit.go`**
  - [x] Implement raw JSON array exporter.
  - [x] Implement JUnit XML report exporter for CI/CD test runner integration.

- **`cmd/marshal/scan.go`**
  - [x] Connect `marshal scan <binary>` to invoke `binaryscan` and write formatted reports via `internal/report`.

---

## Phase 2: Semgrep Adapter (SAST)

*Goal*: Ingest static application security testing (SAST) findings from Semgrep into Marshal's shared schema.

### Package & File-Level TODOs

- **`internal/adapters/semgrep/parser.go`**
  - [ ] Parse Semgrep native SARIF (`semgrep scan --sarif`) and JSON outputs (`semgrep scan --json`).
  - [ ] Map Semgrep rule IDs, severity levels (`ERROR` -> `HIGH`, `WARNING` -> `MEDIUM`, `INFO` -> `LOW`), and CWE identifiers to `findings.Severity` and `findings.Finding`.

- **`internal/adapters/semgrep/semgrep.go`**
  - [ ] Implement process execution wrapper to optional shell-out to `semgrep` CLI if raw input file is not directly provided.
  - [ ] Implement `Adapter.ParseReport(ctx, reportBytes)` returning `[]findings.Finding` with `EngineSemgrep` and `LocationTypeFile`.

- **`cmd/marshal/scan.go`**
  - [ ] Add CLI flags `--semgrep-report <path>` and `--run-semgrep` to include SAST results in the scan pipeline.

---

## Phase 3: ZAP Adapter (DAST)

*Goal*: Ingest dynamic application security testing (DAST) findings from OWASP ZAP, mapping URL/endpoint-based locations to the shared schema.

### Package & File-Level TODOs

- **`internal/adapters/zap/parser.go`**
  - [ ] Parse OWASP ZAP JSON (`zap-cli report -f json`) and XML report formats.
  - [ ] Extract endpoint-specific metadata: target URL, HTTP method (GET, POST, etc.), vulnerable query parameter/header, HTTP status code, and attack evidence payload.

- **`internal/adapters/zap/zap.go`**
  - [ ] Map ZAP alert risk codes (0: Info, 1: Low, 2: Medium, 3: High) to `findings.Severity`.
  - [ ] Construct `findings.Location` using `LocationTypeURL` and `URLLocation` fields (`URL`, `Method`, `Parameter`, `Header`, `Evidence`).
  - [ ] Implement `Adapter.ParseReport(ctx, reportBytes)` returning `[]findings.Finding` with `EngineZAP`.

- **`cmd/marshal/scan.go`**
  - [ ] Add CLI flag `--zap-report <path>` to ingest ZAP DAST reports into the scan pipeline.

---

## Phase 4: Correlation Layer

*Goal*: Merge findings from Binary SCA, SAST, and DAST into unified entities, deduplicating identical vulnerabilities across detection tools.

### Package & File-Level TODOs

- **`internal/correlate/fingerprint.go`**
  - [ ] Define cross-engine correlation strategy:
    - Match Binary SCA CVEs against SAST dependency rules.
    - Match SAST entry points / route handlers against DAST target URLs and endpoints.
  - [ ] Build stable canonical fingerprint generation across engines.

- **`internal/correlate/correlate.go`**
  - [ ] Implement `Correlator.Correlate(ctx, findings)` to group duplicate findings, synthesize confidence scores, and aggregate metadata.
  - [ ] Retain original engine sources inside correlated finding metadata for traceability.

- **`cmd/marshal/scan.go`**
  - [ ] Pass aggregated findings through `internal/correlate` prior to reporting.

---

## Phase 5: LLM-Based Reachability & Exploitability Triage

*Goal*: Add an opt-in LLM layer to evaluate whether correlated vulnerabilities are practically reachable or exploitable in the codebase, avoiding false positives without modifying deterministic scanner outputs.

### Package & File-Level TODOs

- **`internal/triage/client.go`**
  - [ ] Implement `LLMClient` interface implementations for OpenAI, Anthropic, and local Ollama API endpoints.
  - [ ] Create provider factory `NewLLMClient(provider, apiKey, model)`.

- **`internal/triage/prompt.go`**
  - [ ] Build context extraction helpers (fetching surrounding lines of code for SAST/BCA findings or API route definitions for DAST findings).
  - [ ] Construct structured prompts asking the LLM to output structured JSON with `verdict` (`REACHABLE`, `UNREACHABLE`, `FALSE_POSITIVE`, `NEEDS_REVIEW`), `confidence` (0.0 - 1.0), and concise `reasoning`.

- **`internal/triage/triage.go`**
  - [ ] Ensure triage is strictly opt-in (`--triage` flag or config file).
  - [ ] Gracefully pass findings unmodified if unconfigured or if API calls fail.
  - [ ] Attach `TriageResult` to `finding.Triage`.

- **`cmd/marshal/scan.go`**
  - [ ] Wire `--triage`, `--llm-provider`, and `--llm-model` CLI flags into `triage.Engine`.

---

## Phase 6: Automated Fix PR Generation

*Goal*: Automatically generate remediation code patches and pull requests for high-confidence triaged findings.

### Package & File-Level TODOs

- **`internal/fix/patch.go`**
  - [ ] Use triage output to prioritize reachable vulnerabilities.
  - [ ] Prompt LLM or dependency auto-updater to draft code patches or dependency version bumps in `go.mod`, `package.json`, etc.

- **`internal/fix/git.go`**
  - [ ] Implement Git operations (branch creation, commit crafting, diff formatting).

- **`cmd/marshal/fix.go`**
  - [ ] Add `marshal fix` subcommand to generate local patches or submit GitHub Pull Requests via GitHub API.

---

## Distribution Track (Parallel Track)

*Goal*: Ensure seamless installation and release automation across platforms.

- **Milestone D1: GoReleaser & Release Automation (Completed in Scaffold)**
  - [x] Create `.goreleaser.yaml` supporting `linux/amd64`, `linux/arm64`, `darwin/amd64`, `darwin/arm64`, and `windows/amd64`.
  - [x] Create `.github/workflows/release.yml` to trigger cross-compilation releases on `v*` tags.
  - [ ] Author shell install script (`install.sh`) for `curl | sh` binary downloads from GitHub Releases.

- **Milestone D2: GitHub Action Wrapper**
  - [ ] Create `action.yml` wrapper repo (`marshal-security/marshal-action`) to execute `marshal scan` in GitHub Actions workflows and upload SARIF results automatically.

- **Milestone D3: Homebrew Tap**
  - [ ] Create `homebrew-marshal` formula tap repository for `brew install marshal-security/tap/marshal`.
