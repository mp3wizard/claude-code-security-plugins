# Changelog

All notable changes to this project will be documented in this file.

## [1.1.0] - 2026-04-01

### Changed

- `security-scanner` skill — optimized prompt: condensed from 348 to 145 lines; same 7-tool coverage, tighter bash examples, shorter install table, compact report template
- `security-analysis` agent — optimized prompt: condensed from 142 to 112 lines; concise persona, shortened phase descriptions, compact vulnerability category one-liners, simplified detection source field, condensed severity framework and memory section

## [1.0.0] - 2026-03-13

### Added

- `security-scanner` skill — orchestrates Bandit, Semgrep, Trivy, and TruffleHog with structured markdown output
- `security-analysis` agent — comprehensive static security review across 12 vulnerability categories
- Pre-flight tool check with interactive install-or-skip flow
- Cross-tool observation analysis in scan reports
- Coverage gap reporting for manual review awareness
- Dual-audience report output (executive summary + engineering findings)
