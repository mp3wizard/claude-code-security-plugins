# Changelog

All notable changes to this project will be documented in this file.

## [1.1.0] - 2026-04-01

### Changed

Prompt optimization pass on both skill and agent — same coverage and functionality, significantly fewer tokens.

| File | Before | After | Reduction |
|------|--------|-------|-----------|
| `skills/security-scanner/SKILL.md` | 348 lines | 145 lines | −58% |
| `agents/security-analysis.md` | 142 lines | 112 lines | −21% |

**security-scanner:** Condensed pre-flight bash block, install instructions, step headers, and report template. All 7 tools and 4-step workflow preserved.

**security-analysis:** Concise persona, tighter phase descriptions, compact vulnerability category one-liners, simplified detection source field (`Automated (<tool>) / Manual / Both`), condensed severity definitions, shorter memory section.

## [1.0.0] - 2026-03-13

### Added

- `security-scanner` skill — orchestrates Bandit, Semgrep, Trivy, and TruffleHog with structured markdown output
- `security-analysis` agent — comprehensive static security review across 12 vulnerability categories
- Pre-flight tool check with interactive install-or-skip flow
- Cross-tool observation analysis in scan reports
- Coverage gap reporting for manual review awareness
- Dual-audience report output (executive summary + engineering findings)
