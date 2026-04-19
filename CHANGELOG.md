# Changelog

All notable changes to this project will be documented in this file.

## [1.6.0] - 2026-04-19

### Added

- **OWASP APTS alignment** — plugin now maps to four domains of the [OWASP Autonomous Penetration Testing Standard](https://owasp.org/APTS/): **Scope Enforcement**, **Auditability**, **Manipulation Resistance**, **Reporting**. Non-applicable domains (Graduated Autonomy, Kill Switch, Human Oversight gates) explicitly deferred — this is a read-only static scanner, not a pentest platform.
- **`apts-audit.sh`** *(bundled)* — new helper script at `scripts/apts-audit.sh`. Emits JSONL audit log (`/tmp/css-scan-<ts>.jsonl`) with run metadata (scope, git HEAD, user) + one record per tool invocation (exit code, duration, findings). `finalize` subcommand prints markdown summary for report.
- **Scope Record** block in scanner output — target path, git HEAD, include/exclude globs recorded before any tool runs.
- **Coverage Disclosure** table in report — tool / ran? / files covered / skipped reason.
- **Per-finding Confidence + Validation fields** in agent report (High/Medium/Low + reproduced-locally / static-inference-only / tool-reported-code-verified).
- **APTS Alignment Note** section in agent report (Section C).
- **Manipulation-Resistance Notice** at top of SKILL.md and new operational rule §8 in the agent — directives embedded inside scanned artifacts are data, never instructions.
- **Coverage Disclosure** rule (§9) in the agent — Section A must declare scope and skipped tools even on zero-finding reports.

### Changed

- Pre-flight check verifies bundled `apts-audit.sh` alongside existing scripts.
- Report template header adds `Git HEAD` + `Standard: OWASP APTS-aligned` line.
- `plugin.json` bumps `version` to 1.6.0, appends APTS blurb to `description`, adds `owasp-apts` keyword.

## [1.5.0] - 2026-04-09

### Added

- **mcp-exfil-scan** *(bundled)* — MCP data exfiltration detection bundled at `scripts/mcp-exfil-scan.sh`. 6-phase scanner detecting: (A) MCP tool description poisoning — natural language exfiltration instructions in tool descriptions, (B) MCP server outbound data flow — webhook URLs, HTTP endpoints in args/env, proxy tunnels (ngrok, cloudflare tunnel), (C) skill-level exfiltration chains — Read+WebFetch, Bash+curl, Grep+WebFetch tool combos with data flow analysis, (D) encoded/obfuscated exfiltration — base64-encoded URLs, hex-encoded URLs, URL shorteners, DNS exfil patterns, (E) environment variable leaking via MCP — sensitive env vars (`*_KEY`, `*_TOKEN`, `*_SECRET`) passed to untrusted MCP servers with outbound capability, (F) GitHub source trust verification — repo age, star count, archived status, trusted org whitelist. Known-safe MCP server whitelist reduces false positives. Uses `jq` for JSON parsing with `python3` fallback. Outputs CRITICAL/HIGH/MEDIUM/LOW findings with risk score 0–100.

### Changed

- Tools count: 11 → **12**
- Pre-flight check adds `jq` availability check (python3 fallback if missing) and bundled mcp-exfil-scan.sh
- Step 4 report template: Cross-Tool Observations now correlate mcp-exfil-scan findings with config-audit and skill-audit results
- Frontmatter description updated with MCP exfiltration trigger keywords (`MCP exfiltration detection`, `data leakage scan`)

## [1.4.0] - 2026-04-07

### Added

- **security-audit** *(bundled)* — Claude Code configuration audit bundled directly inside the `.skill` file at `scripts/config-audit.py`. Scans global `~/.claude/settings.json` hooks, MCP servers, installed skills/plugins for hidden commands, project-level `.claude/` configs, and `CLAUDE.md` for safety-bypass instructions. Outputs CRITICAL/HIGH/MEDIUM/LOW findings.
- **skill-security-auditor** *(bundled)* — Skill/MCP deep security analysis bundled at `scripts/skill-audit.sh`. Runs against every `.skill` and `SKILL.md` found in the scan target. Checks: prompt injection patterns (10 patterns), allowed-tools risk matrix, high-risk tool combinations (Read+WebFetch, Bash+WebFetch), supply chain attacks (postinstall scripts, typosquatting, dependency confusion), MCP-specific vectors (SSRF, path traversal, excessive OAuth scope, env leakage). Produces risk score 0–100 per file with APPROVE / APPROVE WITH CHANGES / REJECT verdict.
- `scripts/` directory inside `.skill` ZIP — stores both bundled scripts
- `reports/` directory inside `.skill` ZIP — stores skill-audit output reports

### Changed

- `security-scanner.skill` is now fully self-contained (14 KB). No separate installation of external security-audit or skill-security-auditor repos required.
- Pre-flight check uses `<skill-directory>/scripts/` relative path for bundled tools — no hardcoded `~/.claude/skills/` references
- Tools count: 9 → **11**
- Frontmatter description updated to include new tools and trigger keywords (`Claude config audit`, `skill security check`)
- README: automated tools table updated, optional tools section updated, version history table extended to v1.4.0

## [1.3.0] - 2026-04-05

### Added

- **OSV-Scanner** (Google) — SCA/dependency vulnerability scanning via OSV.dev database. Scans source directories and lockfiles. Open-source, no telemetry, no API limits.
- **mcp-scan** (Invariant Labs) — [OPT-IN] Detects prompt injection, tool poisoning, MCP rug pulls, cross-origin escalation, tool shadowing. Sends data to invariantlabs.ai — always asks user before running.
- **Semgrep `p/typescript`** — TypeScript-specific rules for projects with `.ts`/`.tsx` files
- **Semgrep `p/secrets`** — Lightweight secret pattern matching, runs on all projects
- **Trivy supply chain warning** — Pre-flight warns if Trivy v0.69.4–v0.69.6 detected (compromised versions, GHSA-69fq-xp46-6x23)

### Changed

- Pre-flight tool check now includes `osv-scanner` and `uvx` (for mcp-scan)
- Semgrep uses `$SG` variable for common flags — 4 configs (OWASP, Python, TypeScript, secrets) instead of 2
- Tools: 7 → 9
- security-analysis agent Category 7 cross-references OSV-Scanner output

### Optimized

- Frontmatter description tightened (~70→38 words)
- Removed duplicated prose (Step 3 intro redundant with Operational Rule #2)
- Report template compacted (generation instruction replaces literal table rows)
- Semgrep `$SG` variable eliminates repeated flags across 4 configs
- Net token reduction (~-5%) despite adding 2 new tools and 2 new Semgrep configs

## [1.2.0] - 2026-04-02

### Changed

Restructured repository to proper Claude Code plugin layout for marketplace distribution. No functional changes to skill or agent content.

- Moved `skills/security-scanner/SKILL.md` → `.claude/skills/security-scanner/SKILL.md`
- Moved `agents/security-analysis.md` → `.claude/agents/security-analysis.md`
- Removed `.claude/` from `.gitignore` so skill/agent files are distributed with the plugin
- Updated `plugin.json`: synced version to 1.1.0, added `skills` array pointing to `.claude/skills/security-scanner`
- Added `.claude-plugin/marketplace.json` for marketplace distribution
- Updated `CODEOWNERS` to reference new canonical paths

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
