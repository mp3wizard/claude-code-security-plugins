# Changelog

All notable changes to this project will be documented in this file.

## [1.8.0] - 2026-07-17

### Added

- **PreToolUse secret-scan hook** (`hooks/secret-scan-pretooluse.sh`, matcher `Write|Edit|MultiEdit|NotebookEdit`) — runs Gitleaks on the *pending* write content and **blocks** the write (exit 0 + `permissionDecision:"deny"`) when a hardcoded secret is detected, with a **redacted** reason (rule + line, never the secret value). Reads content from the real tool-schema keys (`content`, `new_string`, `edits[].new_string`, `new_source`). **Fails open** on every error path (no python3 / no gitleaks / parse error / scanner error) so it can never wedge the session.
- **PreToolUse bash-guard hook** (`hooks/bash-guard-pretooluse.sh`, matcher `Bash`) — denies a deliberately **narrow, near-zero-false-positive** set of catastrophic commands (`rm -rf /`|`~`|`$HOME`, `mkfs`, `dd of=/dev/…`, fork bombs, `curl|wget … | sh`, recursive `chmod 777 /`). Everything else is allowed; fails open.
- **SessionStart preflight hook** (`hooks/preflight-sessionstart.sh`) — reports which core scanner CLIs are installed via `hookSpecificOutput.additionalContext`. Never blocks.
- **`hooks/hooks.json`** wiring the three hooks (shape verified against the official `security-guidance` plugin).
- **`/security-scan` slash command** (`commands/security-scan.md`) — explicit user entry point that invokes the `security-scanner` skill (skills alone are model-invoked only).
- **`userConfig` toggles** — `secret_scan` and `bash_guard` (both default `true`), exported to the hooks as `CLAUDE_PLUGIN_OPTION_SECRET_SCAN` / `CLAUDE_PLUGIN_OPTION_BASH_GUARD`, letting users disable either blocking hook without disabling the whole plugin.
- **Rule-file injection + hidden-Unicode detection** in `config-audit.py` — now scans agent rule/instruction files (`.cursorrules`, `.windsurfrules`, `.clinerules`, `AGENTS.md`, `.github/copilot-instructions.md`, `.cursor/rules/`, `.github/instructions/`) for prompt-injection instructions and invisible/bidi/tag-character injection (the class behind the 2025 Cursor/Copilot rule-file CVEs).
- **SBOM + Sunglasses guidance** in `SKILL.md` — how to emit a CycloneDX software SBOM via Trivy, with AI-BOM (OWASP AIBOM / ML-BOM) marked explicitly as **roadmap, not yet produced**; and Sunglasses documented as an optional **runtime/hook-layer** prompt-injection complement, not a static Step-4 tool.
- **Manifest enrichment** — `plugin.json` gains `$schema` (schemastore, verified 200), `displayName`, `homepage`, and `defaultEnabled: false` (the plugin shells out to 13 external CLIs and adds blocking hooks, so it now **installs disabled** and the user opts in). `marketplace.json` gains a top-level `version`.
- **Six regression tests** in `tests/run-tests.sh` covering hidden-unicode/rule-file detection, hooks.json validity, bash-guard deny/allow/toggle, and secret-scan deny/allow/fail-open.
- **OpenAI Codex CLI support (single source tree)** — the plugin now also installs on Codex CLI (codex-cli 0.144+):
  - `.codex-plugin/plugin.json` (Codex manifest, `interface` block + `skills: "./.claude/skills/"` + `hooks: "./codex/hooks.json"`) and `.agents/plugins/marketplace.json` (Codex marketplace, `source.path: "."` → repo root is the plugin). Verified end-to-end with `codex plugin marketplace add` → `codex plugin add` → `codex plugin list` (installed, enabled) and by running a bundled script from the Codex plugin cache.
  - `codex/hooks.json` maps the guardrails to Codex's `PreToolUse` event (matcher includes `apply_patch`, Codex's edit tool). Codex's deny contract is identical to Claude Code's (`hookSpecificOutput.permissionDecision:"deny"` or exit 2), so the **same `hooks/*.sh` scripts run on both hosts**, reached via the `CLAUDE_PLUGIN_ROOT` alias Codex sets.
  - `secret-scan-pretooluse.sh` now also extracts content from Codex `apply_patch` (`input`/`patch`), with a whole-`tool_input` fallback — verified to block a secret planted in an `apply_patch` body and to allow a clean patch.
  - The `security-analysis` agent and `/security-scan` command stay Claude-only (the skill is the Codex entry point).

### Changed

- **`defaultEnabled: false`** — the plugin no longer auto-enables on install (requires Claude Code v2.1.154+; earlier versions ignore the field and enable on install). Enable with `claude plugin enable claude-code-security-plugins` or the `/plugin` UI.
- **`build-dist.sh`** now packages `hooks/` and `commands/` into the plugin ZIP (executable hook scripts) and ships the agent at the root `agents/` dir.

### Fixed

- **`security-analysis` agent was never discovered** — it shipped under `.claude/agents/` with no `agents` manifest field, so default agent discovery (root `agents/`) never found it, and an explicit `agents` path in `plugin.json` did **not** register it either (verified against `claude plugin details` in current Claude Code). Moved the agent to the canonical root `agents/security-analysis.md` and rely on default discovery; `claude plugin details` now reports it. This was a latent bug in every prior release.

### Notes

- No `marketplace.json` `$schema` was added — the schemastore marketplace-manifest URL 404s (no schema published); a fabricated URL was deliberately avoided.
- No `renames` entry was added — nothing is being renamed; `renames` is the documented mechanism to add *when* a future rename/removal happens.
- `SHA256SUMS` integrity coverage remains scoped to the five bundled **skill** scripts (its documented purpose); hook scripts are not integrity-checked at hook-run time.

## [1.7.1] - 2026-06-14

### Fixed

- **`apts-audit.sh run` corrupted the audit log on zero-finding tools** — the findings-count proxy used `grep -icE ... || echo 0`, but `grep -c` already prints `0` (and exits 1) when there are no matches, so `|| echo 0` appended a second `0`, producing a multi-line value that broke the JSON record (`"findings":0\n0,"measured":true}`). Now uses `| head -1` + integer sanitisation. Regression introduced in v1.7.0; surfaced by a self-scan. (APTS § Auditability)
- **`mcp-exfil-scan.sh` violated scope enforcement** — it unconditionally searched `~/.claude/skills` and the global `~/.claude/settings*.json` regardless of the scan target, so scanning any unrelated project reported the user's own installed skills/MCP servers as findings (out-of-scope, mostly false positives). Global config is now audited only when the scan target IS `~/.claude` (new `AUDIT_GLOBAL` gate). (APTS § Scope Enforcement)

### Added

- Two regression tests in `tests/run-tests.sh` covering both fixes (zero-finding audit record stays valid JSON; mcp-exfil-scan stays within the target).

## [1.7.0] - 2026-06-14

### Added

- **skillspector** — NVIDIA AI-skill scanner added as tool 4l (tools **12 → 13**). Scans `*.skill` / `SKILL.md` / `AGENTS.md` artifacts across 64 patterns in 16 categories (prompt injection, data exfiltration, privilege escalation, supply chain, excessive agency, malicious code). SARIF output, risk score 0–100. Defaults to `--no-llm` (local-only); LLM-assisted mode is **opt-in** behind the same privacy gate as mcp-scan. Conditional — runs only when AI-skill artifacts are present.
- **`scripts/aggregate-findings.py`** *(bundled)* — merges SARIF reports from Gitleaks/Semgrep/Trivy/skillspector, deduplicates secret findings by `(file, line, fingerprint)`, prints a severity rollup, and supports `--fail-on <critical|high|medium|low>` for CI/CD gating (non-zero exit). Deterministic, no network, no LLM.
- **`scripts/SHA256SUMS`** *(bundled)* — integrity / tamper-evidence manifest of all bundled scripts. Pre-flight verifies it with `shasum -c` and refuses to run on mismatch. Detects corruption, partial downloads, and accidental edits — note it is not a defense against a malicious redistributor who regenerates the manifest alongside a tampered script.
- **`apts-audit.sh run`** subcommand — executes a tool and records *measured* exit code, wall-time, and findings count instead of LLM-asserted values (APTS § Auditability integrity). `finalize` now reports measured vs asserted run counts.
- **`build-dist.sh`** — reproducible packaging script that rebuilds both distribution artifacts from source, regenerates `SHA256SUMS`, and hard-excludes `settings.local.json` + `.DS_Store`. Fails the build if local config ever leaks into the ZIP.
- **`tests/`** — regression suite with known-vulnerable fixtures and a runner (`tests/run-tests.sh`) asserting that Bandit, Semgrep, Gitleaks, skill-audit, mcp-exfil-scan, and aggregate-findings all fire.

### Fixed

- **Stale `.skill` distribution** — the shipped `security-scanner.skill` had drifted to a v1.4.0-era build missing `mcp-exfil-scan.sh` and `apts-audit.sh`; users installing it got a broken skill. Now rebuilt from current source.
- **Version drift** — `marketplace.json` was pinned at `1.5.0` while `plugin.json` was `1.6.0`. Both now `1.7.0`.
- **Repository URL drift** — `plugin.json` pointed at `github.com/casedone/...` while README/marketplace used `github.com/mp3wizard/...`. Canonicalised to `mp3wizard`.
- **Local-config leak** — the plugin ZIP bundled `.claude/settings.local.json` (author's absolute home paths + a pre-approved Bash permission allowlist that would merge into any installer's config). Now git-ignored, untracked, and excluded from both artifacts.
- **Fragile `SKILL_DIR` resolution** — replaced the `$0`/`readlink -f` derivation (unreliable under the inline Bash-tool exec model, and `readlink -f` is unsupported on stock macOS) with `${CLAUDE_PLUGIN_ROOT}` + a known-path fallback search.

### Changed

- Semgrep step now discloses files skipped by `--max-target-bytes 300000` (>300 KB) in the report's Coverage Disclosure.
- `plugin.json` / `marketplace.json` bumped to `1.7.0`; descriptions, keywords, and tool counts updated for skillspector.

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
