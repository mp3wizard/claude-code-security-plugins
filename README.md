# security-toolkit

A Claude Code plugin that brings automated security scanning and comprehensive static security review to your development workflow.

It combines **13 scanning tools** with an AI-powered senior AppSec engineer agent that performs deep manual analysis across 12 vulnerability categories — producing actionable, dual-audience reports you can hand to both engineers and stakeholders.

This material is a part of a 15-minute short talk at [Claude Code Thailand Meetup on March 15, 2026](https://www.facebook.com/photo?fbid=1600902880954303&set=gm.2182266732311295&idorvanity=1745892855948687). The link to the presentation slide is [here](https://1drv.ms/b/c/65172434bf16609a/IQAyXUe31nHqSpW0JIrVTDj5AZEbZw5RJ8TCYEUV-bdB_x0?e=KEEBpj).

## Components

| Component | Type | Description |
|-----------|------|-------------|
| `security-scanner` | Skill | Orchestrates Gitleaks, Bandit, Semgrep, Trivy, TruffleHog, CodeQL (GitHub repos), mcps-audit (MCP projects), OSV-Scanner (SCA), mcp-scan (opt-in MCP security), security-audit (Claude config + **rule-file injection / hidden-Unicode** audit), skill-security-auditor (skill/MCP deep analysis), mcp-exfil-scan (MCP data exfiltration detection), and skillspector (NVIDIA AI-skill scanner) to produce a structured scan report |
| `security-analysis` | Agent | Senior AppSec engineer that runs the scanner, then performs deep manual review across 12 vulnerability categories |
| `/security-scan` | Command | Explicit slash-command entry point that runs the `security-scanner` skill against a path (defaults to cwd) |
| secret-scan hook | Hook (PreToolUse) | Runs Gitleaks on pending `Write`/`Edit`/`MultiEdit` content and **blocks** the write if a hardcoded secret is detected. Fails open. Toggle: `secret_scan` |
| bash-guard hook | Hook (PreToolUse) | Blocks a narrow set of catastrophic Bash commands (`rm -rf /`, `mkfs`, `dd` to a raw device, fork bombs, pipe-to-shell). Fails open. Toggle: `bash_guard` |
| preflight hook | Hook (SessionStart) | Reports which core scanner CLIs are installed. Never blocks |

## Prerequisites

- **Claude Code** v1.0.33+
- **Security tools** (the scanner will check for these and offer to install any that are missing):

```bash
# Python SAST
pip install bandit

# Multi-language SAST
pip install semgrep

# Dependency & IaC scanner
brew install trivy

# Secret detection (git history + filesystem)
brew install trufflehog

# Secret detection (pre-commit friendly, SARIF output)
brew install gitleaks

# SCA / dependency vulnerability scanner
brew install osv-scanner

# ⚠️ Trivy v0.69.4–v0.69.6 were compromised (GHSA-69fq-xp46-6x23). Use v0.69.3 or v0.69.7+.
```

- **Optional tools** (conditional — scanner detects and skips gracefully if unavailable):
  - **CodeQL** — GitHub repos only. Requires [`gh` CLI](https://cli.github.com/) authenticated and a CodeQL workflow in `.github/workflows/`
  - **mcps-audit** — MCP projects only. Requires `npx` (`npm install -g npx`)
  - **mcp-scan** — MCP security analysis. Requires `uvx` (`pip install uv` or `brew install uv`). **Opt-in only** — sends data to invariantlabs.ai API. Scanner always asks before running.
  - **skillspector** — NVIDIA AI-skill scanner (64 patterns / 16 categories, SARIF output, risk score 0–100). Runs only when AI-skill artifacts (`*.skill`, `SKILL.md`, `AGENTS.md`) are present. Install: `git clone https://github.com/NVIDIA/skillspector && cd skillspector && uv venv .venv && . .venv/bin/activate && make install` (or `make docker-build`). Note: a venv install only exposes `skillspector` on `PATH` while the venv is active — activate it (or symlink the binary) before scanning, or the pre-flight reports it missing. Defaults to `--no-llm` (local-only); **LLM-assisted mode is opt-in** and the scanner asks first, same privacy gate as mcp-scan.
  - **security-audit**, **skill-security-auditor**, and **mcp-exfil-scan** — **bundled inside the `.skill` file**. No separate installation required.
  - **jq** — JSON parser used by mcp-exfil-scan. Optional — falls back to `python3` if unavailable. Install: `brew install jq`

## Installation

> **What's bundled:** `security-audit` and `skill-security-auditor` scripts are packed inside both distribution files — no extra `git clone` required.

> **⚠️ Installs disabled (v1.8.0+):** this plugin sets `defaultEnabled: false` — it shells out to external CLIs and adds blocking PreToolUse hooks, so it does **not** auto-enable on install. Turn it on with `claude plugin enable claude-code-security-plugins` (or the `/plugin` UI). Requires Claude Code **v2.1.154+** for `defaultEnabled` and the guardrail hooks; older versions ignore the field and enable on install. Disable either hook without disabling the plugin via the `secret_scan` / `bash_guard` config options.

### Option 1 — Plugin ZIP (skill + agent, recommended)

Download `claude-code-security-plugins.zip` from the [Releases](https://github.com/mp3wizard/claude-code-security-plugins/releases) page, then:

```bash
# Extract
unzip claude-code-security-plugins.zip

# Quick test — one-time session, no permanent install
claude --plugin-dir ./claude-code-security-plugins

# Permanent install
claude plugin install ./claude-code-security-plugins
```

Includes: `security-scanner` skill + `security-analysis` agent + `/security-scan` command + guardrail hooks (`hooks/`) + bundled audit scripts (`scripts/config-audit.py`, `scripts/skill-audit.sh`, `scripts/mcp-exfil-scan.sh`).

**Plugin structure inside ZIP:**
```
claude-code-security-plugins/
├── .claude/
│   ├── skills/security-scanner/
│   │   ├── SKILL.md
│   │   ├── scripts/
│   │   │   ├── config-audit.py       # Claude config audit (bundled)
│   │   │   ├── skill-audit.sh        # Skill/MCP deep analysis (bundled)
│   │   │   ├── mcp-exfil-scan.sh     # MCP exfiltration detection (bundled)
│   │   │   ├── apts-audit.sh         # APTS measured audit log (bundled)
│   │   │   ├── aggregate-findings.py # SARIF merge + dedup + CI gate (bundled)
│   │   │   └── SHA256SUMS            # integrity manifest, verified at pre-flight
│   │   └── reports/
├── agents/security-analysis.md
├── hooks/
│   ├── hooks.json
│   ├── preflight-sessionstart.sh   # SessionStart: report installed CLIs
│   ├── secret-scan-pretooluse.sh   # PreToolUse: block secret-leaking writes
│   └── bash-guard-pretooluse.sh    # PreToolUse: block catastrophic commands
├── commands/
│   └── security-scan.md            # /security-scan entry point
└── .claude-plugin/
    ├── plugin.json
    └── marketplace.json
```

> Both artifacts are produced by [`build-dist.sh`](build-dist.sh) so they never drift from source. It regenerates `SHA256SUMS`, rebuilds both the `.skill` and the plugin `.zip`, and hard-excludes `settings.local.json` and `.DS_Store`. Regression tests live in [`tests/`](tests/) — run `bash tests/run-tests.sh` to confirm the scanners fire against the known-vulnerable fixtures.

### Option 2 — Skill only (.skill file)

Download `security-scanner.skill` from the [Releases](https://github.com/mp3wizard/claude-code-security-plugins/releases) page, then:

**Double-click** `security-scanner.skill` — Claude Code will install it automatically.

Or via terminal:

```bash
claude plugin install ./security-scanner.skill
```

Includes bundled audit scripts. Does **not** include the `security-analysis` agent.

### Option 3 — Install from GitHub

Pin to a specific release tag to ensure integrity:

```bash
claude plugin install claude-code-security-plugins@1.7.0
```

> **Security note:** Always install from a tagged release rather than HEAD. Check the [CHANGELOG](CHANGELOG.md) before upgrading.

### Option 4 — Install on OpenAI Codex CLI

The same source tree installs on **Codex CLI** (codex-cli 0.144+). Codex reads the `.codex-plugin/plugin.json` manifest and the `.agents/plugins/marketplace.json` marketplace at the repo root; the `security-scanner` skill and its scripts are shared verbatim with the Claude Code build.

```bash
# From GitHub (Codex clones the repo and reads .agents/plugins/marketplace.json):
codex plugin marketplace add https://github.com/mp3wizard/claude-code-security-plugins
# …or from a local clone:
codex plugin marketplace add /path/to/claude-code-security-plugins

codex plugin add claude-code-security-plugins@casedone-security
codex plugin list        # → installed, enabled
```

**What maps across:**

| Component | Claude Code | Codex |
|-----------|-------------|-------|
| `security-scanner` skill + scripts | `.claude/skills/` (shared) | same dir, discovered via `.codex-plugin` `skills` |
| Guardrail hooks | `hooks/hooks.json` (`PreToolUse`) | `codex/hooks.json` (`PreToolUse`, matcher includes `apply_patch`) — same scripts, identical `permissionDecision:"deny"` contract, reached via the `CLAUDE_PLUGIN_ROOT` alias Codex sets |
| `security-analysis` agent, `/security-scan` command | yes | Claude-only (the skill is the Codex entry point) |

**Codex notes:**
- **Hook trust:** Codex requires plugin hooks to be *trusted* on first use before they run (or `--dangerously-bypass-hook-trust` for vetted automation). The three hooks fail open, same as on Claude Code.
- **Remove any older standalone skill** at `~/.codex/skills/security-scanner/` first — it will otherwise shadow/duplicate the plugin's skill.
- The Codex local-marketplace source copies the whole repo into its cache (including `tests/`); only `./.claude/skills/` is scanned for skills, so the test fixtures never load as skills.

## Usage

### Run the automated scanner only

```
/claude-code-security-plugins:security-scanner
```

Runs all available tools against your codebase and produces a structured markdown report with findings, cross-tool observations, and coverage gaps.

Or use the slash command (defaults to the current directory; pass a path to scope it):

```
/security-scan
/security-scan ./services/api
```

### Guardrail hooks (opt-in, active while the plugin is enabled)

The plugin registers three hooks (all **fail open** — a missing tool or scanner error never wedges the session):

- **secret-scan** (`PreToolUse` on `Write`/`Edit`/`MultiEdit`/`NotebookEdit`) — scans pending content with Gitleaks and **blocks** the write if it introduces a hardcoded secret. Disable with the `secret_scan` config option.
- **bash-guard** (`PreToolUse` on `Bash`) — blocks a narrow, near-zero-false-positive set of catastrophic commands (`rm -rf /`|`~`, `mkfs`, `dd of=/dev/…`, fork bombs, `curl|wget … | sh`). Disable with the `bash_guard` config option.
- **preflight** (`SessionStart`) — reports which core scanner CLIs are installed.

### Run a full security review

Ask Claude naturally:

```
"Run a security review of this codebase"
"We're preparing to deploy v2.0 — can you do a security review first?"
"I just merged the auth branch, please review for vulnerabilities"
```

The `security-analysis` agent will automatically:
1. Run the automated scanner (Phase 0)
2. Perform codebase reconnaissance (Phase 1)
3. Analyze 12 vulnerability categories with manual review (Phase 2)
4. Document findings with structured fields (Phase 3)
5. Produce a dual-audience report with executive summary and engineering findings (Phase 4)

### Direct agent invocation

Use `/agents` to see available agents and launch `claude-code-security-plugins:security-analysis` directly.

## What gets scanned

### Automated tools

| Tool | Coverage | Condition |
|------|----------|-----------|
| Gitleaks | Secrets in git history + filesystem, SARIF output | Always run (pre-check) |
| Bandit | Python SAST — injection, unsafe deserialization, subprocess, weak crypto | Python files present |
| Semgrep | Multi-language SAST — OWASP Top 10, Python, TypeScript, secrets (4 configs) | Always run |
| Trivy | Dependencies, IaC misconfigs, secrets, container images | Always run |
| TruffleHog | Secrets in git history with live API verification | Always run |
| CodeQL | Deep semantic SAST via GitHub Actions | GitHub repos only |
| mcps-audit | MCP skill/tool permission audit, prompt injection risks | MCP projects only |
| OSV-Scanner | SCA — dependency vulnerabilities via OSV.dev database | Always run |
| mcp-scan | MCP tool poisoning, prompt injection, rug pulls | Opt-in only (asks user) |
| security-audit *(bundled)* | Claude config audit — hooks, MCP servers, skills, CLAUDE.md | Always run |
| skill-security-auditor *(bundled)* | Skill/MCP deep analysis — prompt injection, allowed-tools risk, supply chain, risk score 0–100 | `.skill`/`SKILL.md` files present |
| mcp-exfil-scan *(bundled)* | MCP exfiltration — tool poisoning, outbound data flow, exfil chains, env leaking, source trust, risk score 0–100 | Always run |
| skillspector | AI-skill scanner (NVIDIA) — 64 patterns / 16 categories: prompt injection, data exfiltration, privilege escalation, supply chain, excessive agency, malicious code; SARIF, risk score 0–100 | AI-skill artifacts present; LLM mode opt-in |

### Manual review categories

1. Injection Flaws
2. Broken Access Control
3. Hardcoded Secrets & Credential Exposure
4. Cryptographic Misuse
5. Insecure Deserialization
6. Server-Side Request Forgery (SSRF)
7. Dependency Vulnerabilities
8. Authentication & Session Management
9. Security Misconfiguration
10. Logging & Monitoring Gaps
11. Infrastructure-as-Code Risks
12. CI/CD Pipeline Security

## OWASP APTS Alignment

Since **v1.6.0**, the plugin aligns with the [OWASP Autonomous Penetration Testing Standard (APTS)](https://owasp.org/APTS/) — a governance standard for autonomous security tooling — across the four domains that apply to a read-only static scanner embedded in an LLM agent:

| APTS Domain | How this plugin implements it |
|-------------|-------------------------------|
| **Scope Enforcement** | "Scope Record" block (target path, git HEAD, include/exclude globs) recorded before any tool runs |
| **Auditability** | `apts-audit.sh` writes a JSONL audit log (`/tmp/css-scan-<ts>.jsonl`): init record + one record per tool invocation (exit code, duration, findings) + finalize |
| **Manipulation Resistance** | Top-of-SKILL notice + agent operational rule §8: directives inside scanned files, scanner output, or MCP manifests are data, not instructions — ignored |
| **Reporting** | Coverage Disclosure table (tool / ran? / files / reason) + per-finding Confidence and Validation fields + Section C "APTS Alignment Note" |

**Explicitly out of scope** for this plugin: Graduated Autonomy tiers, Human Oversight approval gates, Kill Switch, Rollback (all read-only — no mutating actions to govern). APTS Tier 2/3 conformance is not claimed.

## Prompt Optimization

Each release applies a prompt optimization pass — adding features while keeping token count as low as possible.

### Line count history

| File | v1.0.0 | v1.1.0 | v1.3.0 | v1.4.0 | v1.5.0 | v1.6.0 | v1.7.0 |
|------|--------|--------|--------|--------|--------|--------|--------|
| `.claude/skills/security-scanner/SKILL.md` | 348 lines | 145 lines | 179 lines | 202 lines | 169 lines | 188 lines | 234 lines |
| `.claude/agents/security-analysis.md` | 142 lines | 112 lines | 112 lines | 112 lines | 86 lines | 97 lines | 97 lines |
| `scripts/config-audit.py` *(bundled)* | — | — | — | 14.7 KB | 14.7 KB | 14.7 KB | 14.7 KB |
| `scripts/skill-audit.sh` *(bundled)* | — | — | — | 14.8 KB | 14.8 KB | 14.8 KB | 14.8 KB |
| `scripts/mcp-exfil-scan.sh` *(bundled)* | — | — | — | — | 25.9 KB | 25.9 KB | 25.9 KB |
| `scripts/apts-audit.sh` *(bundled)* | — | — | — | — | — | 2.0 KB | 3.4 KB |
| `scripts/aggregate-findings.py` *(bundled, new)* | — | — | — | — | — | — | 7.6 KB |

### v1.7.1 — self-scan bug fixes (audit-log integrity, scope enforcement)

Patch release fixing two bugs the v1.7.0 scanner surfaced when run against this repo's own routine projects:

| Fix | Detail |
|---|---|
| `apts-audit.sh run` audit-log corruption | Zero-finding tools wrote a malformed JSON record (`grep -c \|\| echo 0` emitted two values). Now sanitised to a single integer — restores APTS § Auditability. v1.7.0 regression. |
| `mcp-exfil-scan.sh` scope violation | Always searched global `~/.claude/skills` + settings regardless of target, flagging the user's own installed skills as out-of-scope findings. Global config now audited only when the target IS `~/.claude` (APTS § Scope Enforcement). |
| Regression tests | Added to `tests/run-tests.sh` for both fixes. |

### v1.7.0 — skillspector (AI-skill scanner), measured audit log, SARIF aggregation, release-integrity fixes

Tools **12 → 13** (added NVIDIA **skillspector**), plus a round of correctness and release-engineering fixes.

| What changed | Detail |
|---|---|
| **skillspector** integration | NVIDIA AI-skill scanner added as tool 4l — runs when AI-skill artifacts are present; 64 patterns / 16 categories; SARIF output; LLM mode opt-in (defaults to `--no-llm`, same privacy gate as mcp-scan) |
| Bundled `scripts/aggregate-findings.py` | Merges SARIF from Gitleaks/Semgrep/Trivy/skillspector, **deduplicates secrets** by `(file, line, fingerprint)`, prints a severity rollup, and supports **`--fail-on <level>` CI/CD gating** (non-zero exit) |
| Measured audit log | `apts-audit.sh run <tool> <log> -- <cmd>` now executes the tool and records **measured** exit code, wall-time, and findings count — replacing LLM-asserted values (APTS § Auditability integrity). `finalize` reports measured vs asserted counts |
| Bundled-script integrity | `scripts/SHA256SUMS` manifest + pre-flight `shasum -c` verification — refuses to run on checksum mismatch (tamper-evidence: catches corruption / accidental edits; not a defense against a redistributor who regenerates the manifest) |
| Robust `SKILL_DIR` resolution | Replaced the unreliable `$0`/`readlink -f` derivation with `${CLAUDE_PLUGIN_ROOT}` + known-path fallback search (the inline-Bash exec model makes `$0` the shell, not the skill path) |
| Large-file coverage disclosure | Semgrep's `--max-target-bytes 300000` silently skips files >300 KB — the report now lists them |
| **Fixed: stale `.skill` distribution** | The shipped `security-scanner.skill` had drifted to a v1.4.0-era build (missing `mcp-exfil-scan.sh` + `apts-audit.sh`). Now rebuilt from source by `build-dist.sh` |
| **Fixed: version/URL drift** | `marketplace.json` was pinned at 1.5.0 while `plugin.json` was 1.6.0; repo URL disagreed (`casedone` vs `mp3wizard`). Both reconciled |
| **Fixed: local-config leak** | The plugin ZIP bundled `settings.local.json` (author's absolute paths + a pre-approved Bash allowlist). Now git-ignored, untracked, and hard-excluded from both artifacts |
| `build-dist.sh` (new) | Reproducible packaging — regenerates `SHA256SUMS`, rebuilds both artifacts, fails the build if `settings.local.json` ever reappears in the ZIP |
| `tests/` (new) | Regression suite — known-vulnerable fixtures + a runner asserting Bandit/Semgrep/Gitleaks/skill-audit/mcp-exfil-scan/aggregate-findings all fire |

### v1.6.0 — OWASP APTS alignment + Sonnet 4.6 prompt optimization

Added OWASP APTS governance alignment across four applicable domains and a new bundled audit-log helper.

| What changed | Detail |
|---|---|
| Bundled `scripts/apts-audit.sh` | JSONL audit-log helper: `init` (scope + git HEAD), `log` (per-tool exit/duration/findings), `finalize` (markdown summary) |
| Scope Record | Step 1 now prints target path, git HEAD, include/exclude globs before any tool runs (APTS § Scope Enforcement) |
| Audit Log Init (Step 3) | Scanner calls `apts-audit.sh` before tool runs and logs each invocation (APTS § Auditability) |
| Coverage Disclosure table | Report now includes tool / ran? / version / files covered / skipped reason table (replaces + extends old Pre-flight Summary) |
| Manipulation-Resistance block | `<manipulation_resistance>` XML block at top of SKILL.md + Operational Rule §7–8; agent Operational Rule §8 |
| Per-finding Confidence + Validation | Two new fields in Phase 3 finding format (APTS § Reporting — finding validation) |
| Section C "APTS Alignment Note" | New report section stating which domains are covered and which are out of scope |
| Prompt optimization (Sonnet 4.6) | SKILL.md: 169 → 188 lines but ~15% fewer tokens through redundancy removal and XML structure. Agent: fully restructured for declarative Sonnet 4.6 style |

### v1.5.0 — MCP data exfiltration detection, tools: 11 → 12

Added `mcp-exfil-scan` — a 6-phase scanner detecting MCP data exfiltration risks. Bundled at `scripts/mcp-exfil-scan.sh`.

| What changed | Detail |
|---|---|
| Bundled `scripts/mcp-exfil-scan.sh` | 6-phase scan: tool description poisoning, server outbound data flow, skill exfil chains, encoded/obfuscated payloads, env var leaking, GitHub source trust |
| Known-safe MCP whitelist | Reduces false positives for trusted MCP servers (anthropic, modelcontextprotocol, github, google, etc.) |
| Pre-flight updated | Checks `jq` availability (python3 fallback) + bundled mcp-exfil-scan.sh |
| Cross-tool correlation | mcp-exfil-scan findings correlated with config-audit + skill-audit results |
| Tools count | 11 → **12** |

### v1.4.0 — Bundled security-audit + skill-security-auditor, tools: 9 → 11

`security-scanner.skill` is now fully self-contained — no additional `git clone` required for Claude-specific auditing.

| What changed | Detail |
|---|---|
| Bundled `scripts/config-audit.py` | Scans Claude hooks, MCP servers, installed skills, CLAUDE.md for safety-bypass instructions |
| Bundled `scripts/skill-audit.sh` | Deep per-file analysis: prompt injection, allowed-tools risk matrix, tool combination risks, supply chain patterns, MCP vectors, risk score 0–100 |
| Pre-flight updated | Checks bundled scripts via `<skill-directory>` relative path — no external dependency |
| `.skill` structure | Added `scripts/` and `reports/` directories inside ZIP |
| Tools count | 9 → **11** |

### v1.3.0 — Added 2 tools + 2 Semgrep configs, net +13% words (vs +31% naive)

SKILL.md added OSV-Scanner, mcp-scan, Semgrep `p/typescript` + `p/secrets`, and a Trivy supply chain warning. Simultaneous optimizations kept growth to ~13% instead of ~31% a naive addition would have produced.

| Optimization | Savings |
|---|---|
| `$SG` variable for Semgrep — define 7 common flags once, reuse across 4 configs | ~45 words |
| Report template compaction — generation instruction replaces 9 literal table rows | ~35 words |
| Frontmatter description tightened — removed redundant trigger prose | ~32 words |
| Step 3 intro + intro sentence removed (both covered by Operational Rule #2) | ~27 words |
| Install note condensed | ~18 words |
| **Total optimization savings vs naive addition** | **~157 words** |

### v1.1.0 — Reduced 348→145 lines (−58%) with full functionality preserved

| Section | Before | After |
|---------|--------|-------|
| Pre-flight bash block | Verbose if/else block (18 lines) | Single for-loop (7 lines) |
| Missing tools prompt | Multi-line prose quote block | One-liner ask |
| Install instructions | Expanded table + explanations | Compact inline note |
| Step headers | `---` separators + prose | Inline bold labels |
| Report template | Repeated "insert output here" prose | Single compact template |

`security-analysis.md` v1.1.0 changes:

| Section | Before | After |
|---------|--------|-------|
| Persona | 2-sentence verbose intro | 1-sentence summary |
| Phase 0 | 4 sentences + redundant explanation | 1 sentence |
| Phase 1 labels | "Framework & Stack Identification" etc. | "Stack", "Entry Points" etc. |
| Vulnerability categories | Long comma lists with "Look for…" | Tight 1-liners |
| Detection Source field | 9-item enumerated list | `Automated (<tool>) / Manual / Both` |
| Severity definitions | Full prose per level | Compact bullet per level |
| Memory section | 10 lines with examples | 2-line summary |

## License

MIT
