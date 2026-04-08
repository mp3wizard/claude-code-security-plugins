# security-toolkit

A Claude Code plugin that brings automated security scanning and comprehensive static security review to your development workflow.

It combines **12 scanning tools** with an AI-powered senior AppSec engineer agent that performs deep manual analysis across 12 vulnerability categories — producing actionable, dual-audience reports you can hand to both engineers and stakeholders.

This material is a part of a 15-minute short talk at [Claude Code Thailand Meetup on March 15, 2026](https://www.facebook.com/photo?fbid=1600902880954303&set=gm.2182266732311295&idorvanity=1745892855948687). The link to the presentation slide is [here](https://1drv.ms/b/c/65172434bf16609a/IQAyXUe31nHqSpW0JIrVTDj5AZEbZw5RJ8TCYEUV-bdB_x0?e=KEEBpj).

## Components

| Component | Type | Description |
|-----------|------|-------------|
| `security-scanner` | Skill | Orchestrates Gitleaks, Bandit, Semgrep, Trivy, TruffleHog, CodeQL (GitHub repos), mcps-audit (MCP projects), OSV-Scanner (SCA), mcp-scan (opt-in MCP security), security-audit (Claude config audit), skill-security-auditor (skill/MCP deep analysis), and mcp-exfil-scan (MCP data exfiltration detection) to produce a structured scan report |
| `security-analysis` | Agent | Senior AppSec engineer that runs the scanner, then performs deep manual review across 12 vulnerability categories |

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
  - **security-audit**, **skill-security-auditor**, and **mcp-exfil-scan** — **bundled inside the `.skill` file**. No separate installation required.
  - **jq** — JSON parser used by mcp-exfil-scan. Optional — falls back to `python3` if unavailable. Install: `brew install jq`

## Installation

> **What's bundled:** `security-audit` and `skill-security-auditor` scripts are packed inside both distribution files — no extra `git clone` required.

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

Includes: `security-scanner` skill + `security-analysis` agent + bundled audit scripts (`scripts/config-audit.py`, `scripts/skill-audit.sh`, `scripts/mcp-exfil-scan.sh`).

**Plugin structure inside ZIP:**
```
claude-code-security-plugins/
├── .claude/
│   ├── skills/security-scanner/
│   │   ├── SKILL.md
│   │   ├── scripts/
│   │   │   ├── config-audit.py     # Claude config audit (bundled)
│   │   │   ├── skill-audit.sh      # Skill/MCP deep analysis (bundled)
│   │   │   └── mcp-exfil-scan.sh   # MCP exfiltration detection (bundled)
│   │   └── reports/
│   └── agents/security-analysis.md
└── .claude-plugin/
    ├── plugin.json
    └── marketplace.json
```

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
claude plugin install claude-code-security-plugins@1.5.0
```

> **Security note:** Always install from a tagged release rather than HEAD. Check the [CHANGELOG](CHANGELOG.md) before upgrading.

## Usage

### Run the automated scanner only

```
/claude-code-security-plugins:security-scanner
```

Runs all available tools against your codebase and produces a structured markdown report with findings, cross-tool observations, and coverage gaps.

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

## Prompt Optimization

Each release applies a prompt optimization pass — adding features while keeping token count as low as possible.

### Line count history

| File | v1.0.0 | v1.1.0 | v1.3.0 | v1.4.0 | v1.5.0 |
|------|--------|--------|--------|--------|--------|
| `.claude/skills/security-scanner/SKILL.md` | 348 lines | 145 lines | 179 lines | 202 lines | 169 lines |
| `.claude/agents/security-analysis.md` | 142 lines | 112 lines | 112 lines | 112 lines | 86 lines |
| `scripts/config-audit.py` *(bundled)* | — | — | — | 14.7 KB | 14.7 KB |
| `scripts/skill-audit.sh` *(bundled)* | — | — | — | 14.8 KB | 14.8 KB |
| `scripts/mcp-exfil-scan.sh` *(bundled)* | — | — | — | — | 25.9 KB |

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
