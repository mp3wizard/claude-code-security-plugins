# security-toolkit

A Claude Code plugin that brings automated security scanning and comprehensive static security review to your development workflow.

It combines seven industry-standard scanning tools with an AI-powered senior AppSec engineer agent that performs deep manual analysis across 12 vulnerability categories — producing actionable, dual-audience reports you can hand to both engineers and stakeholders.

This material is a part of a 15-minute short talk at [Claude Code Thailand Meetup on March 15, 2026](https://www.facebook.com/photo?fbid=1600902880954303&set=gm.2182266732311295&idorvanity=1745892855948687). The link to the presentation slide is [here](https://1drv.ms/b/c/65172434bf16609a/IQAyXUe31nHqSpW0JIrVTDj5AZEbZw5RJ8TCYEUV-bdB_x0?e=KEEBpj).

## Components

| Component | Type | Description |
|-----------|------|-------------|
| `security-scanner` | Skill | Orchestrates Gitleaks, Bandit, Semgrep, Trivy, TruffleHog, CodeQL (GitHub repos), and mcps-audit (MCP projects) to produce a structured scan report |
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
```

- **Optional tools** (conditional — scanner detects and skips gracefully if unavailable):
  - **CodeQL** — GitHub repos only. Requires [`gh` CLI](https://cli.github.com/) authenticated and a CodeQL workflow in `.github/workflows/`
  - **mcps-audit** — MCP projects only. Requires `npx` (`npm install -g npx`)

## Installation

### Quick test (local directory)

```bash
claude --plugin-dir ./claude-code-security-plugins
```

### Permanent install

Pin to a specific release tag to ensure integrity:

```bash
claude plugin install claude-code-security-plugins@1.0.0
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
| Bandit | Python SAST — injection, pickle, subprocess, weak crypto | Python files present |
| Semgrep | Multi-language SAST — OWASP Top 10 + Python-specific rules | Always run |
| Trivy | Dependencies, IaC misconfigs, secrets, container images | Always run |
| TruffleHog | Secrets in git history with live API verification | Always run |
| CodeQL | Deep semantic SAST via GitHub Actions | GitHub repos only |
| mcps-audit | MCP skill/tool permission audit, prompt injection risks | MCP projects only |

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

## License

MIT
