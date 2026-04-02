---
name: security-scanner
description: >
  Run automated security scanning tools (Bandit, Semgrep, Trivy, TruffleHog) against a codebase
  and return structured findings as markdown for LLM consumption. Use this skill whenever a
  security review requires tool-based scanning — whether invoked by the security-analysis agent
  or directly by the user. Trigger on any request to: run a security scan, check for
  vulnerabilities, scan for secrets, audit dependencies, or perform SAST analysis.
  Also trigger proactively when the security-analysis agent needs automated findings to
  supplement its manual review.
---

# Security Scanner

Runs complementary automated security tools against a target path and assembles a structured markdown report. Include full tool output verbatim — do not truncate or summarize.

## Tools

| Tool | Purpose |
|------|---------|
| Bandit | Python SAST — injection, unsafe deserialization, subprocess, weak crypto |
| Semgrep | Multi-language SAST — OWASP Top 10 + Python rules |
| Trivy | Dependencies, IaC misconfigs, secrets, containers |
| TruffleHog | Secrets in git history with live API verification |
| Gitleaks | Secrets in git history + filesystem |
| CodeQL | Deep semantic SAST via GitHub Actions (GitHub repos only) |
| mcps-audit | MCP skill/tool permission audit |

## Step 1: Scan Target

Use specified path or default to current working directory. Print: `Scan target: <absolute path>`

## Step 2: Pre-flight Tool Check

```bash
for tool in bandit semgrep trivy trufflehog gitleaks; do
  command -v "$tool" &>/dev/null && echo "OK  $tool $($tool --version 2>&1 | head -1)" || echo "MISSING  $tool"
done
command -v gh &>/dev/null && echo "OK  gh (CodeQL available)" || echo "MISSING  gh"
command -v npx &>/dev/null && echo "OK  npx (mcps-audit available)" || echo "MISSING  npx"
```

All found → `All tools ready. Starting scan...` and proceed. Any missing → list them and ask:
"Missing: **[list]**. Skip (noted as gap) or Install?"

Install: `bandit`/`semgrep` via `pip install`; `trivy`/`trufflehog`/`gitleaks` via `brew install`. Re-run pre-flight after install. Install fail → skip tool or abort per user.

## Step 3: Run Each Available Tool

Capture full stdout+stderr. Do not filter or truncate.

**3a-pre. Gitleaks** (run first as early-warning):
```bash
gitleaks detect --source <path> --report-format sarif --report-path gitleaks.sarif --no-banner 2>&1
gitleaks detect --source <path> --no-banner 2>&1
```

**3a. Bandit** — skip if no `.py` files (`find <path> -name "*.py" | head -1`):
```bash
bandit -r <path> -f txt 2>&1
```

**3b. Semgrep** — run each config separately to prevent OOM:
```bash
semgrep scan --metrics=off --disable-version-check \
  --config p/owasp-top-ten \
  --max-memory 1500 --jobs 1 --timeout 20 --timeout-threshold 2 \
  --max-target-bytes 300000 --include "*.py" --include "*.js" --include "*.ts" --include "*.jsx" --include "*.tsx" --include "*.java" --include "*.go" --include "*.rb" <path> 2>&1
```
If the above succeeds and Python files exist, run additionally:
```bash
semgrep scan --metrics=off --disable-version-check \
  --config p/python \
  --max-memory 1500 --jobs 1 --timeout 20 --timeout-threshold 2 \
  --max-target-bytes 300000 --include "*.py" <path> 2>&1
```
If Semgrep exits with code 137 (OOM-killed), note in the report: "Semgrep OOM — Bandit covers Python SAST; re-run on a machine with more RAM for full multi-language coverage."
_(1.5 GB cap; single job; split configs to halve peak memory; skip non-code and files >300 KB)_

**3c. Trivy:**
```bash
trivy fs <path> 2>&1
```

**3d. TruffleHog:**
```bash
git -C <path> rev-parse --git-dir 2>/dev/null \
  && trufflehog git file://<path> --no-update 2>&1 \
  || trufflehog filesystem <path> --no-update 2>&1
```

**3e. CodeQL** (GitHub repos + `gh` CLI only):
```bash
git -C <path> remote get-url origin 2>/dev/null | grep -i "github.com"
```
Check `.github/workflows/` for CodeQL workflow. Present → `gh run list --workflow codeql.yml`. Absent → note gap. Skip if not GitHub, no `gh`, or no internet.

**3f. mcps-audit** (only if MCP files found):
```bash
find <path> -name "*.skill" -o -name "SKILL.md" -o -name "mcp*.json" -o -name ".mcp*" 2>/dev/null | head -5
npx mcps-audit <path> 2>&1
```

## Step 4: Assemble Report

Extract counts from each tool's output, then write this document in one pass.

Report structure:

```
# Automated Security Scan Report
**Target:** `<path>`  **Scanned at:** <ISO 8601>
**Tools run:** <list>  **Tools skipped:** <list with reason, or "none">

## Pre-flight Summary
| Tool | Status | Version / Note |
|------|--------|----------------|
| Gitleaks   | [OK/SKIPPED]     | x.y.z |
| Bandit     | [OK/SKIPPED]     | x.y.z |
| Semgrep    | [OK/SKIPPED]     | x.y.z |
| Trivy      | [OK/SKIPPED]     | x.y.z |
| TruffleHog | [OK/SKIPPED]     | x.y.z |
| CodeQL     | [OK/SKIPPED/N/A] | GitHub Actions / not GH repo |
| mcps-audit | [OK/SKIPPED/N/A] | no MCP files / ran ok |
```

For each tool, include a section:

```
## <Tool> — <Purpose>
**Summary:** <counts> (or "Skipped: <reason>")
[CONFIDENTIAL warning if secrets tool]
<full output verbatim>
```

End with:

```
## Cross-Tool Observations
Issues flagged by multiple tools (higher-confidence signals), or "No cross-tool overlaps detected."

## Coverage Gaps
Categories not covered by tools that ran: business logic, IDOR, skipped-tool gaps, runtime behavior.
```

## Operational Rules

1. Never read `.env`/credential files — note presence only.
2. Never truncate tool output. Redact detected secret values with `[REDACTED]` (keep file path, line, detector type). Never fabricate counts — derive from actual output.
3. Fail loudly on pre-flight — missing tools must be surfaced before scanning begins.
4. TruffleHog live-verified secrets are Critical — flag prominently even if overall tone is mild.
5. Tool crash/non-zero exit → include error output and note "tool exited with error" in summary.
