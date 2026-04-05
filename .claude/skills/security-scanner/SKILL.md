---
name: security-scanner
description: >
  Run security scanning tools (Bandit, Semgrep, Trivy, TruffleHog, Gitleaks, OSV-Scanner, mcp-scan)
  against a codebase and return structured markdown findings. Trigger on: security scan, vulnerability check,
  secrets scan, dependency audit, SAST analysis, or when the security-analysis agent needs automated findings.
---

# Security Scanner

Runs automated security tools against a target path and assembles a structured markdown report.

## Tools

| Tool | Purpose |
|------|---------|
| Gitleaks | Secrets in git history + filesystem |
| Bandit | Python SAST — injection, unsafe deserialization, subprocess, weak crypto |
| Semgrep | Multi-language SAST — OWASP Top 10, Python, TypeScript, secrets |
| Trivy | Dependencies, IaC misconfigs, secrets, containers |
| TruffleHog | Secrets in git history with live API verification |
| CodeQL | Deep semantic SAST via GitHub Actions (GitHub repos only) |
| mcps-audit | MCP skill/tool permission audit |
| OSV-Scanner | SCA — dependency vulnerabilities via OSV.dev |
| mcp-scan | [OPT-IN] MCP tool poisoning, prompt injection, rug pulls (→ invariantlabs.ai API) |

## Step 1: Scan Target

Default to cwd. Print: `Scan target: <absolute path>`

## Step 2: Pre-flight Tool Check

```bash
for tool in bandit semgrep trivy trufflehog gitleaks osv-scanner; do
  command -v "$tool" &>/dev/null && echo "OK  $tool $($tool --version 2>&1 | head -1)" || echo "MISSING  $tool"
done
command -v gh &>/dev/null && echo "OK  gh (CodeQL available)" || echo "MISSING  gh"
command -v npx &>/dev/null && echo "OK  npx (mcps-audit available)" || echo "MISSING  npx"
command -v uvx &>/dev/null && echo "OK  uvx (mcp-scan available — opt-in only)" || echo "MISSING  uvx (mcp-scan — optional, opt-in)"
```

**Trivy supply chain check** — run after pre-flight loop:
```bash
trivy_ver=$(trivy --version 2>&1 | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1)
case "$trivy_ver" in 0.69.4|0.69.5|0.69.6)
  echo "⚠️ WARNING: Trivy $trivy_ver COMPROMISED (supply chain attack GHSA-69fq-xp46-6x23, Mar 2026). Downgrade to v0.69.3 or upgrade to v0.69.7+."
  ;; esac
```

All found → proceed. Any missing → list and ask: "Missing: **[list]**. Skip (noted as gap) or Install?"

Install: pip (bandit, semgrep); brew (trivy, trufflehog, gitleaks, osv-scanner); uvx (mcp-scan, no install needed). Re-run pre-flight. Fail → skip or abort.

## Step 3: Run Each Available Tool

**3a-pre. Gitleaks** (run first as early-warning):
```bash
gitleaks detect --source <path> --report-format sarif --report-path gitleaks.sarif --no-banner 2>&1
gitleaks detect --source <path> --no-banner 2>&1
```

**3a. Bandit** — skip if no `.py` files (`find <path> -name "*.py" | head -1`):
```bash
bandit -r <path> -f txt 2>&1
```

**3b. Semgrep** — define common flags, run each config separately to prevent OOM:
```bash
SG="semgrep scan --metrics=off --disable-version-check --max-memory 1500 --jobs 1 --timeout 20 --timeout-threshold 2 --max-target-bytes 300000"
```

OWASP Top 10 (always):
```bash
$SG --config p/owasp-top-ten --include "*.py" --include "*.js" --include "*.ts" --include "*.jsx" --include "*.tsx" --include "*.java" --include "*.go" --include "*.rb" <path> 2>&1
```

Python (if `.py` files exist):
```bash
$SG --config p/python --include "*.py" <path> 2>&1
```

TypeScript (if `.ts`/`.tsx` files exist):
```bash
$SG --config p/typescript --include "*.ts" --include "*.tsx" <path> 2>&1
```

Secrets (always):
```bash
$SG --config p/secrets <path> 2>&1
```

If Semgrep exits 137 (OOM): note "Semgrep OOM — re-run on a machine with more RAM for full coverage."
_(1.5 GB cap; single job; split 4 configs to reduce peak memory; skip files >300 KB)_

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

**3g. OSV-Scanner** — SCA dependency scan:
```bash
osv-scanner scan source -r <path> 2>&1
```
If lockfiles present (`find <path> -name "package-lock.json" -o -name "yarn.lock" -o -name "pnpm-lock.yaml" -o -name "poetry.lock" -o -name "go.sum" -o -name "Cargo.lock" | head -1`), also scan:
```bash
osv-scanner scan -L <lockfile> 2>&1
```

**3h. mcp-scan [OPT-IN]** — MCP tool poisoning & prompt injection:
⚠️ **Privacy:** mcp-scan sends MCP tool descriptions to invariantlabs.ai for analysis. **ASK the user before running — never run by default.**

If user consents:
```bash
uvx mcp-scan@latest 2>&1
```
Local-only inspection (no API call):
```bash
uvx mcp-scan@latest inspect 2>&1
```

## Step 4: Assemble Report

Extract counts from each tool's output, then write in one pass:

```
# Automated Security Scan Report
**Target:** `<path>`  **Scanned at:** <ISO 8601>
**Tools run:** <list>  **Tools skipped:** <list with reason, or "none">

## Pre-flight Summary
| Tool | Status | Version / Note |
|------|--------|----------------|
```
One row per tool from Tools table above. Status: OK / SKIPPED / N/A / OPT-IN. Include version or skip reason.

For each tool that ran:
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
6. mcp-scan is opt-in only. Always ask the user before running. Include privacy warning in output.
