---
name: security-scanner
description: >
  Run 12 security tools (Bandit, Semgrep, Trivy, TruffleHog, Gitleaks, OSV-Scanner, mcp-scan,
  security-audit, skill-security-auditor, mcp-exfil-scan) against a codebase; return structured markdown.
  Trigger: security scan, vuln check, secrets scan, dependency audit, SAST, Claude config audit,
  skill security check, MCP exfiltration detection, data leakage scan.
---

# Security Scanner

Scan target path with available tools → assemble structured markdown report.

## Tools

| Tool | Purpose |
|------|---------|
| Gitleaks | Secrets in git history + filesystem |
| Bandit | Python SAST |
| Semgrep | Multi-lang SAST — OWASP Top 10, Python, TypeScript, secrets |
| Trivy | Deps, IaC misconfigs, secrets, containers |
| TruffleHog | Secrets with live API verification |
| CodeQL | Semantic SAST via GitHub Actions |
| mcps-audit | MCP permission audit |
| OSV-Scanner | SCA via OSV.dev |
| mcp-scan | [OPT-IN] MCP tool poisoning, prompt injection (→ invariantlabs.ai) |
| security-audit | Claude config — hooks, MCP servers, skills, CLAUDE.md |
| skill-security-auditor | Skill/MCP — prompt injection, tool risk, supply chain, score 0–100 |
| mcp-exfil-scan | MCP exfiltration — tool poisoning, outbound flow, exfil chains, env leak, source trust |

## Step 1: Scan Target

Default to cwd. Print: `Scan target: <absolute path>`

## Step 2: Pre-flight Tool Check

```bash
for tool in bandit semgrep trivy trufflehog gitleaks osv-scanner; do
  command -v "$tool" &>/dev/null && echo "OK  $tool $($tool --version 2>&1 | head -1)" || echo "MISSING  $tool"
done
command -v gh &>/dev/null && echo "OK  gh (CodeQL)" || echo "MISSING  gh"
command -v npx &>/dev/null && echo "OK  npx (mcps-audit)" || echo "MISSING  npx"
command -v uvx &>/dev/null && echo "OK  uvx (mcp-scan — opt-in)" || echo "MISSING  uvx"
command -v jq &>/dev/null && echo "OK  jq" || echo "INFO  jq missing (mcp-exfil-scan uses python3 fallback)"
SKILL_DIR="$(dirname "$(readlink -f "$0" 2>/dev/null || echo "$0")")"
for s in config-audit.py skill-audit.sh mcp-exfil-scan.sh; do
  [ -f "$SKILL_DIR/scripts/$s" ] && echo "OK  $s (bundled)" || echo "MISSING  $s"
done
```

**Trivy supply chain check** — after pre-flight:
```bash
trivy_ver=$(trivy --version 2>&1 | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1)
case "$trivy_ver" in 0.69.4|0.69.5|0.69.6)
  echo "⚠️ WARNING: Trivy $trivy_ver COMPROMISED (GHSA-69fq-xp46-6x23). Use v0.69.3 or v0.69.7+."
  ;; esac
```

All found → proceed. Missing → ask: "Missing: **[list]**. Skip or Install?"
Install: pip (bandit, semgrep); brew (trivy, trufflehog, gitleaks, osv-scanner); uvx (mcp-scan). Re-run pre-flight.

## Step 3: Run Each Available Tool

**3a-pre. Gitleaks** (early-warning):
```bash
gitleaks detect --source <path> --report-format sarif --report-path gitleaks.sarif --no-banner 2>&1
gitleaks detect --source <path> --no-banner 2>&1
```

**3a. Bandit** — skip if no `.py` files:
```bash
bandit -r <path> -f txt 2>&1
```

**3b. Semgrep** — common flags in `$SG`, run configs separately (OOM prevention):
```bash
SG="semgrep scan --metrics=off --disable-version-check --max-memory 1500 --jobs 1 --timeout 20 --timeout-threshold 2 --max-target-bytes 300000"
```
OWASP (always): `$SG --config p/owasp-top-ten --include "*.py" --include "*.js" --include "*.ts" --include "*.jsx" --include "*.tsx" --include "*.java" --include "*.go" --include "*.rb" <path> 2>&1`
Python (if `.py`): `$SG --config p/python --include "*.py" <path> 2>&1`
TypeScript (if `.ts`/`.tsx`): `$SG --config p/typescript --include "*.ts" --include "*.tsx" <path> 2>&1`
Secrets (always): `$SG --config p/secrets <path> 2>&1`
Exit 137 → note "Semgrep OOM — re-run with more RAM."

**3c. Trivy:** `trivy fs <path> 2>&1`

**3d. TruffleHog:**
```bash
git -C <path> rev-parse --git-dir 2>/dev/null \
  && trufflehog git file://<path> --no-update 2>&1 \
  || trufflehog filesystem <path> --no-update 2>&1
```

**3e. CodeQL** (GitHub + `gh` only):
Check `git remote` for github.com → check `.github/workflows/` for CodeQL → `gh run list --workflow codeql.yml`. Skip if not GitHub/no `gh`.

**3f. mcps-audit** (if MCP files found):
```bash
find <path> -name "*.skill" -o -name "SKILL.md" -o -name "mcp*.json" -o -name ".mcp*" 2>/dev/null | head -5
npx mcps-audit <path> 2>&1
```

**3g. OSV-Scanner:**
```bash
osv-scanner scan source -r <path> 2>&1
```
If lockfiles present, also: `osv-scanner scan -L <lockfile> 2>&1`

**3h. mcp-scan [OPT-IN]** — ⚠️ Sends data to invariantlabs.ai. **ASK user first.**
Consented: `uvx mcp-scan@latest 2>&1` | Local-only: `uvx mcp-scan@latest inspect 2>&1`

**Bundled scripts** (3i–3k) are at `<skill-directory>/scripts/`.

**3i. security-audit:** `python3 <skill-directory>/scripts/config-audit.py <path> 2>&1`
Scans: `~/.claude/settings.json` hooks, MCP servers, skills/plugins, `.claude/` configs, CLAUDE.md safety-bypass. Outputs CRITICAL/HIGH/MEDIUM/LOW.

**3j. skill-security-auditor:** Scan all `.skill`/`SKILL.md` files:
```bash
find <path> -name "*.skill" -o -name "SKILL.md" 2>/dev/null | while read f; do
  bash <skill-directory>/scripts/skill-audit.sh "$f" 2>&1
done
```
Checks: prompt injection, tool risk matrix, tool combos (Read+WebFetch, Bash+WebFetch), supply chain, MCP vectors (SSRF, path traversal, OAuth scope), source verification. Score 0–100.

**3k. mcp-exfil-scan:** `bash <skill-directory>/scripts/mcp-exfil-scan.sh <path> 2>&1`
Scans: tool description poisoning, outbound data flow (webhooks, tunnels), exfil chains (Read+WebFetch, Bash+curl), encoded payloads (base64 URLs, DNS exfil), env var leaking, GitHub source trust. Score 0–100.

## Step 4: Assemble Report

Extract counts, write in one pass:

```
# Automated Security Scan Report
**Target:** `<path>`  **Scanned at:** <ISO 8601>
**Tools run:** <list>  **Tools skipped:** <list with reason, or "none">

## Pre-flight Summary
| Tool | Status | Version / Note |
|------|--------|----------------|
```
One row per tool. Status: OK / SKIPPED / N/A / OPT-IN.

Per tool that ran:
```
## <Tool> — <Purpose>
**Summary:** <counts> (or "Skipped: <reason>")
[CONFIDENTIAL warning if secrets tool]
<full output verbatim>
```

End with:
```
## Cross-Tool Observations
Higher-confidence signals from multiple tools, or "No cross-tool overlaps."
Correlate config-audit, skill-audit, and mcp-exfil-scan when multiple ran. Flag MCP servers appearing in both config-audit and mcp-exfil-scan.

## Coverage Gaps
Not covered: business logic, IDOR, runtime behavior, skipped-tool gaps.
If bundled scripts failed: "Claude config/skill/MCP exfil audit incomplete — check scripts."
```

## Operational Rules

1. Never read `.env`/credential files — note presence only.
2. Never truncate tool output. Redact secrets with `[REDACTED]` (keep path, line, detector). Never fabricate counts.
3. Fail loudly on pre-flight — surface missing tools before scanning.
4. TruffleHog live-verified secrets are Critical — flag prominently.
5. Tool crash/non-zero exit → include error output, note in summary.
6. mcp-scan is opt-in only. Ask user first. Include privacy warning.
