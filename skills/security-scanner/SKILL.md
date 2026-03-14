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

Runs four complementary automated security tools against a target path and assembles a
structured markdown report for LLM consumption. Full tool output is always included — do
not truncate or summarize tool output before writing the report.

## Tools

| Tool       | Purpose                                                    |
| ---------- | ---------------------------------------------------------- |
| Bandit     | Python SAST — injection, pickle, subprocess, weak crypto   |
| Semgrep    | Multi-language SAST — OWASP Top 10 + Python-specific rules |
| Trivy      | Dependencies, IaC misconfigs, secrets, container images    |
| TruffleHog | Secrets in git history with live API verification          |

---

## Step 1: Determine Scan Target

If the calling agent or user specified a path, use it. Otherwise default to the current
working directory. Confirm with a brief message:

```
Scan target: <resolved absolute path>
```

---

## Step 2: Pre-flight Tool Check

Before running anything, check availability and version of all four tools:

```bash
for tool in bandit semgrep trivy trufflehog; do
  if command -v "$tool" &>/dev/null; then
    echo "OK  $tool $($tool --version 2>&1 | head -1)"
  else
    echo "MISSING  $tool"
  fi
done
```

### If any tools are missing

List the missing tools clearly and ask the user:

> "The following tools are not installed: **[list]**
>
> How would you like to proceed?
>
> - **Skip** — continue without them (coverage will be incomplete; I'll note the gap in the report)
> - **Install** — I'll attempt to install the missing tools before scanning"

**Do not proceed until the user responds.** Wait for an explicit choice.

### If the user chooses Install

Use these install commands (macOS with Homebrew assumed; adapt if on Linux):

| Tool       | Install command           |
| ---------- | ------------------------- |
| Bandit     | `pip install bandit`      |
| Semgrep    | `pip install semgrep`     |
| Trivy      | `brew install trivy`      |
| TruffleHog | `brew install trufflehog` |

After installing, re-run the pre-flight check to confirm each tool is now available.
If install fails, fall back to asking the user whether to skip that tool or abort.

---

## Step 3: Run Each Available Tool

Run tools in this order. Capture the full stdout + stderr of each command.
**Do not filter, truncate, or interpret output at this stage** — raw output goes into the report.

### 3a. Bandit — Python SAST

```bash
bandit -r <path> -f txt 2>&1
```

Skip gracefully if the target has no Python files (check with `find <path> -name "*.py" | head -1`).

### 3b. Semgrep — Multi-language SAST

```bash
semgrep scan --metrics=off --config p/python --config p/owasp-top-ten <path> 2>&1
```

### 3c. Trivy — Dependencies & Misconfigurations

```bash
trivy fs <path> 2>&1
```

### 3d. TruffleHog — Secret Detection

First, check whether the target is a git repository:

```bash
git -C <path> rev-parse --git-dir 2>/dev/null
```

If it is a git repo (exit code 0), scan git history:

```bash
trufflehog git file://<path> --no-update 2>&1
```

If it is not a git repo, scan the filesystem instead:

```bash
trufflehog filesystem <path> --no-update 2>&1
```

---

## Step 4: Assemble the Report

Produce the following markdown document. Insert actual tool output verbatim into each
fenced code block. Fill in all summary lines from the output before writing — do a quick
read of each tool's output to extract counts, then write the report in one pass.

---

### Report Template

Use the following structure for the report. Insert actual tool output verbatim into
each fenced code block.

---

**Begin the report with this header:**

# Automated Security Scan Report

**Target:** `<absolute path>`
**Scanned at:** <ISO 8601 datetime>
**Tools run:** <comma-separated list of tools that executed>
**Tools skipped:** <comma-separated list with reason, or "none">

---

## Pre-flight Summary

| Tool       | Status         | Version |
| ---------- | -------------- | ------- |
| Bandit     | [OK / SKIPPED] | x.y.z   |
| Semgrep    | [OK / SKIPPED] | x.y.z   |
| Trivy      | [OK / SKIPPED] | x.y.z   |
| TruffleHog | [OK / SKIPPED] | x.y.z   |

---

**For each tool, include a section like this:**

## Bandit — Python SAST

**Summary:** <X> issues found — <Y> high, <Z> medium, <W> low
_(or "Skipped: <reason>")_

```
<full bandit output>
```

## Semgrep — OWASP + Python Rules

**Summary:** <X> findings across <Y> files
_(or "Skipped: <reason>")_

```
<full semgrep output>
```

## Trivy — Dependencies & Misconfigurations

**Summary:** <X> vulnerabilities (<Y> critical, <Z> high), <W> misconfigurations
_(or "Skipped: <reason>")_

```
<full trivy output>
```

## TruffleHog — Secret Detection

**Summary:** <X> secrets detected (<Y> verified live, <Z> unverified)
_(or "Skipped: <reason>")_

```
<full trufflehog output>
```

---

**End the report with these two sections:**

## Cross-Tool Observations

List any files or issues flagged by more than one tool — these are higher-confidence
signals. Format as a short bulleted list:

- `<file>:<line>` — flagged by Bandit (shell injection) AND Semgrep (command injection rule)
- `<file>` — flagged by both Trivy (CVE-XXXX) and Semgrep (insecure deserialization)

If no overlaps, write: "No cross-tool overlaps detected."

## Coverage Gaps

List any vulnerability categories NOT covered by the tools that ran, so the calling
agent or human reviewer knows what still requires manual analysis:

- Business logic flaws — not detectable by static tools
- IDOR / broken object-level authorization — requires runtime context
- <any gap caused by skipped tools>

---

## Operational Rules

1. **Never read `.env` files or credential files.** Note their presence only.
2. **Never truncate tool output** in the report. The calling agent needs the full text.
3. **Never fabricate counts or summaries** — derive them from actual tool output.
4. **Fail loudly on pre-flight** — missing tools must be surfaced before any scanning begins.
5. **TruffleHog live-verified secrets are Critical by default** — flag them prominently even
   if the overall report tone is mild.
6. **If a tool crashes or returns a non-zero exit code**, include the error output in the
   report section and note "tool exited with error" in the summary line.
