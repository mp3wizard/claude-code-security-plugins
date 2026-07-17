---
description: Run the full 13-tool security scan (SAST, secrets, SCA, MCP/skill audit) on a path and return one APTS-aligned report.
argument-hint: "[path — defaults to the current directory]"
---

Run a complete security scan by invoking the **security-scanner** skill.

Target path: `$ARGUMENTS` (if empty, use the current working directory).

Steps:
1. Invoke the `security-scanner` skill against the target path.
2. Follow the skill exactly — Scope Record → Pre-flight → per-tool runs → assembled report. Honor its opt-in privacy gates (mcp-scan and skillspector LLM mode ask the user first).
3. If any core CLI is missing, surface the pre-flight list and ask **Skip or Install?** before scanning — do not silently omit a tool.
4. Return the single structured markdown report the skill produces; do not summarize away the per-tool verbatim output.
