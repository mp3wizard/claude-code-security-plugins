#!/usr/bin/env bash
# preflight-sessionstart.sh — SessionStart hook.
#
# Reports which of the security-scanner CLIs are installed so the user knows
# up front what the scanner can and cannot run. Pure information: it NEVER
# blocks the session and NEVER fails the hook (always exits 0). Output is
# surfaced to Claude via hookSpecificOutput.additionalContext.
#
# Contract: SessionStart. stdin is JSON (ignored here). stdout = one JSON
# object with hookSpecificOutput.additionalContext.
set -u

# Core scanners the skill drives. Optional/opt-in tools (mcp-scan, skillspector)
# are intentionally omitted — their absence is expected, not worth flagging.
CORE="gitleaks bandit semgrep trivy trufflehog osv-scanner"
missing=""
for t in $CORE; do
  command -v "$t" >/dev/null 2>&1 || missing="$missing $t"
done

# jq / python3 are what the hooks themselves need to parse tool input.
hook_dep_warn=""
if ! command -v jq >/dev/null 2>&1 && ! command -v python3 >/dev/null 2>&1; then
  hook_dep_warn=" Neither jq nor python3 found — the PreToolUse secret-scan and command-guard hooks will fail open (no protection)."
fi

if [ -z "$missing" ] && [ -z "$hook_dep_warn" ]; then
  msg="security-scanner: all core CLIs present (gitleaks, bandit, semgrep, trivy, trufflehog, osv-scanner). PreToolUse secret-scan + Bash guard active."
else
  msg="security-scanner preflight —"
  [ -n "$missing" ] && msg="$msg missing tools:$missing (those checks will be skipped; install via pip/brew)."
  [ -n "$hook_dep_warn" ] && msg="$msg$hook_dep_warn"
fi

# Emit JSON. Prefer jq for safe escaping; fall back to python3; last-resort
# plain stdout (SessionStart shows plain stdout to Claude too).
if command -v jq >/dev/null 2>&1; then
  jq -n --arg m "$msg" '{hookSpecificOutput:{hookEventName:"SessionStart",additionalContext:$m}}'
elif command -v python3 >/dev/null 2>&1; then
  MSG="$msg" python3 -c 'import json,os; print(json.dumps({"hookSpecificOutput":{"hookEventName":"SessionStart","additionalContext":os.environ["MSG"]}}))'
else
  printf '%s\n' "$msg"
fi
exit 0
