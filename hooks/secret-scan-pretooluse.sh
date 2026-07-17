#!/usr/bin/env bash
# secret-scan-pretooluse.sh — PreToolUse hook (matcher: Write|Edit|MultiEdit|NotebookEdit).
#
# Scans the CONTENT about to be written for hardcoded secrets with gitleaks,
# BEFORE it lands on disk. On a hit it DENIES the tool call (exit 0 +
# permissionDecision:"deny") with a redacted reason (file, rule, line — never
# the secret value). Everything else FAILS OPEN (exit 0, no decision) so a
# missing tool or a scanner error never wedges the user's edits:
#   - python3 absent            -> allow
#   - no extractable content    -> allow
#   - gitleaks absent           -> allow
#   - gitleaks errors (rc>1)    -> allow
#   - gitleaks clean (rc 0)     -> allow
#   - gitleaks finds leaks (rc1)-> DENY
#
# Content keys handled (verified against the real Claude Code tool schemas,
# NOT the docs' inferred names): Write.content, Edit.new_string,
# MultiEdit.edits[].new_string, NotebookEdit.new_source. Codex uses apply_patch
# (input/patch) — handled via a fallback that scans the whole tool_input, so
# the same script works on both Claude Code and Codex.
set -u

# User toggle (plugin userConfig `secret_scan`, default on). Off -> no-op.
[ "${CLAUDE_PLUGIN_OPTION_SECRET_SCAN:-true}" = "false" ] && exit 0

# Fail open if we cannot parse the hook input.
command -v python3 >/dev/null 2>&1 || exit 0

IN="$(cat)"

TMPDIR_HK="$(mktemp -d 2>/dev/null)" || exit 0
trap 'rm -rf "$TMPDIR_HK"' EXIT

# Extract file_path + content. Preserve the original extension on the temp
# file so filename-aware gitleaks rules still apply. Prints the basename used
# on stdout; writes the content to $TMPDIR_HK/<basename>. Empty content -> rc 3.
BASENAME="$(IN="$IN" TMPDIR_HK="$TMPDIR_HK" python3 - <<'PY'
import json, os, sys
try:
    d = json.loads(os.environ["IN"])
except Exception:
    sys.exit(3)
ti = d.get("tool_input") or {}
content = ti.get("content")
if content is None:
    content = ti.get("new_string")
if content is None:
    content = ti.get("new_source")
if content is None and isinstance(ti.get("edits"), list):
    parts = [e.get("new_string", "") for e in ti["edits"] if isinstance(e, dict)]
    content = "\n".join(parts) if parts else None
if content is None:
    content = ti.get("input") or ti.get("patch")   # codex apply_patch
if not content and ti:
    content = json.dumps(ti)                        # last resort: scan whole tool_input
if not content:
    sys.exit(3)
fp = ti.get("file_path") or "pending-write.txt"
base = os.path.basename(fp) or "pending-write.txt"
# Guard against path traversal in the basename.
base = base.replace("/", "_").replace("\\", "_") or "pending-write.txt"
with open(os.path.join(os.environ["TMPDIR_HK"], base), "w", encoding="utf-8", errors="replace") as f:
    f.write(content)
print(base)
PY
)"
rc=$?
[ "$rc" -eq 0 ] || exit 0        # no content / parse error -> allow

command -v gitleaks >/dev/null 2>&1 || exit 0

REPORT="$TMPDIR_HK/gitleaks-report.json"
gitleaks detect --no-git --source "$TMPDIR_HK" --no-banner --redact \
  --report-format json --report-path "$REPORT" >/dev/null 2>&1
grc=$?

# gitleaks: 0 = clean, 1 = leaks found, >1 = operational error. Only 1 blocks.
[ "$grc" -eq 1 ] || exit 0

# Build a redacted reason from the report. --redact already masked the secret
# values; we surface only rule + line + file.
REASON="$(REPORT="$REPORT" BASENAME="$BASENAME" python3 - <<'PY'
import json, os
try:
    with open(os.environ["REPORT"]) as f:
        findings = json.load(f)
except Exception:
    findings = []
if not isinstance(findings, list) or not findings:
    print("")  # nothing parseable -> caller falls back to a generic reason
else:
    rows = []
    for x in findings[:5]:
        rule = x.get("RuleID") or x.get("Description") or "secret"
        line = x.get("StartLine", "?")
        rows.append(f"{rule} (line {line})")
    more = "" if len(findings) <= 5 else f" (+{len(findings)-5} more)"
    print(f"{len(findings)} secret(s) detected by gitleaks in the pending write to "
          f"'{os.environ['BASENAME']}': " + "; ".join(rows) + more +
          ". Remove the hardcoded credential (use an env var or secret store) and retry.")
PY
)"

[ -z "$REASON" ] && REASON="gitleaks detected a hardcoded secret in the pending write to '$BASENAME'. Remove the credential and retry."

REASON="$REASON" python3 - <<'PY'
import json, os
print(json.dumps({
    "hookSpecificOutput": {
        "hookEventName": "PreToolUse",
        "permissionDecision": "deny",
        "permissionDecisionReason": os.environ["REASON"],
    }
}))
PY
exit 0
