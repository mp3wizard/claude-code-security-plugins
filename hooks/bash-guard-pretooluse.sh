#!/usr/bin/env bash
# bash-guard-pretooluse.sh — PreToolUse hook (matcher: Bash).
#
# DENIES only a small, deliberately narrow set of CATASTROPHIC, near-zero-
# false-positive commands (root/home wipes, disk formatting, fork bombs,
# pipe-to-shell installers). It is NOT a general SAST gate — the goal is to
# stop an agent from running an irreversibly destructive command, not to
# second-guess normal shell usage. Everything not on the list is allowed, and
# any parse/tooling error FAILS OPEN (exit 0). Blocking uses exit 0 +
# permissionDecision:"deny" per the PreToolUse contract.
set -u

# User toggle (plugin userConfig `bash_guard`, default on). Off -> no-op.
[ "${CLAUDE_PLUGIN_OPTION_BASH_GUARD:-true}" = "false" ] && exit 0

command -v python3 >/dev/null 2>&1 || exit 0
IN="$(cat)"

CMD="$(IN="$IN" python3 -c 'import json,os,sys
try: d=json.loads(os.environ["IN"])
except Exception: sys.exit(1)
print((d.get("tool_input") or {}).get("command","")); ' 2>/dev/null)"
[ -n "$CMD" ] || exit 0

# Catastrophic patterns. Kept narrow on purpose. Extended-regex, case-sensitive.
deny_reason=""
match() { printf '%s' "$CMD" | grep -Eq "$1"; }

if   match 'rm[[:space:]]+(-[a-zA-Z]*[rR][a-zA-Z]*[[:space:]]+)+(-[a-zA-Z]*f[a-zA-Z]*[[:space:]]+)?(/|~|/\*|\$HOME)([[:space:]]|$)'; then
  deny_reason="Recursive delete of a root/home path (rm -rf / | ~ | \$HOME). Blocked as irreversibly destructive."
elif match 'rm[[:space:]]+-[a-zA-Z]*[rR][a-zA-Z]*f|rm[[:space:]]+-[a-zA-Z]*f[a-zA-Z]*[rR]' && match '[[:space:]](/|~|\$HOME)([[:space:]]|$)'; then
  deny_reason="Recursive force-delete targeting a root/home path. Blocked as irreversibly destructive."
elif match '\bmkfs(\.[a-z0-9]+)?\b'; then
  deny_reason="Filesystem format (mkfs). Blocked as irreversibly destructive."
elif match '\bdd\b.*[[:space:]]of=/dev/(sd|nvme|disk|hd|vd)'; then
  deny_reason="Raw write to a block device (dd of=/dev/...). Blocked as irreversibly destructive."
elif match ':\(\)[[:space:]]*\{[[:space:]]*:[[:space:]]*\|[[:space:]]*:'; then
  deny_reason="Fork bomb detected. Blocked."
elif match '(curl|wget)[[:space:]].*\|[[:space:]]*(sudo[[:space:]]+)?(ba)?sh\b'; then
  deny_reason="Pipe-to-shell installer (curl|wget ... | sh). Blocked — download, inspect, then run instead."
elif match '\bchmod[[:space:]]+(-[a-zA-Z]*[rR][a-zA-Z]*[[:space:]]+)+0*777[[:space:]]+/([[:space:]]|$)'; then
  deny_reason="Recursive chmod 777 on / (world-writable root). Blocked."
fi

[ -z "$deny_reason" ] && exit 0

REASON="$deny_reason" python3 - <<'PY'
import json, os
print(json.dumps({
    "hookSpecificOutput": {
        "hookEventName": "PreToolUse",
        "permissionDecision": "deny",
        "permissionDecisionReason": os.environ["REASON"] +
            " (security-scanner bash-guard; disable the plugin if this is intentional.)",
    }
}))
PY
exit 0
