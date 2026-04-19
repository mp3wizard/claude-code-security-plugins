#!/usr/bin/env bash
# apts-audit.sh — APTS Auditability helper (JSONL scan log)
# Aligned with OWASP APTS (Autonomous Penetration Testing Standard) § Auditability.
# Usage:
#   apts-audit.sh init <scope-path>                     → creates log, prints path
#   apts-audit.sh log <tool> <exit> <ms> <findings> [log-path]
#   apts-audit.sh finalize [log-path]                   → prints markdown summary
set -eu

_esc() { printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g'; }
_now() { date -u +%Y-%m-%dT%H:%M:%SZ; }

cmd="${1:-}"; shift || true

case "$cmd" in
  init)
    scope="${1:-$(pwd)}"
    ts=$(date -u +%Y%m%dT%H%M%SZ)
    log="/tmp/css-scan-${ts}.jsonl"
    user=$(id -un 2>/dev/null || echo unknown)
    head=$(git -C "$scope" rev-parse --short HEAD 2>/dev/null || echo none)
    printf '{"event":"init","ts":"%s","scope":"%s","user":"%s","git_head":"%s","tool":"apts-audit","standard":"OWASP-APTS"}\n' \
      "$(_now)" "$(_esc "$scope")" "$(_esc "$user")" "$head" > "$log"
    echo "$log"
    ;;
  log)
    tool="${1:?tool}"; ec="${2:?exit}"; ms="${3:-0}"; n="${4:-0}"
    log="${5:-$(ls -t /tmp/css-scan-*.jsonl 2>/dev/null | head -1)}"
    [ -n "$log" ] && [ -f "$log" ] || { echo "apts-audit: no log file" >&2; exit 1; }
    printf '{"event":"tool","ts":"%s","tool":"%s","exit":%s,"duration_ms":%s,"findings":%s}\n' \
      "$(_now)" "$(_esc "$tool")" "$ec" "$ms" "$n" >> "$log"
    ;;
  finalize)
    log="${1:-$(ls -t /tmp/css-scan-*.jsonl 2>/dev/null | head -1)}"
    [ -n "$log" ] && [ -f "$log" ] || { echo "apts-audit: no log file" >&2; exit 1; }
    runs=$(grep -c '"event":"tool"' "$log" 2>/dev/null || echo 0)
    printf '{"event":"finalize","ts":"%s","tool_runs":%s}\n' "$(_now)" "$runs" >> "$log"
    echo
    echo "### APTS Audit Log"
    echo "- **Log:** \`$log\`"
    echo "- **Tool runs recorded:** $runs"
    echo "- **Standard:** OWASP APTS § Auditability"
    ;;
  *)
    echo "usage: apts-audit.sh {init <scope>|log <tool> <exit> <ms> <findings>|finalize}" >&2
    exit 2
    ;;
esac
