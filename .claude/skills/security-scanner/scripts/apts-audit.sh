#!/usr/bin/env bash
# apts-audit.sh — APTS Auditability helper (JSONL scan log)
# Aligned with OWASP APTS (Autonomous Penetration Testing Standard) § Auditability.
# Usage:
#   apts-audit.sh init <scope-path>                     → creates log, prints path
#   apts-audit.sh run <tool> <log-path> -- <command...> → runs cmd, logs MEASURED exit/time/count
#   apts-audit.sh log <tool> <exit> <ms> <findings> [log-path]
#   apts-audit.sh finalize [log-path]                   → prints markdown summary
set -eu

_esc() { printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g'; }
_now() { date -u +%Y-%m-%dT%H:%M:%SZ; }
# Millisecond clock — macOS `date` has no %N, so prefer python3, fall back to second resolution.
_now_ms() { python3 -c 'import time;print(int(time.time()*1000))' 2>/dev/null || echo "$(( $(date +%s) * 1000 ))"; }

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
  run)
    # apts-audit.sh run <tool> <log> -- <command...>
    tool="${1:?tool}"; log="${2:?log}"; shift 2
    [ "${1:-}" = "--" ] && shift
    [ $# -ge 1 ] || { echo "apts-audit: run needs a command after --" >&2; exit 2; }
    [ -n "$log" ] && [ -f "$log" ] || { echo "apts-audit: no log file" >&2; exit 1; }
    tmp=$(mktemp 2>/dev/null || echo "/tmp/apts-run-$$.out")
    start=$(_now_ms)
    "$@" 2>&1 | tee "$tmp"          # stream tool output unchanged; capture a copy
    ec=${PIPESTATUS[0]}             # real tool exit (bash); tee masks it otherwise
    dur=$(( $(_now_ms) - start ))
    # MEASURED findings proxy: lines matching severity/finding keywords (deterministic, not LLM-estimated)
    n=$(grep -icE '(CRITICAL|HIGH|MEDIUM|LOW|WARNING|ERROR|finding|vuln|secret|poison|exfil)' "$tmp" 2>/dev/null || echo 0)
    rm -f "$tmp"
    printf '{"event":"tool","ts":"%s","tool":"%s","exit":%s,"duration_ms":%s,"findings":%s,"measured":true}\n' \
      "$(_now)" "$(_esc "$tool")" "$ec" "$dur" "$n" >> "$log"
    exit "$ec"
    ;;
  log)
    tool="${1:?tool}"; ec="${2:?exit}"; ms="${3:-0}"; n="${4:-0}"
    log="${5:-$(ls -t /tmp/css-scan-*.jsonl 2>/dev/null | head -1)}"
    [ -n "$log" ] && [ -f "$log" ] || { echo "apts-audit: no log file" >&2; exit 1; }
    printf '{"event":"tool","ts":"%s","tool":"%s","exit":%s,"duration_ms":%s,"findings":%s,"measured":false}\n' \
      "$(_now)" "$(_esc "$tool")" "$ec" "$ms" "$n" >> "$log"
    ;;
  finalize)
    log="${1:-$(ls -t /tmp/css-scan-*.jsonl 2>/dev/null | head -1)}"
    [ -n "$log" ] && [ -f "$log" ] || { echo "apts-audit: no log file" >&2; exit 1; }
    runs=$(grep -c '"event":"tool"' "$log" 2>/dev/null || echo 0)
    measured=$(grep -c '"measured":true' "$log" 2>/dev/null || echo 0)
    printf '{"event":"finalize","ts":"%s","tool_runs":%s,"measured_runs":%s}\n' "$(_now)" "$runs" "$measured" >> "$log"
    echo
    echo "### APTS Audit Log"
    echo "- **Log:** \`$log\`"
    echo "- **Tool runs recorded:** $runs (measured: $measured, asserted: $(( runs - measured )))"
    echo "- **Standard:** OWASP APTS § Auditability"
    ;;
  *)
    echo "usage: apts-audit.sh {init <scope>|run <tool> <log> -- <cmd...>|log <tool> <exit> <ms> <findings>|finalize}" >&2
    exit 2
    ;;
esac
