#!/usr/bin/env bash
# run-tests.sh — regression tests for the security-scanner bundled scripts.
# Proves the scanners and helpers actually fire against known-vulnerable fixtures.
# Exit 0 = all passed, 1 = a failure. Optional external tools are skipped if absent.
set -u

HERE="$(cd "$(dirname "${BASH_SOURCE:-$0}")" && pwd)"
SCRIPTS="$HERE/../.claude/skills/security-scanner/scripts"
FIX="$HERE/fixtures"
PASS=0; FAIL=0; SKIP=0

ok()   { printf '  \033[32mPASS\033[0m %s\n' "$1"; PASS=$((PASS+1)); }
no()   { printf '  \033[31mFAIL\033[0m %s\n' "$1"; FAIL=$((FAIL+1)); }
skip() { printf '  \033[33mSKIP\033[0m %s\n' "$1"; SKIP=$((SKIP+1)); }
have() { command -v "$1" >/dev/null 2>&1; }

echo "== aggregate-findings.py: dedup =="
OUT="$(python3 "$SCRIPTS/aggregate-findings.py" "$FIX"/sarif/*.sarif 2>&1)"
echo "$OUT" | grep -q 'deduped=2'            && ok "two SARIFs collapse to 2 findings"   || no "expected deduped=2 — got: $(echo "$OUT" | tr '\n' ' ')"
echo "$OUT" | grep -q 'duplicates_removed=1' && ok "shared secret deduplicated"           || no "expected duplicates_removed=1"
echo "$OUT" | grep -q 'critical=1'           && ok "CVSS 9.8 mapped to critical"          || no "expected critical=1"
echo "$OUT" | grep -q 'high=1'               && ok "secret mapped to high"                || no "expected high=1"

echo "== aggregate-findings.py: CI gate =="
python3 "$SCRIPTS/aggregate-findings.py" --fail-on critical "$FIX"/sarif/*.sarif >/dev/null 2>&1
[ $? -eq 1 ] && ok "--fail-on critical exits 1"  || no "--fail-on critical should exit 1"
python3 "$SCRIPTS/aggregate-findings.py" --fail-on none "$FIX"/sarif/*.sarif >/dev/null 2>&1
[ $? -eq 0 ] && ok "--fail-on none exits 0"      || no "--fail-on none should exit 0"

echo "== apts-audit.sh: measured run wrapper =="
L="$(bash "$SCRIPTS/apts-audit.sh" init /tmp)"
bash "$SCRIPTS/apts-audit.sh" run probe "$L" -- printf 'CRITICAL x\nHIGH y\n' >/dev/null 2>&1
grep -q '"tool":"probe".*"findings":2,"measured":true' "$L" && ok "wrapper logs measured findings=2" || no "wrapper did not log measured run"
bash "$SCRIPTS/apts-audit.sh" run failer "$L" -- sh -c 'exit 3' >/dev/null 2>&1
[ $? -eq 3 ] && ok "wrapper propagates tool exit code (3)" || no "wrapper should exit 3"
rm -f "$L"

echo "== apts-audit.sh: zero-findings record stays valid JSON (regression) =="
L="$(bash "$SCRIPTS/apts-audit.sh" init /tmp)"
bash "$SCRIPTS/apts-audit.sh" run zerotool "$L" -- printf 'nothing here\nall clean\n' >/dev/null 2>&1
if python3 -c "import json,sys; [json.loads(x) for x in open('$L')]" 2>/dev/null && grep -q '"tool":"zerotool","exit":0,"duration_ms":[0-9]*,"findings":0,"measured":true' "$L"; then
  ok "0-finding run writes a single valid JSON record"
else
  no "0-finding run corrupted the audit log (grep -c || echo 0 regression)"
fi
rm -f "$L"

echo "== mcp-exfil-scan.sh: respects scope, no global ~/.claude leakage (regression) =="
if [ -f "$SCRIPTS/mcp-exfil-scan.sh" ]; then
  SCOPE="$(bash "$SCRIPTS/mcp-exfil-scan.sh" "$FIX" 2>&1)"
  if echo "$SCOPE" | grep -q "$HOME/.claude/skills"; then
    no "mcp-exfil-scan scanned out-of-scope $HOME/.claude/skills"
  else
    ok "mcp-exfil-scan stayed within the target (no ~/.claude/skills findings)"
  fi
else
  skip "mcp-exfil-scan.sh not bundled"
fi

echo "== skill-audit.sh: flags malicious skill =="
if [ -f "$SCRIPTS/skill-audit.sh" ]; then
  SA="$(bash "$SCRIPTS/skill-audit.sh" "$FIX/malicious-skill/SKILL.md" 2>&1)"
  echo "$SA" | grep -qiE 'inject|exfil|credential|high|critical|risk' && ok "skill-audit flags the malicious skill" || no "skill-audit produced no risk signal"
else
  skip "skill-audit.sh not bundled"
fi

echo "== mcp-exfil-scan.sh: flags exfil chain =="
if [ -f "$SCRIPTS/mcp-exfil-scan.sh" ]; then
  ME="$(bash "$SCRIPTS/mcp-exfil-scan.sh" "$FIX/malicious-skill" 2>&1)"
  echo "$ME" | grep -qiE 'exfil|webfetch|curl|outbound|base64|high|critical' && ok "mcp-exfil-scan flags exfil indicators" || no "mcp-exfil-scan produced no signal"
else
  skip "mcp-exfil-scan.sh not bundled"
fi

echo "== config-audit.py: executes =="
python3 "$SCRIPTS/config-audit.py" "$FIX" >/dev/null 2>&1
rc=$?; { [ $rc -eq 0 ] || [ $rc -eq 1 ]; } && ok "config-audit runs (exit $rc)" || no "config-audit crashed (exit $rc)"

echo "== Bandit: fires on vuln_sample.py (optional) =="
if have bandit; then
  bandit "$FIX/vuln_sample.py" -f txt >/tmp/bandit.out 2>&1; rc=$?
  if [ $rc -ge 2 ] || grep -q 'Traceback' /tmp/bandit.out; then
    skip "bandit installed but errored in this env (exit $rc) — $(grep -m1 Error /tmp/bandit.out || echo 'see /tmp/bandit.out')"
  elif grep -qiE 'Issue:|Severity:' /tmp/bandit.out; then ok "Bandit reports issues"
  else no "Bandit found nothing on a planted-vuln file"; fi
else
  skip "bandit not installed"
fi

echo "== Semgrep: fires on vuln_sample.py (optional) =="
if have semgrep; then
  semgrep scan --config p/python --metrics=off --quiet "$FIX/vuln_sample.py" >/tmp/sg.out 2>&1; rc=$?
  if [ $rc -ge 2 ] || grep -q 'Traceback' /tmp/sg.out; then
    skip "semgrep installed but errored in this env (exit $rc)"
  elif grep -qiE 'finding|rule|md5|eval|subprocess' /tmp/sg.out; then ok "Semgrep reports findings"
  else no "Semgrep found nothing on a planted-vuln file"; fi
else
  skip "semgrep not installed"
fi

echo "== Gitleaks: fires on planted secret (optional) =="
if have gitleaks; then
  gitleaks detect --source "$FIX" --no-git --no-banner >/tmp/gl.out 2>&1
  rc=$?
  { [ $rc -ne 0 ] || grep -qi 'secret\|leak' /tmp/gl.out; } && ok "Gitleaks detects the planted secret" || no "Gitleaks found nothing"
else
  skip "gitleaks not installed"
fi

echo
echo "==================== RESULT ===================="
echo "PASS=$PASS  FAIL=$FAIL  SKIP=$SKIP"
[ "$FAIL" -eq 0 ] && { echo "ALL PASSED"; exit 0; } || { echo "FAILURES PRESENT"; exit 1; }
