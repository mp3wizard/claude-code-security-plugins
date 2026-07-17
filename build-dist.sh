#!/usr/bin/env bash
# build-dist.sh — rebuild both distribution artifacts reproducibly from source.
#
# Produces:
#   security-scanner.skill            (skill-only: SKILL.md + bundled scripts)
#   claude-code-security-plugins.zip  (full plugin: skill + agent + manifests)
#
# Guarantees the artifacts never drift from source again (the v1.4–1.6 bug where
# the shipped .skill lagged the repo). Regenerates SHA256SUMS first, and NEVER
# bundles settings.local.json or .DS_Store.
set -eu

ROOT="$(cd "$(dirname "${BASH_SOURCE:-$0}")" && pwd)"
cd "$ROOT"
SKILL_SRC=".claude/skills/security-scanner"
SCRIPTS="$SKILL_SRC/scripts"
BUNDLED="config-audit.py skill-audit.sh mcp-exfil-scan.sh apts-audit.sh aggregate-findings.py"

echo "==> Regenerating $SCRIPTS/SHA256SUMS"
( cd "$SCRIPTS" && { command -v shasum >/dev/null && shasum -a 256 $BUNDLED || sha256sum $BUNDLED; } > SHA256SUMS )
( cd "$SCRIPTS" && { shasum -a 256 -c SHA256SUMS >/dev/null 2>&1 || sha256sum -c SHA256SUMS >/dev/null 2>&1; } ) \
  && echo "    integrity manifest verified"

STAGE="$(mktemp -d)"
trap 'rm -rf "$STAGE"' EXIT

# ---- 1) security-scanner.skill (top-level dir: security-scanner/) ----
echo "==> Building security-scanner.skill"
SK="$STAGE/security-scanner"
mkdir -p "$SK/scripts" "$SK/reports"
cp "$SKILL_SRC/SKILL.md" "$SK/SKILL.md"
for f in $BUNDLED SHA256SUMS; do cp "$SCRIPTS/$f" "$SK/scripts/$f"; done
rm -f "$ROOT/security-scanner.skill"
( cd "$STAGE" && find security-scanner -name '.DS_Store' -delete \
  && zip -rqX "$ROOT/security-scanner.skill" security-scanner )

# ---- 2) claude-code-security-plugins.zip (top-level dir: claude-code-security-plugins/) ----
echo "==> Building claude-code-security-plugins.zip"
PL="$STAGE/claude-code-security-plugins"
PLSK="$PL/.claude/skills/security-scanner"
mkdir -p "$PLSK/scripts" "$PLSK/reports" "$PL/agents" "$PL/.claude-plugin"
cp "$SKILL_SRC/SKILL.md" "$PLSK/SKILL.md"
for f in $BUNDLED SHA256SUMS; do cp "$SCRIPTS/$f" "$PLSK/scripts/$f"; done
# Agent lives at the canonical root agents/ dir — the explicit `agents` manifest
# field does not register in current Claude Code; default discovery does.
cp agents/security-analysis.md "$PL/agents/"
cp .claude-plugin/plugin.json .claude-plugin/marketplace.json "$PL/.claude-plugin/"
# Guardrail hooks + slash command (v1.8.0+). Ship executable.
mkdir -p "$PL/hooks" "$PL/commands"
cp hooks/hooks.json "$PL/hooks/"
cp hooks/*.sh "$PL/hooks/" && chmod +x "$PL/hooks/"*.sh
cp commands/*.md "$PL/commands/"
# Hard exclusions — never ship machine-local config, OS cruft, or generated reports.
find "$PL" \( -name '.DS_Store' -o -name 'settings.local.json' \) -delete
rm -f "$ROOT/claude-code-security-plugins.zip"
( cd "$STAGE" && zip -rqX "$ROOT/claude-code-security-plugins.zip" claude-code-security-plugins )

echo "==> Done. Contents:"
echo "--- security-scanner.skill ---"
unzip -l "$ROOT/security-scanner.skill" | awk 'NR>3 && $4 {print "   "$4}'
echo "--- claude-code-security-plugins.zip ---"
unzip -l "$ROOT/claude-code-security-plugins.zip" | awk 'NR>3 && $4 {print "   "$4}'
# Fail loudly if the local-settings leak ever reappears.
if unzip -l "$ROOT/claude-code-security-plugins.zip" | grep -q settings.local.json; then
  echo "ERROR: settings.local.json leaked into plugin zip" >&2; exit 1
fi
echo "OK — artifacts rebuilt, no local config bundled."
