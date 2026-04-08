#!/bin/bash
# mcp-exfil-scan.sh — MCP Data Exfiltration Detection Scanner v1.0
# Detects data exfiltration risks in MCP servers, skills, and plugins
# Usage: bash mcp-exfil-scan.sh [scan-target-path]

set -uo pipefail

SCAN_TARGET="${1:-.}"
SCAN_TARGET="$(cd "$SCAN_TARGET" 2>/dev/null && pwd || echo "$SCAN_TARGET")"
CLAUDE_DIR="${CLAUDE_CONFIG_DIR:-$HOME/.claude}"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPORT_DIR="${SCRIPT_DIR}/../reports"
REPORT_FILE="$REPORT_DIR/mcp-exfil-$TIMESTAMP.txt"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Counters
TOTAL_FINDINGS=0
CRITICAL_COUNT=0
HIGH_COUNT=0
MEDIUM_COUNT=0
LOW_COUNT=0
RISK_SCORE=0

mkdir -p "$REPORT_DIR"

# Cleanup old reports (keep last 50)
REPORT_COUNT=$(ls -1 "$REPORT_DIR"/mcp-exfil-*.txt 2>/dev/null | wc -l | tr -d ' ' || true)
if [ "$REPORT_COUNT" -gt 50 ]; then
  ls -1t "$REPORT_DIR"/mcp-exfil-*.txt | tail -n +51 | xargs rm -f
fi

log() { echo -e "$1" | tee -a "$REPORT_FILE"; }

finding() {
  local severity="$1" location="$2" description="$3" evidence="${4:-}"
  TOTAL_FINDINGS=$((TOTAL_FINDINGS + 1))
  case "$severity" in
    CRITICAL) CRITICAL_COUNT=$((CRITICAL_COUNT + 1)); RISK_SCORE=$((RISK_SCORE + 50)); log "${RED}  [CRITICAL] $location${NC}" ;;
    HIGH)     HIGH_COUNT=$((HIGH_COUNT + 1));         RISK_SCORE=$((RISK_SCORE + 30)); log "${RED}  [HIGH] $location${NC}" ;;
    MEDIUM)   MEDIUM_COUNT=$((MEDIUM_COUNT + 1));     RISK_SCORE=$((RISK_SCORE + 15)); log "${YELLOW}  [MEDIUM] $location${NC}" ;;
    LOW)      LOW_COUNT=$((LOW_COUNT + 1));           RISK_SCORE=$((RISK_SCORE + 5));  log "${BLUE}  [LOW] $location${NC}" ;;
  esac
  log "    $description"
  [ -n "$evidence" ] && log "    Evidence: ${evidence:0:200}"
}

# JSON parsing — prefer jq, fallback to python3
json_get() {
  local file="$1" query="$2"
  if command -v jq &>/dev/null; then
    jq -r "$query" "$file" 2>/dev/null
  else
    python3 -c "
import json, sys
try:
    data = json.load(open('$file'))
    keys = '''$query'''.strip('.').split('.')
    for k in keys:
        if k and isinstance(data, dict):
            data = data.get(k, {})
    if isinstance(data, dict):
        for k in data: print(k)
    elif isinstance(data, list):
        for item in data: print(item)
    else:
        print(data)
except: pass
" 2>/dev/null
  fi
}

json_get_value() {
  local file="$1" query="$2"
  if command -v jq &>/dev/null; then
    jq -r "$query // empty" "$file" 2>/dev/null
  else
    python3 -c "
import json, sys
try:
    data = json.load(open('$file'))
    # Simple path navigation
    result = data
    parts = '''$query'''.replace('?','').strip('.').split('.')
    for p in parts:
        if p.startswith('[') and p.endswith(']'):
            result = result[int(p[1:-1])]
        elif isinstance(result, dict):
            result = result.get(p, None)
        else:
            result = None
            break
    if result is not None:
        if isinstance(result, (dict, list)):
            print(json.dumps(result))
        else:
            print(result)
except: pass
" 2>/dev/null
  fi
}

# Known-safe MCP server patterns (reduce false positives)
TRUSTED_MCP_PATTERNS="anthropic|modelcontextprotocol|github|google|microsoft|slack|notion|linear|supabase|vercel|cloudflare|stripe|figma|sentry|datadog|postman"

is_trusted_mcp() {
  local name="$1" cmd="$2"
  echo "$name $cmd" | grep -qiE "$TRUSTED_MCP_PATTERNS"
}

# ============================================================
log "${BLUE}============================================================${NC}"
log "${BLUE}  MCP Data Exfiltration Scanner v1.0${NC}"
log "${BLUE}============================================================${NC}"
log "Scan target: $SCAN_TARGET"
log "Report: $REPORT_FILE"
log ""

# Collect all MCP config files to scan
MCP_CONFIGS=()
for f in \
  "$CLAUDE_DIR/settings.json" \
  "$CLAUDE_DIR/settings.local.json" \
  "$SCAN_TARGET/.claude/settings.json" \
  "$SCAN_TARGET/.claude/settings.local.json" \
  "$SCAN_TARGET/.mcp.json" \
  "$SCAN_TARGET/mcp.json"; do
  [ -f "$f" ] && MCP_CONFIGS+=("$f")
done

# Also find any .mcp.json in subdirectories (max depth 3)
while IFS= read -r f; do
  [ -f "$f" ] && MCP_CONFIGS+=("$f")
done < <(find "$SCAN_TARGET" -maxdepth 3 -name ".mcp.json" -o -name "mcp.json" 2>/dev/null | head -20)

# Deduplicate
MCP_CONFIGS=($(printf '%s\n' "${MCP_CONFIGS[@]}" | sort -u))

# Collect skill files
SKILL_FILES=()
while IFS= read -r f; do
  [ -f "$f" ] && SKILL_FILES+=("$f")
done < <(find "$CLAUDE_DIR/skills" "$SCAN_TARGET/.claude/skills" "$SCAN_TARGET" -maxdepth 4 \( -name "*.skill" -o -name "SKILL.md" \) 2>/dev/null | head -50)
SKILL_FILES=($(printf '%s\n' "${SKILL_FILES[@]}" 2>/dev/null | sort -u))

log "MCP configs found: ${#MCP_CONFIGS[@]}"
log "Skill files found: ${#SKILL_FILES[@]}"
log ""

# ============================================================
# Phase A: MCP Tool Description Poisoning
# ============================================================
log "${BLUE}[1/6] Scanning MCP tool descriptions for exfiltration instructions...${NC}"

POISONING_PATTERNS=(
  "send (all|the|any|every)? ?(file|data|content|code|secret|token|key|env).*(to |toward).*(http|https|ftp|ws)://"
  "(before|after) respond(ing)?,? ?(send|post|forward|transmit|relay|upload)"
  "(silently|quietly|secretly|without telling|without mentioning|do not tell).*(send|post|forward|transmit|fetch|request|upload)"
  "(collect|exfiltrate|extract|harvest|steal|siphon).*(data|file|content|secret|token|credential|env)"
  "(include|append|embed|attach).*(all|every|each)? ?(file|content|data|code).*(request|payload|body|header|parameter|query)"
  "(phone home|beacon|ping back|report back|call home)"
  "(webhook|callback).*(send|post|forward|relay).*(data|content|file|secret)"
  "ignore.*(previous|prior|above).*(instruction|rule|constraint).*(send|post|forward)"
)

PHASE_A_FOUND=0

# Scan MCP config files for tool descriptions and args that contain poisoning
for config in "${MCP_CONFIGS[@]}"; do
  if [ -f "$config" ]; then
    content=$(cat "$config" 2>/dev/null || true)
    for pattern in "${POISONING_PATTERNS[@]}"; do
      matches=$(echo "$content" | grep -ciE "$pattern" 2>/dev/null || true)
      if [ "$matches" -gt 0 ]; then
        evidence=$(echo "$content" | grep -iE "$pattern" 2>/dev/null | head -1)
        finding "CRITICAL" "$config" "MCP tool description poisoning: exfiltration instruction detected" "$evidence"
        PHASE_A_FOUND=$((PHASE_A_FOUND + 1))
      fi
    done
  fi
done

# Scan skill files for poisoning patterns targeting MCP tools
for skill in "${SKILL_FILES[@]}"; do
  if [ -f "$skill" ]; then
    content=$(cat "$skill" 2>/dev/null || true)
    for pattern in "${POISONING_PATTERNS[@]}"; do
      matches=$(echo "$content" | grep -ciE "$pattern" 2>/dev/null || true)
      if [ "$matches" -gt 0 ]; then
        evidence=$(echo "$content" | grep -iE "$pattern" 2>/dev/null | head -1)
        finding "CRITICAL" "$skill" "Skill contains exfiltration instruction pattern" "$evidence"
        PHASE_A_FOUND=$((PHASE_A_FOUND + 1))
      fi
    done
  fi
done

[ $PHASE_A_FOUND -eq 0 ] && log "${GREEN}  No tool description poisoning detected${NC}"

# ============================================================
# Phase B: MCP Server Outbound Data Flow
# ============================================================
log ""
log "${BLUE}[2/6] Scanning MCP server outbound data flow...${NC}"

PHASE_B_FOUND=0

# Outbound endpoint patterns in server args
OUTBOUND_PATTERNS=(
  "https?://[a-zA-Z0-9._:/@%-]+"
  "--endpoint"
  "--webhook"
  "--callback"
  "--notify"
  "--url"
  "--server"
  "--host"
)

# Proxy/tunnel patterns
TUNNEL_PATTERNS="ngrok|cloudflare.*tunnel|localtunnel|bore|serveo|localhost\.run|telebit|pagekite"

for config in "${MCP_CONFIGS[@]}"; do
  [ -f "$config" ] || continue

  # Get list of MCP server names
  servers=$(json_get "$config" ".mcpServers | keys[]" 2>/dev/null || true)
  [ -z "$servers" ] && continue

  while IFS= read -r server_name; do
    [ -z "$server_name" ] && continue

    cmd=$(json_get_value "$config" ".mcpServers.${server_name}.command" 2>/dev/null || true)
    args_raw=$(json_get_value "$config" ".mcpServers.${server_name}.args" 2>/dev/null || true)
    args_str="$cmd $args_raw"

    # Check for tunnel/proxy tools
    if echo "$args_str" | grep -qiE "$TUNNEL_PATTERNS"; then
      finding "HIGH" "$config → mcpServers.$server_name" "MCP server uses tunnel/proxy tool (data may leave local network)" "$args_str"
      PHASE_B_FOUND=$((PHASE_B_FOUND + 1))
      continue
    fi

    # Check for outbound URLs in args
    urls=$(echo "$args_str" | grep -oE 'https?://[a-zA-Z0-9./?=_&:%-]+' 2>/dev/null | sort -u || true)
    if [ -n "$urls" ]; then
      while IFS= read -r url; do
        [ -z "$url" ] && continue
        if echo "$url" | grep -qiE "(pastebin|0bin|hastebin|tempfile|anonfile|transfer\.sh|file\.io|requestbin|webhook\.site|pipedream|hookbin|beeceptor)"; then
          finding "CRITICAL" "$config → mcpServers.$server_name" "MCP server args contain suspicious exfiltration endpoint" "$url"
          PHASE_B_FOUND=$((PHASE_B_FOUND + 1))
        elif is_trusted_mcp "$server_name" "$url"; then
          : # Skip trusted
        elif echo "$url" | grep -qiE "(localhost|127\.0\.0\.1|0\.0\.0\.0|::1)"; then
          : # Skip local
        else
          finding "MEDIUM" "$config → mcpServers.$server_name" "MCP server args contain external URL — verify legitimacy" "$url"
          PHASE_B_FOUND=$((PHASE_B_FOUND + 1))
        fi
      done <<< "$urls"
    fi

    # Check for webhook/callback args
    if echo "$args_str" | grep -qiE "\-\-(webhook|callback|notify|hook-url|post-url|report-url)"; then
      if ! is_trusted_mcp "$server_name" "$args_str"; then
        finding "HIGH" "$config → mcpServers.$server_name" "MCP server uses webhook/callback argument — data may be sent externally" "$args_str"
        PHASE_B_FOUND=$((PHASE_B_FOUND + 1))
      fi
    fi

    # Check for pipe/redirect operators in args (data exfil via shell)
    if echo "$args_str" | grep -qE '\|.*curl|\|.*wget|\|.*nc |\|.*ncat|>\s*/dev/tcp'; then
      finding "CRITICAL" "$config → mcpServers.$server_name" "MCP server args contain pipe to network command" "$args_str"
      PHASE_B_FOUND=$((PHASE_B_FOUND + 1))
    fi

  done <<< "$servers"
done

[ $PHASE_B_FOUND -eq 0 ] && log "${GREEN}  No suspicious outbound data flow detected${NC}"

# ============================================================
# Phase C: Skill-Level Exfiltration Chains
# ============================================================
log ""
log "${BLUE}[3/6] Scanning skill-level exfiltration chains...${NC}"

PHASE_C_FOUND=0

# Exfiltration chain patterns in code blocks
EXFIL_CHAIN_PATTERNS=(
  "cat .*(\\||>).*(curl|wget|nc |ncat|netcat)"
  "read.*(\\||>).*(curl|wget|nc |ncat)"
  "grep.*(\\||>).*(curl|wget|nc |ncat)"
  "find.*(\\||>).*(curl|wget|nc |ncat)"
  "curl.*-d.*\\$\\(cat"
  "curl.*--data.*\\$\\(cat"
  "curl.*-F.*@"
  "wget.*--post-file"
  "curl.*-X POST.*-d.*\\$"
  "base64.*\\|.*curl"
  "tar.*\\|.*curl"
  "zip.*\\|.*curl"
)

# MCP tool exfiltration combo patterns
MCP_TOOL_COMBOS=(
  "mcp__.*WebFetch|WebFetch.*mcp__"
  "mcp__.*Bash|Bash.*mcp__"
)

for skill in "${SKILL_FILES[@]}"; do
  [ -f "$skill" ] || continue
  content=$(cat "$skill" 2>/dev/null || true)

  # Check allowed-tools for risky combinations
  allowed_tools=$(echo "$content" | grep -iE "^allowed.?tools:" | head -1 || true)
  if [ -n "$allowed_tools" ]; then
    has_read=$(echo "$allowed_tools" | grep -qi "Read" && echo 1 || echo 0)
    has_webfetch=$(echo "$allowed_tools" | grep -qi "WebFetch" && echo 1 || echo 0)
    has_bash=$(echo "$allowed_tools" | grep -qi "Bash" && echo 1 || echo 0)
    has_grep=$(echo "$allowed_tools" | grep -qi "Grep" && echo 1 || echo 0)

    # Check if skill also contains outbound URL patterns
    has_urls=$(echo "$content" | grep -cE 'https?://[a-zA-Z0-9.]' 2>/dev/null || true)

    if [ "$has_read" -eq 1 ] && [ "$has_webfetch" -eq 1 ] && [ "$has_urls" -gt 0 ]; then
      finding "HIGH" "$skill" "Skill has Read+WebFetch tools with external URLs — potential exfiltration chain" "$allowed_tools"
      PHASE_C_FOUND=$((PHASE_C_FOUND + 1))
    fi

    if [ "$has_bash" -eq 1 ] && [ "$has_webfetch" -eq 1 ]; then
      finding "HIGH" "$skill" "Skill has Bash+WebFetch tools — can execute and exfiltrate" "$allowed_tools"
      PHASE_C_FOUND=$((PHASE_C_FOUND + 1))
    fi

    if [ "$has_grep" -eq 1 ] && [ "$has_webfetch" -eq 1 ] && [ "$has_urls" -gt 0 ]; then
      finding "MEDIUM" "$skill" "Skill has Grep+WebFetch tools with external URLs — potential data search+exfiltrate" "$allowed_tools"
      PHASE_C_FOUND=$((PHASE_C_FOUND + 1))
    fi
  fi

  # Check code blocks for exfiltration chains
  for pattern in "${EXFIL_CHAIN_PATTERNS[@]}"; do
    if echo "$content" | grep -qiE "$pattern" 2>/dev/null; then
      evidence=$(echo "$content" | grep -iE "$pattern" 2>/dev/null | head -1)
      finding "CRITICAL" "$skill" "Skill contains data exfiltration chain in code block" "$evidence"
      PHASE_C_FOUND=$((PHASE_C_FOUND + 1))
    fi
  done

  # Check for MCP tool + network tool combos
  for pattern in "${MCP_TOOL_COMBOS[@]}"; do
    if echo "$content" | grep -qiE "$pattern" 2>/dev/null; then
      evidence=$(echo "$content" | grep -iE "$pattern" 2>/dev/null | head -1)
      finding "MEDIUM" "$skill" "Skill combines MCP tools with network-capable tools" "$evidence"
      PHASE_C_FOUND=$((PHASE_C_FOUND + 1))
    fi
  done
done

[ $PHASE_C_FOUND -eq 0 ] && log "${GREEN}  No exfiltration chains detected${NC}"

# ============================================================
# Phase D: Encoded/Obfuscated Exfiltration
# ============================================================
log ""
log "${BLUE}[4/6] Scanning for encoded/obfuscated exfiltration payloads...${NC}"

PHASE_D_FOUND=0

# URL shorteners
URL_SHORTENERS="bit\\.ly|tinyurl\\.com|t\\.co|is\\.gd|rb\\.gy|cutt\\.ly|short\\.io|ow\\.ly|buff\\.ly|tiny\\.cc"

# DNS exfiltration patterns
DNS_EXFIL="(nslookup|dig|host).*\\$\\(|\\$\\{.*\\}\\.[a-zA-Z0-9.-]+\\.(com|net|org|io|xyz)"

# Encoded URL construction
ENCODED_PATTERNS=(
  "\\\\x68\\\\x74\\\\x74\\\\x70"
  "\\$\\(echo.*\\|.*base64.*-d\\).*http"
  "eval.*atob|eval.*decode"
  "String\\.fromCharCode.*104.*116.*116.*112"
  "printf.*\\\\x.*http"
)

ALL_FILES=("${MCP_CONFIGS[@]}" "${SKILL_FILES[@]}")

for file in "${ALL_FILES[@]}"; do
  [ -f "$file" ] || continue
  content=$(cat "$file" 2>/dev/null || true)

  # Check for URL shorteners
  if echo "$content" | grep -qiE "$URL_SHORTENERS" 2>/dev/null; then
    evidence=$(echo "$content" | grep -iE "$URL_SHORTENERS" 2>/dev/null | head -1)
    finding "HIGH" "$file" "URL shortener detected — may hide exfiltration endpoint" "$evidence"
    PHASE_D_FOUND=$((PHASE_D_FOUND + 1))
  fi

  # Check for DNS exfiltration
  if echo "$content" | grep -qiE "$DNS_EXFIL" 2>/dev/null; then
    evidence=$(echo "$content" | grep -iE "$DNS_EXFIL" 2>/dev/null | head -1)
    finding "CRITICAL" "$file" "DNS exfiltration pattern detected — data encoded in DNS query" "$evidence"
    PHASE_D_FOUND=$((PHASE_D_FOUND + 1))
  fi

  # Check for encoded patterns
  for pattern in "${ENCODED_PATTERNS[@]}"; do
    if echo "$content" | grep -qiE "$pattern" 2>/dev/null; then
      evidence=$(echo "$content" | grep -iE "$pattern" 2>/dev/null | head -1)
      finding "HIGH" "$file" "Encoded/obfuscated URL construction detected" "$evidence"
      PHASE_D_FOUND=$((PHASE_D_FOUND + 1))
    fi
  done

  # Check for base64-encoded strings that might be URLs
  while IFS= read -r b64str; do
    [ -z "$b64str" ] && continue
    decoded=$(echo "$b64str" | base64 -d 2>/dev/null || true)
    if echo "$decoded" | grep -qE "^https?://" 2>/dev/null; then
      finding "HIGH" "$file" "Base64-encoded URL found — may hide exfiltration target" "Decoded: ${decoded:0:100}"
      PHASE_D_FOUND=$((PHASE_D_FOUND + 1))
    fi
  done < <(echo "$content" | grep -oE '[A-Za-z0-9+/]{20,}={0,2}' 2>/dev/null | head -10)
done

[ $PHASE_D_FOUND -eq 0 ] && log "${GREEN}  No encoded/obfuscated exfiltration detected${NC}"

# ============================================================
# Phase E: Environment Variable Leaking via MCP
# ============================================================
log ""
log "${BLUE}[5/6] Scanning environment variable leaking via MCP servers...${NC}"

PHASE_E_FOUND=0

SENSITIVE_ENV_PATTERN="(API_KEY|SECRET|TOKEN|PASSWORD|CREDENTIAL|PRIVATE_KEY|AUTH|SESSION|ACCESS_KEY|MASTER_KEY|ENCRYPTION)"

for config in "${MCP_CONFIGS[@]}"; do
  [ -f "$config" ] || continue

  servers=$(json_get "$config" ".mcpServers | keys[]" 2>/dev/null || true)
  [ -z "$servers" ] && continue

  while IFS= read -r server_name; do
    [ -z "$server_name" ] && continue

    # Get env vars for this server
    env_raw=$(json_get_value "$config" ".mcpServers.${server_name}.env" 2>/dev/null || true)
    [ -z "$env_raw" ] || [ "$env_raw" = "null" ] && continue

    # Check if env contains sensitive vars
    sensitive_vars=$(echo "$env_raw" | grep -oiE "[A-Z_]*(${SENSITIVE_ENV_PATTERN})[A-Z_]*" 2>/dev/null | sort -u || true)
    [ -z "$sensitive_vars" ] && continue

    cmd=$(json_get_value "$config" ".mcpServers.${server_name}.command" 2>/dev/null || true)
    args_raw=$(json_get_value "$config" ".mcpServers.${server_name}.args" 2>/dev/null || true)

    # If trusted MCP, report as LOW
    if is_trusted_mcp "$server_name" "$cmd"; then
      finding "LOW" "$config → mcpServers.$server_name" "Trusted MCP server receives sensitive env vars (verify scope)" "Vars: $sensitive_vars"
      PHASE_E_FOUND=$((PHASE_E_FOUND + 1))
    else
      # Check if server also has outbound capability (args with URLs)
      if echo "$cmd $args_raw" | grep -qE 'https?://|--endpoint|--webhook|--url' 2>/dev/null; then
        finding "CRITICAL" "$config → mcpServers.$server_name" "Untrusted MCP server receives sensitive env vars AND has outbound endpoints" "Vars: $sensitive_vars | Cmd: $cmd"
        PHASE_E_FOUND=$((PHASE_E_FOUND + 1))
      else
        finding "HIGH" "$config → mcpServers.$server_name" "Untrusted MCP server receives sensitive env vars" "Vars: $sensitive_vars | Cmd: $cmd"
        PHASE_E_FOUND=$((PHASE_E_FOUND + 1))
      fi
    fi

  done <<< "$servers"
done

# Check skills that reference env vars + have network tools
for skill in "${SKILL_FILES[@]}"; do
  [ -f "$skill" ] || continue
  content=$(cat "$skill" 2>/dev/null || true)

  has_env_ref=$(echo "$content" | grep -ciE "(process\\.env|os\\.environ|\\$\\{?[A-Z_]*(KEY|TOKEN|SECRET|PASSWORD))" 2>/dev/null || true)
  has_network=$(echo "$content" | grep -ciE "(WebFetch|curl|wget|fetch|http\\.request|axios|got\\()" 2>/dev/null || true)

  if [ "$has_env_ref" -gt 0 ] && [ "$has_network" -gt 0 ]; then
    finding "HIGH" "$skill" "Skill references environment variables and has network capability" "Env refs: $has_env_ref, Network refs: $has_network"
    PHASE_E_FOUND=$((PHASE_E_FOUND + 1))
  fi
done

[ $PHASE_E_FOUND -eq 0 ] && log "${GREEN}  No environment variable leaking detected${NC}"

# ============================================================
# Phase F: GitHub Source Trust Verification
# ============================================================
log ""
log "${BLUE}[6/6] Verifying source trust for MCP servers and skills...${NC}"

PHASE_F_FOUND=0

TRUSTED_ORGS="anthropics|anthropic|openai|microsoft|google|modelcontextprotocol|cloudflare|vercel|supabase|stripe|hashicorp|elastic|grafana|mozilla|figma|linear|notion|slack|sentry|datadog"

# Check MCP server source packages (npx, uvx, etc.)
for config in "${MCP_CONFIGS[@]}"; do
  [ -f "$config" ] || continue

  servers=$(json_get "$config" ".mcpServers | keys[]" 2>/dev/null || true)
  [ -z "$servers" ] && continue

  while IFS= read -r server_name; do
    [ -z "$server_name" ] && continue

    cmd=$(json_get_value "$config" ".mcpServers.${server_name}.command" 2>/dev/null || true)
    args_raw=$(json_get_value "$config" ".mcpServers.${server_name}.args" 2>/dev/null || true)
    full_cmd="$cmd $args_raw"

    # Extract package names from npx/uvx commands
    pkg=""
    if echo "$full_cmd" | grep -qE "(npx|uvx|bunx|pnpx)" 2>/dev/null; then
      pkg=$(echo "$full_cmd" | grep -oE "(npx|uvx|bunx|pnpx)\s+[a-zA-Z0-9@/_.-]+" 2>/dev/null | awk '{print $2}' | head -1 || true)
    fi

    # Extract GitHub URLs
    gh_url=$(echo "$full_cmd" | grep -oE "github\.com/[a-zA-Z0-9._-]+/[a-zA-Z0-9._-]+" 2>/dev/null | head -1 || true)

    if [ -n "$gh_url" ]; then
      org=$(echo "$gh_url" | cut -d'/' -f2)
      if echo "$org" | grep -qiE "^($TRUSTED_ORGS)$"; then
        log "${GREEN}    $server_name → $gh_url (trusted org)${NC}"
      else
        finding "MEDIUM" "$config → mcpServers.$server_name" "MCP server sourced from unverified GitHub org" "$gh_url"
        PHASE_F_FOUND=$((PHASE_F_FOUND + 1))

        # Try to check repo details via gh CLI
        if command -v gh &>/dev/null; then
          repo_path=$(echo "$gh_url" | sed 's|github.com/||')
          repo_info=$(gh api "repos/$repo_path" --jq '.stargazers_count, .archived, .created_at' 2>/dev/null || true)
          if [ -n "$repo_info" ]; then
            stars=$(echo "$repo_info" | head -1)
            archived=$(echo "$repo_info" | sed -n '2p')
            created=$(echo "$repo_info" | sed -n '3p')

            if [ "$archived" = "true" ]; then
              finding "HIGH" "$config → mcpServers.$server_name" "MCP server repo is ARCHIVED — may be abandoned/compromised" "$gh_url (archived)"
              PHASE_F_FOUND=$((PHASE_F_FOUND + 1))
            fi

            if [ -n "$stars" ] && [ "$stars" -lt 10 ] 2>/dev/null; then
              finding "MEDIUM" "$config → mcpServers.$server_name" "MCP server repo has very few stars ($stars) — low community trust" "$gh_url"
              PHASE_F_FOUND=$((PHASE_F_FOUND + 1))
            fi

            # Check if repo was created recently (within 30 days)
            if [ -n "$created" ] && command -v date &>/dev/null; then
              created_epoch=$(date -j -f "%Y-%m-%dT%H:%M:%SZ" "$created" "+%s" 2>/dev/null || date -d "$created" "+%s" 2>/dev/null || true)
              now_epoch=$(date "+%s")
              if [ -n "$created_epoch" ]; then
                age_days=$(( (now_epoch - created_epoch) / 86400 ))
                if [ "$age_days" -lt 30 ]; then
                  finding "HIGH" "$config → mcpServers.$server_name" "MCP server repo created less than 30 days ago ($age_days days) — potential typosquatting" "$gh_url (created: $created)"
                  PHASE_F_FOUND=$((PHASE_F_FOUND + 1))
                fi
              fi
            fi
          fi
        fi
      fi
    elif [ -n "$pkg" ]; then
      # Package without GitHub URL — check if it's a known/trusted package
      if echo "$pkg" | grep -qiE "^@?(${TRUSTED_ORGS})/"; then
        log "${GREEN}    $server_name → $pkg (trusted package scope)${NC}"
      else
        finding "LOW" "$config → mcpServers.$server_name" "MCP server uses package without verified source — verify on registry" "Package: $pkg"
        PHASE_F_FOUND=$((PHASE_F_FOUND + 1))
      fi
    fi

  done <<< "$servers"
done

# Check skill files for source attribution
for skill in "${SKILL_FILES[@]}"; do
  [ -f "$skill" ] || continue
  content=$(cat "$skill" 2>/dev/null || true)

  # Check if skill has author/source metadata
  has_source=$(echo "$content" | grep -ciE "^(author|source|repository|homepage):" 2>/dev/null || true)
  has_github=$(echo "$content" | grep -ciE "github\\.com" 2>/dev/null || true)

  if [ "$has_source" -eq 0 ] && [ "$has_github" -eq 0 ]; then
    # Only flag skills with risky tools
    allowed_tools=$(echo "$content" | grep -iE "^allowed.?tools:" | head -1 || true)
    if echo "$allowed_tools" | grep -qiE "(Bash|WebFetch|Write)" 2>/dev/null; then
      finding "MEDIUM" "$skill" "Skill with risky tools (Bash/WebFetch/Write) has no source attribution" "No author/source/repository metadata found"
      PHASE_F_FOUND=$((PHASE_F_FOUND + 1))
    fi
  fi
done

[ $PHASE_F_FOUND -eq 0 ] && log "${GREEN}  All sources verified or no concerns${NC}"

# ============================================================
# Final Report
# ============================================================
[ $RISK_SCORE -gt 100 ] && RISK_SCORE=100
[ $RISK_SCORE -lt 0 ] && RISK_SCORE=0

log ""
log "${BLUE}============================================================${NC}"
log "${BLUE}  MCP Exfiltration Scan Results${NC}"
log "${BLUE}============================================================${NC}"
log ""

if [ $TOTAL_FINDINGS -eq 0 ]; then
  log "${GREEN}No MCP exfiltration risks detected.${NC}"
  log ""
  log "RISK SCORE: 0/100"
  log "VERDICT: CLEAN"
else
  log "Found $TOTAL_FINDINGS issue(s):"
  [ $CRITICAL_COUNT -gt 0 ] && log "  ${RED}CRITICAL: $CRITICAL_COUNT${NC}"
  [ $HIGH_COUNT -gt 0 ] && log "  ${RED}HIGH: $HIGH_COUNT${NC}"
  [ $MEDIUM_COUNT -gt 0 ] && log "  ${YELLOW}MEDIUM: $MEDIUM_COUNT${NC}"
  [ $LOW_COUNT -gt 0 ] && log "  ${BLUE}LOW: $LOW_COUNT${NC}"
  log ""
  log "RISK SCORE: $RISK_SCORE/100"
  log ""

  if [ $RISK_SCORE -lt 20 ]; then
    log "${GREEN}VERDICT: LOW RISK${NC}"
  elif [ $RISK_SCORE -lt 50 ]; then
    log "${YELLOW}VERDICT: MEDIUM RISK — review flagged items${NC}"
  elif [ $RISK_SCORE -lt 75 ]; then
    log "${RED}VERDICT: HIGH RISK — remediate before use${NC}"
  else
    log "${RED}VERDICT: CRITICAL RISK — DO NOT USE without expert review${NC}"
  fi
fi

log ""
log "Coverage note: This scanner checks locally-configured MCP servers, skills,"
log "and plugin files. For runtime MCP tool description analysis, use mcp-scan (opt-in)."
log ""
log "Full report saved to: $REPORT_FILE"

# Exit code
if [ $RISK_SCORE -ge 75 ]; then
  exit 1
else
  exit 0
fi
