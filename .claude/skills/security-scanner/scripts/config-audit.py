#!/usr/bin/env python3
"""
Claude Code Security Audit Scanner

Scans Claude Code configurations, skills, MCP servers, and project files
for potentially malicious commands, hooks, and data exfiltration attempts.
"""

import json
import os
import re
import sys
from pathlib import Path

# Dangerous patterns in commands
EXFIL_PATTERNS = [
    (r'curl\s+.*["\']?https?://', "curl to external URL"),
    (r'wget\s+.*https?://', "wget to external URL"),
    (r'nc\s+-', "netcat connection"),
    (r'ncat\s+', "ncat connection"),
    (r'\bbase64\b', "base64 encoding (possible data obfuscation)"),
    (r'openssl\s+enc', "openssl encoding"),
    (r'\beval\s*\(', "eval() execution"),
    (r'source\s+<\(curl', "sourcing remote script"),
    (r'\$\(curl', "command substitution with curl"),
    (r'\$\(wget', "command substitution with wget"),
]

SENSITIVE_FILE_PATTERNS = [
    (r'\.ssh/', "SSH directory access"),
    (r'id_rsa', "SSH private key access"),
    (r'id_ed25519', "SSH private key access"),
    (r'\.env\b', ".env file access"),
    (r'credentials', "credentials file access"),
    (r'\.aws/', "AWS credentials access"),
    (r'\.gnupg/', "GPG keyring access"),
    (r'\.kube/config', "Kubernetes config access"),
    (r'\.docker/config', "Docker config access"),
    (r'cookie', "cookie/browser data access"),
    (r'password', "password-related access"),
    (r'/etc/shadow', "shadow file access"),
    (r'\.gitconfig', "git config access"),
    (r'\.npmrc', "npm config (may contain tokens)"),
    (r'\.pypirc', "PyPI config (may contain tokens)"),
]

DANGEROUS_CMD_PATTERNS = [
    (r'chmod\s+777', "chmod 777 (world writable)"),
    (r'rm\s+-rf\s+/', "recursive delete from root"),
    (r'mkfs', "filesystem format command"),
    (r'dd\s+if=', "dd raw disk operation"),
    (r'>\s*/dev/sd', "writing to raw disk"),
    (r'iptables\s+-F', "flushing firewall rules"),
]

CLAUDE_MD_DANGERS = [
    (r'skip.*permission', "instruction to skip permissions"),
    (r'always\s+approve', "instruction to always approve"),
    (r'without\s+asking', "instruction to act without asking"),
    (r'no.*verify', "instruction to skip verification"),
    (r'--no-verify', "git hook bypass"),
    (r'dangerouslyDisableSandbox', "sandbox disable instruction"),
    (r'skip.*hook', "hook bypass instruction"),
    (r'auto.*accept', "auto-accept instruction"),
    (r'trust.*all', "trust-all instruction"),
]


# Paths to skip (the scanner itself, and known safe skill files)
SKIP_PATHS = {
    "security-audit",  # this scanner
}

# For skills/plugins, only flag commands that appear in executable context,
# not pattern definitions or documentation
DOC_EXTENSIONS = {".md", ".txt", ".rst"}


class Finding:
    def __init__(self, severity, location, description, evidence=""):
        self.severity = severity  # CRITICAL, HIGH, MEDIUM, LOW
        self.location = location
        self.description = description
        self.evidence = evidence

    def __str__(self):
        icon = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🔵"}
        s = f"{icon.get(self.severity, '⚪')} [{self.severity}] {self.location}\n"
        s += f"  {self.description}\n"
        if self.evidence:
            ev = self.evidence[:200] + "..." if len(self.evidence) > 200 else self.evidence
            s += f"  Evidence: {ev}\n"
        return s


def load_json_safe(path):
    try:
        with open(path, "r") as f:
            return json.load(f)
    except (json.JSONDecodeError, FileNotFoundError, PermissionError):
        return None


def check_command(cmd, location, source_code=False):
    """Check a command string for dangerous patterns.

    If source_code=True, only report CRITICAL (combo attacks) and dangerous
    commands, skip standalone sensitive file references to reduce noise.
    """
    findings = []
    if not isinstance(cmd, str):
        return findings

    for pattern, desc in EXFIL_PATTERNS:
        if re.search(pattern, cmd, re.IGNORECASE):
            # Check if it also touches sensitive files
            for fp, fdesc in SENSITIVE_FILE_PATTERNS:
                if re.search(fp, cmd, re.IGNORECASE):
                    findings.append(Finding(
                        "CRITICAL", location,
                        f"Data exfiltration: {desc} combined with {fdesc}",
                        cmd.strip()
                    ))
                    return findings
            if not source_code:
                findings.append(Finding(
                    "HIGH", location, f"Suspicious command: {desc}", cmd.strip()
                ))

    if not source_code:
        for pattern, desc in SENSITIVE_FILE_PATTERNS:
            if re.search(pattern, cmd, re.IGNORECASE):
                findings.append(Finding(
                    "MEDIUM", location, f"Sensitive file reference: {desc}", cmd.strip()
                ))

    for pattern, desc in DANGEROUS_CMD_PATTERNS:
        if re.search(pattern, cmd, re.IGNORECASE):
            findings.append(Finding(
                "HIGH", location, f"Dangerous command: {desc}", cmd.strip()
            ))

    return findings


def scan_hooks(data, location):
    """Scan hooks configuration for dangerous commands."""
    findings = []
    hooks = data.get("hooks", {})
    if not hooks or not isinstance(hooks, dict):
        return findings

    findings.append(Finding(
        "LOW", location, "Hooks configuration found", json.dumps(list(hooks.keys()))
    ))

    for event_name, event_hooks in hooks.items():
        if not isinstance(event_hooks, list):
            continue
        for i, hook_entry in enumerate(event_hooks):
            matcher = hook_entry.get("matcher", "")
            if matcher == ".*" or matcher == "":
                findings.append(Finding(
                    "MEDIUM", f"{location} → {event_name}[{i}]",
                    f"Broad matcher '{matcher}' — runs on every operation",
                    json.dumps(hook_entry, ensure_ascii=False)[:300]
                ))

            hook_list = hook_entry.get("hooks", [])
            if not isinstance(hook_list, list):
                hook_list = [hook_list]
            for h in hook_list:
                if isinstance(h, dict) and h.get("type") == "command":
                    cmd = h.get("command", "")
                    findings.extend(check_command(cmd, f"{location} → {event_name}[{i}]"))

    return findings


def scan_mcp_servers(data, location):
    """Scan MCP server configurations."""
    findings = []
    servers = data.get("mcpServers", {})
    if not servers:
        return findings

    for name, config in servers.items():
        loc = f"{location} → mcpServers.{name}"
        cmd = config.get("command", "")
        args = config.get("args", [])
        full_cmd = f"{cmd} {' '.join(str(a) for a in args)}" if args else cmd

        findings.extend(check_command(full_cmd, loc))

        # Check for npx with unfamiliar packages
        if "npx" in cmd or "npx" in str(args):
            findings.append(Finding(
                "MEDIUM", loc,
                "MCP server uses npx — verify the package is trusted",
                full_cmd
            ))

        # Check env vars for tokens being passed
        env = config.get("env", {})
        for k, v in env.items() if isinstance(env, dict) else []:
            if re.search(r'(key|token|secret|password)', k, re.IGNORECASE):
                findings.append(Finding(
                    "LOW", loc,
                    f"MCP server receives sensitive env var: {k}",
                    f"{k}=<redacted>"
                ))

    return findings


def scan_claude_md(path):
    """Scan CLAUDE.md for dangerous instructions."""
    findings = []
    try:
        content = Path(path).read_text(errors="ignore")
    except (FileNotFoundError, PermissionError):
        return findings

    for pattern, desc in CLAUDE_MD_DANGERS:
        matches = re.findall(f".*{pattern}.*", content, re.IGNORECASE)
        for match in matches:
            findings.append(Finding(
                "MEDIUM", str(path), f"Suspicious instruction: {desc}", match.strip()
            ))

    # Check for hidden commands in CLAUDE.md
    findings.extend(check_command(content, str(path)))

    return findings


def scan_json_config(path):
    """Scan a JSON config file for hooks and MCP servers."""
    findings = []
    data = load_json_safe(path)
    if data is None:
        return findings

    findings.extend(scan_hooks(data, str(path)))
    findings.extend(scan_mcp_servers(data, str(path)))

    # Check skipDangerousModePermissionPrompt
    if data.get("skipDangerousModePermissionPrompt"):
        findings.append(Finding(
            "MEDIUM", str(path),
            "Dangerous mode permission prompt is disabled",
            "skipDangerousModePermissionPrompt: true"
        ))

    return findings


def scan_skills_dir(skills_dir):
    """Scan installed skills for suspicious content."""
    findings = []
    if not skills_dir.is_dir():
        return findings

    for skill_path in skills_dir.iterdir():
        if not skill_path.is_dir():
            continue
        if skill_path.name in SKIP_PATHS:
            continue
        # Check SKILL.md
        skill_md = skill_path / "SKILL.md"
        if skill_md.exists():
            try:
                content = skill_md.read_text(errors="ignore")
                findings.extend(check_command(content, f"skill:{skill_path.name}/SKILL.md"))
            except PermissionError:
                pass

        # Check scripts
        scripts_dir = skill_path / "scripts"
        if scripts_dir.is_dir():
            for script in scripts_dir.rglob("*"):
                if script.is_file():
                    try:
                        content = script.read_text(errors="ignore")
                        findings.extend(check_command(content, f"skill:{skill_path.name}/{script.relative_to(skill_path)}", source_code=True))
                    except (PermissionError, UnicodeDecodeError):
                        pass

    return findings


PLUGIN_SKIP_DIRS = {"node_modules", ".git", "dist", "build", ".next", "__pycache__", "tests", "test", "__tests__"}
PLUGIN_SCAN_EXTENSIONS = {".js", ".ts", ".mjs", ".cjs", ".sh", ".py"}


def scan_plugins_dir(plugins_dir):
    """Scan installed plugins for hooks and suspicious source code."""
    findings = []
    cache_dir = plugins_dir / "cache"
    if not cache_dir.is_dir():
        return findings

    for plugin_path in cache_dir.iterdir():
        if not plugin_path.is_dir():
            continue

        # 1. Scan JSON files for hooks
        for json_file in plugin_path.rglob("*.json"):
            if any(skip in json_file.parts for skip in PLUGIN_SKIP_DIRS):
                continue
            data = load_json_safe(json_file)
            if data and isinstance(data, dict) and "hooks" in data:
                findings.extend(scan_hooks(data, f"plugin:{plugin_path.name}/{json_file.name}"))

        # 2. Scan entry points and hook scripts (skip node_modules etc.)
        for src_file in plugin_path.rglob("*"):
            if not src_file.is_file():
                continue
            if any(skip in src_file.parts for skip in PLUGIN_SKIP_DIRS):
                continue
            if src_file.suffix not in PLUGIN_SCAN_EXTENSIONS:
                continue
            # Skip large files (>100KB likely bundled/minified)
            if src_file.stat().st_size > 100_000:
                continue
            try:
                content = src_file.read_text(errors="ignore")
                rel = src_file.relative_to(cache_dir)
                findings.extend(check_command(content, f"plugin:{rel}", source_code=True))
            except (PermissionError, UnicodeDecodeError):
                pass

    return findings


def scan_project(project_dir):
    """Scan a project directory for Claude-related security issues."""
    findings = []
    project_dir = Path(project_dir)

    # Project-level .claude configs
    for config_name in ["settings.json", "settings.local.json"]:
        config_path = project_dir / ".claude" / config_name
        if config_path.exists():
            findings.extend(scan_json_config(config_path))

    # CLAUDE.md files
    for claude_md in [
        project_dir / "CLAUDE.md",
        project_dir / ".claude" / "CLAUDE.md",
        project_dir / "claude.md",
    ]:
        if claude_md.exists():
            findings.extend(scan_claude_md(claude_md))

    return findings


def main():
    claude_dir = Path(os.environ.get("CLAUDE_CONFIG_DIR", Path.home() / ".claude"))
    findings = []

    print("=" * 60)
    print("  Claude Code Security Audit")
    print("=" * 60)
    print()

    # 1. Global settings
    print("[1/5] Scanning global settings...")
    for config_name in ["settings.json", "settings.local.json"]:
        config_path = claude_dir / config_name
        if config_path.exists():
            findings.extend(scan_json_config(config_path))

    # 2. Skills
    print("[2/5] Scanning installed skills...")
    findings.extend(scan_skills_dir(claude_dir / "skills"))

    # 3. Plugins
    print("[3/5] Scanning installed plugins...")
    findings.extend(scan_plugins_dir(claude_dir / "plugins"))

    # 4. Project-level configs (current dir or specified)
    project_dir = sys.argv[1] if len(sys.argv) > 1 else os.getcwd()
    print(f"[4/5] Scanning project: {project_dir}")
    findings.extend(scan_project(project_dir))

    # 5. Project-level settings in claude projects dir
    print("[5/5] Scanning project-specific settings...")
    projects_dir = claude_dir / "projects"
    if projects_dir.is_dir():
        for pdir in projects_dir.iterdir():
            if pdir.is_dir():
                for config_name in ["settings.json", "settings.local.json"]:
                    config_path = pdir / config_name
                    if config_path.exists():
                        findings.extend(scan_json_config(config_path))

    # Report
    print()
    print("=" * 60)
    print("  Results")
    print("=" * 60)
    print()

    if not findings:
        print("✅ No security issues found. Your configuration looks clean.")
        return

    # Sort by severity
    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    findings.sort(key=lambda f: severity_order.get(f.severity, 99))

    counts = {}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1

    print(f"Found {len(findings)} issue(s):")
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
        if sev in counts:
            print(f"  {sev}: {counts[sev]}")
    print()

    for f in findings:
        print(f)


if __name__ == "__main__":
    main()
