#!/usr/bin/env python3
"""aggregate-findings.py — merge SARIF reports, dedup secrets, gate CI.

Part of the security-scanner skill (OWASP APTS § Reporting). Reads one or more
SARIF 2.1.0 files emitted by Gitleaks, Semgrep, Trivy, skillspector, etc.,
normalises findings, deduplicates near-identical secret hits by
(file, line, fingerprint), prints a severity rollup, and optionally exits
non-zero when a finding meets/exceeds a threshold (for CI/CD gating).

Usage:
  aggregate-findings.py [--out combined.json] [--fail-on LEVEL] FILE.sarif [FILE.sarif ...]

  --out PATH      Write the combined, deduplicated findings as JSON.
  --fail-on LEVEL  Exit 1 if any finding has severity >= LEVEL.
                   LEVEL in: critical, high, medium, low, none (default: none).

Exit codes: 0 = ok / under threshold · 1 = threshold met · 2 = usage/parse error.
No network, no LLM, deterministic — safe to run in CI.
"""
import argparse
import hashlib
import json
import sys

# SARIF result.level → our severity. SARIF only has error/warning/note/none,
# so we also read common vendor extensions (security-severity, properties).
_LEVEL_RANK = {"none": 0, "informational": 0, "low": 1, "note": 1,
               "medium": 2, "warning": 2, "high": 3, "error": 3, "critical": 4}
_GATE_RANK = {"none": 99, "low": 1, "medium": 2, "high": 3, "critical": 4}


def _severity(result, rule):
    """Best-effort severity from a SARIF result, falling back to its rule."""
    # 1) numeric security-severity (CVSS-ish 0-10) on the rule, if present
    props = (rule or {}).get("properties", {}) if rule else {}
    sec = props.get("security-severity")
    if sec is not None:
        try:
            s = float(sec)
            if s >= 9.0:
                return "critical"
            if s >= 7.0:
                return "high"
            if s >= 4.0:
                return "medium"
            if s > 0:
                return "low"
        except (TypeError, ValueError):
            pass
    # 2) explicit severity in result/rule properties
    for src in (result.get("properties", {}), props):
        for key in ("severity", "problem.severity"):
            v = src.get(key)
            if isinstance(v, str) and v.lower() in _LEVEL_RANK:
                return _canon(v.lower())
    # 3) SARIF level
    lvl = result.get("level") or (rule or {}).get("defaultConfiguration", {}).get("level")
    return _canon((lvl or "warning").lower())


def _canon(level):
    rank = _LEVEL_RANK.get(level, 2)
    return {0: "low", 1: "low", 2: "medium", 3: "high", 4: "critical"}[rank] if level not in (
        "critical", "high", "medium", "low") else level


def _loc(result):
    """Return (file, line) of the first physical location, or ('', 0)."""
    for loc in result.get("locations", []):
        phys = loc.get("physicalLocation", {})
        art = phys.get("artifactLocation", {})
        region = phys.get("region", {})
        return art.get("uri", ""), int(region.get("startLine", 0) or 0)
    return "", 0


def _fingerprint(result, rule_id, file, line):
    """Stable dedup key — prefer SARIF partialFingerprints, else hash the message."""
    fp = result.get("partialFingerprints") or {}
    if fp:
        return ";".join(f"{k}={v}" for k, v in sorted(fp.items()))
    msg = (result.get("message", {}) or {}).get("text", "")
    return hashlib.sha256(f"{rule_id}|{file}|{line}|{msg}".encode()).hexdigest()[:16]


def load_sarif(path):
    findings = []
    try:
        with open(path, encoding="utf-8") as fh:
            doc = json.load(fh)
    except (OSError, json.JSONDecodeError) as e:
        print(f"WARN  could not parse {path}: {e}", file=sys.stderr)
        return findings
    for run in doc.get("runs", []):
        tool = run.get("tool", {}).get("driver", {})
        tool_name = tool.get("name", "unknown")
        rules = {r.get("id"): r for r in tool.get("rules", [])}
        for res in run.get("results", []):
            rule_id = res.get("ruleId", "")
            rule = rules.get(rule_id)
            file, line = _loc(res)
            findings.append({
                "tool": tool_name,
                "ruleId": rule_id,
                "severity": _severity(res, rule),
                "file": file,
                "line": line,
                "message": (res.get("message", {}) or {}).get("text", "").strip(),
                "fingerprint": _fingerprint(res, rule_id, file, line),
            })
    return findings


def dedup(findings):
    """Collapse findings sharing (file, line, fingerprint); merge contributing tools."""
    seen = {}
    for f in findings:
        key = (f["file"], f["line"], f["fingerprint"])
        if key in seen:
            tools = set(seen[key]["tools"]) | {f["tool"]}
            seen[key]["tools"] = sorted(tools)
            # keep the highest severity seen for this finding
            if _GATE_RANK.get(f["severity"], 0) > _GATE_RANK.get(seen[key]["severity"], 0):
                seen[key]["severity"] = f["severity"]
        else:
            entry = dict(f)
            entry["tools"] = [f.pop("tool")]
            seen[key] = entry
    return list(seen.values())


def main():
    ap = argparse.ArgumentParser(description="Merge SARIF, dedup, gate CI.")
    ap.add_argument("sarif", nargs="+", help="SARIF files to aggregate")
    ap.add_argument("--out", help="write combined JSON to this path")
    ap.add_argument("--fail-on", default="none",
                    choices=["critical", "high", "medium", "low", "none"],
                    help="exit 1 if any finding >= this severity")
    args = ap.parse_args()

    raw = []
    for p in args.sarif:
        raw.extend(load_sarif(p))
    merged = dedup(raw)

    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for f in merged:
        counts[f["severity"]] = counts.get(f["severity"], 0) + 1
    dup_removed = len(raw) - len(merged)

    summary = {
        "total_raw": len(raw),
        "total_deduped": len(merged),
        "duplicates_removed": dup_removed,
        "by_severity": counts,
        "findings": sorted(merged, key=lambda x: (-_GATE_RANK.get(x["severity"], 0),
                                                  x["file"], x["line"])),
    }

    if args.out:
        with open(args.out, "w", encoding="utf-8") as fh:
            json.dump(summary, fh, indent=2)
        print(f"Wrote {args.out}")

    print("=== Aggregated findings (deduplicated) ===")
    print(f"raw={len(raw)}  deduped={len(merged)}  duplicates_removed={dup_removed}")
    print(f"critical={counts['critical']}  high={counts['high']}  "
          f"medium={counts['medium']}  low={counts['low']}")

    if args.fail_on != "none":
        gate = _GATE_RANK[args.fail_on]
        triggered = [f for f in merged if _GATE_RANK.get(f["severity"], 0) >= gate]
        if triggered:
            print(f"GATE FAILED: {len(triggered)} finding(s) >= {args.fail_on}", file=sys.stderr)
            sys.exit(1)
        print(f"GATE PASSED: no findings >= {args.fail_on}")
    sys.exit(0)


if __name__ == "__main__":
    main()
