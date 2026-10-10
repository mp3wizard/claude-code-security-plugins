#!/usr/bin/env python3
"""jev-annotate.py — OPT-IN Jev (TypeSafe System One) annotations for scan results.

Adds typed judgments next to existing findings. It never drops a finding, never
changes a severity, and never feeds the CI gate (aggregate-findings.py stays
deterministic and offline). Jev output is an annotation column only: scanned
content can try to steer it, so nothing downstream may act on it automatically.

Subcommands:
  triage  COMBINED_JSON --target DIR   Item 1: per SAST/skill finding, Choice on the
                                       flagged code in context: real_issue /
                                       test_or_fixture / documentation_or_prose /
                                       benign_usage. Secrets + SCA findings are
                                       never sent.
  scope   AREAS_JSON                   Item 3: Score each deep-audit candidate area
                                       (from security-analysis Section D) for audit
                                       priority. Reorders only.
  verify  CLAIMS_JSON --target DIR     Item 4: check a {id, claim, file, line} list
                                       (or deep-audit findings.json via --findings)
                                       against the cited source. Location checks
                                       are code-only (invalid_location, no API
                                       call); then Choice supports / contradicts /
                                       says_nothing.

Privacy: NOTHING is sent unless --send is given. Without it the script prints the
exact payloads it would send (dry run). Before sending, every payload is scanned
with gitleaks; flagged payloads are skipped, and if gitleaks is missing nothing is
sent (fail closed). Key: $TYPESAFE_API_KEY, else ~/.config/typesafe/env.

Common flags: --send  --max N (default 50)  --parallel N (default 4)  --out PATH
Output: JSON {mode, sent, skipped:{reason:count}, results:[...]}; exit 0, 2 on usage error.
"""
import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor

API = "https://api.typesafe.ai/v1/systemone"
# Test hook only: may point at a loopback port, never at another host (it would receive the key).
if re.match(r"http://(127\.0\.0\.1|localhost)(:\d+)?/", os.environ.get("JEV_API_URL", "")):
    API = os.environ["JEV_API_URL"]
MODEL = os.environ.get("JEV_MODEL", "jev-latest")
ACCEPT = float(os.environ.get("JEV_ACCEPT", "0.8"))
WINDOW = 15  # lines of context each side of the cited line

SECRET_TOOLS = {"gitleaks", "trufflehog"}
SECRET_WORDS = re.compile(r"secret|password|passwd|credential|api[-_ ]?key|token|private[-_ ]?key", re.I)
SCA_WORDS = re.compile(r"\bCVE-\d|\bGHSA-|vulnerab\w* (package|dependency)|osv", re.I)

TRIAGE_Q = {
    "assessment": {
        "type": "choice",
        "instructions": "A static security scanner flagged line `line` of `file` (marked >> in `snippet`) "
                        "with `scanner_message`. Considering only the code and text shown, what is the "
                        "flagged content?",
        "criteria": {
            "real_issue": "Executable application, library, or configuration code where the weakness the "
                          "scanner describes is plausibly reachable in normal use",
            "test_or_fixture": "A test, fixture, example, or intentionally vulnerable sample that is not "
                               "shipped behavior",
            "documentation_or_prose": "Documentation, comments, or prose describing a concept, not code or "
                                      "configuration that executes",
            "benign_usage": "Code that matches the scanner pattern but whose context makes it safe: constant "
                            "or validated input, sanitized output, or no security relevance",
        },
    }
}

SCOPE_Q = {
    "priority": {
        "type": "score",
        "instructions": "How valuable would a deep manual security audit of the `area` be, given `why` it "
                        "was flagged and the trust `boundary` involved?",
        "criteria": [
            "Little attacker-reachable surface; a manual audit is unlikely to find a boundary violation",
            "Some attacker-reachable input, but existing controls or narrow impact make a serious finding unlikely",
            "Attacker-reachable input near an authorization, tenant, or trust decision whose correctness the "
            "static review could not settle",
            "Directly attacker-reachable and guarding high-impact resources (accounts, tenants, money, code "
            "execution) with an unresolved control",
        ],
    }
}

VERIFY_Q = {
    "relation": {
        "type": "choice",
        "instructions": "How does the source code in `section` relate to the `claim` a security reviewer "
                        "made about `file` line `line` (marked >>)?",
        "criteria": {
            "supports": "The code shown does what the claim says at or around the cited line",
            "contradicts": "The code shown does something different from, or the opposite of, what the claim says",
            "says_nothing": "The code shown does not address what the claim asserts, either way",
        },
    }
}


# ---------- code-owned helpers (no network) ----------

def safe_path(target, raw):
    """Resolve a finding/claim path to a file inside target, or None.

    SARIF uris may be file://, percent-encoded, absolute, or relative to either the
    target or the scanner's cwd; try each reading. The realpath containment check is
    the only guard, so '..' and symlink escapes are rejected however they are spelled.
    """
    if not raw or not isinstance(raw, str):
        return None
    root = os.path.realpath(target)
    for p in dict.fromkeys((raw, urllib.parse.unquote(raw))):
        if p.startswith("file://"):
            p = p[7:]
        for base in ((None,) if os.path.isabs(p) else (root, os.getcwd())):
            real = os.path.realpath(p if base is None else os.path.join(base, p))
            if real.startswith(root + os.sep) and os.path.isfile(real):
                return real
    return None


def first_line(line):
    """Leading line number from 21, "21", "12-18", "12–18", "L12"; else None."""
    if isinstance(line, int):
        return line
    m = re.search(r"\d+", str(line or ""))
    return int(m.group()) if m else None


def section(path, line):
    """Numbered lines around `line` with the cited line marked; None if out of range."""
    line = first_line(line)
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            lines = fh.read().splitlines()
    except OSError:
        return None
    if line is None or line < 1 or line > len(lines):
        return None
    lo, hi = max(1, line - WINDOW), min(len(lines), line + WINDOW)
    return "\n".join(f"{'>>' if n == line else '  '} {n:5d}  {lines[n - 1][:400]}" for n in range(lo, hi + 1))


def is_secret_finding(f):
    tools = {t.lower() for t in f.get("tools", [f.get("tool", "")])}
    if tools & SECRET_TOOLS:
        return True
    return bool(SECRET_WORDS.search(f"{f.get('ruleId', '')} {f.get('message', '')}"))


def is_sca_finding(f):
    return bool(SCA_WORDS.search(f"{f.get('ruleId', '')} {f.get('message', '')}"))


def gitleaks_flagged(payloads):
    """Return the set of indexes whose payload gitleaks flags, or None if gitleaks is unavailable/failed."""
    if not shutil.which("gitleaks"):
        return None
    with tempfile.TemporaryDirectory() as d:
        for i, p in enumerate(payloads):
            with open(os.path.join(d, f"p{i}.txt"), "w", encoding="utf-8") as fh:
                # Raw values, one per line: JSON-escaping (\" \n) would hide quoted secrets and PEM blocks.
                fh.write("\n".join(v if isinstance(v, str) else json.dumps(v) for v in p["state"].values()))
        report = os.path.join(d, "report.json")
        rc = subprocess.run(["gitleaks", "detect", "--no-git", "--source", d, "--no-banner", "--redact",
                             "--report-format", "json", "--report-path", report],
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode
        if rc not in (0, 1):
            return None
        try:
            with open(report, encoding="utf-8") as fh:
                hits = json.load(fh) or []
        except (OSError, json.JSONDecodeError):
            return set() if rc == 0 else None
    return {int(m.group(1)) for h in hits if (m := re.search(r"p(\d+)\.txt$", h.get("File", "")))}


def api_key():
    k = os.environ.get("TYPESAFE_API_KEY")
    if k:
        return k
    try:
        with open(os.path.expanduser("~/.config/typesafe/env"), encoding="utf-8") as fh:
            for ln in fh:
                m = re.match(r"\s*(?:export\s+)?TYPESAFE_API_KEY\s*=\s*['\"]?([^'\"\s]+)", ln)
                if m:
                    return m.group(1)
    except OSError:
        pass
    return None


def ask(key, body):
    data = json.dumps({**body, "model": MODEL}).encode()
    for attempt in range(1, 6):
        req = urllib.request.Request(API, data=data, method="POST", headers={
            "Authorization": f"Bearer {key}", "Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=60) as r:
                return json.load(r)
        except urllib.error.HTTPError as e:
            if e.code in (429, 529):
                time.sleep(2 ** attempt)
                continue
            raise RuntimeError(f"typesafe HTTP {e.code}") from None  # body may echo input; don't print it
        except urllib.error.URLError as e:
            raise RuntimeError(f"typesafe unreachable: {e.reason}") from None
    raise RuntimeError("typesafe still rate-limited after 5 tries")


# ---------- build payloads per subcommand ----------

def build_triage(args):
    doc = json.load(open(args.input, encoding="utf-8"))
    items, skipped = [], []
    for f in doc.get("findings", []):
        fid = f.get("fingerprint", "")
        if is_secret_finding(f):
            skipped.append((fid, "secret_finding_never_sent"))
            continue
        if is_sca_finding(f):
            skipped.append((fid, "sca_finding_not_code_judgeable"))
            continue
        path = safe_path(args.target, f.get("file", ""))
        sec = section(path, f.get("line")) if path else None
        if not sec:
            skipped.append((fid, "location_unreadable"))
            continue
        items.append({"id": fid, "state": {
            "tool": ",".join(f.get("tools", [])), "rule": f.get("ruleId", ""),
            "scanner_message": f.get("message", "")[:1000],
            "file": os.path.relpath(path, os.path.realpath(args.target)),
            "line": f.get("line"), "snippet": sec}, "questions": TRIAGE_Q})
    return items, skipped, []


def build_scope(args):
    areas = json.load(open(args.input, encoding="utf-8"))
    items = [{"id": a.get("area") or f"area{i}", "state": {
        "area": a.get("area", ""), "paths": a.get("paths", []), "why": a.get("why", ""),
        "boundary": a.get("boundary", "")}, "questions": SCOPE_Q} for i, a in enumerate(areas)]
    return items, [], []


def claims_from_findings(path, all_verdicts=False):
    """Adapter: deep-audit findings.json trace/evidence items -> generic claims (confirmed only by default)."""
    out = []
    for rec in json.load(open(path, encoding="utf-8")):
        if not all_verdicts and rec.get("verdict") != "confirmed":
            continue
        for kind in ("trace", "evidence"):
            for i, it in enumerate(rec.get(kind, []) or []):
                out.append({"id": f"{rec.get('fingerprint', '?')}#{kind}[{i}]", "claim": it.get("description", ""),
                            "file": it.get("file", ""), "line": it.get("line"), "verdict": rec.get("verdict")})
    return out


def build_verify(args):
    claims = claims_from_findings(args.input, args.all_verdicts) if args.findings else json.load(open(args.input, encoding="utf-8"))
    items, invalid = [], []
    for c in claims:
        path = safe_path(args.target, c.get("file", ""))
        sec = section(path, c.get("line")) if path else None
        if not sec:
            # Code-owned: a path outside the target, a missing file, or a line past EOF is a
            # fabricated/stale location. No API call needed.
            invalid.append({"id": c.get("id"), "file": c.get("file"), "line": c.get("line"),
                            "verdict": "invalid_location"})
            continue
        items.append({"id": c.get("id"), "state": {
            "claim": c.get("claim", "")[:2000], "file": c.get("file"), "line": c.get("line"),
            "section": sec}, "questions": VERIFY_Q})
    return items, [], invalid


def interpret(cmd, item, ans):
    a = ans["answers"]
    if cmd == "triage":
        x = a["assessment"]
        return {"id": item["id"], "jev_assessment": x["choice"], "jev_confidence": x["confidence"],
                "jev_p_real_issue": x["probabilities"].get("real_issue"), "review": x["confidence"] < ACCEPT}
    if cmd == "scope":
        x = a["priority"]
        return {"id": item["id"], "jev_priority": x["score"], "jev_confidence": x["confidence"]}
    x = a["relation"]
    return {"id": item["id"], "verdict": {"supports": "verified", "contradicts": "contradicted",
                                          "says_nothing": "unsupported"}[x["choice"]],
            "jev_confidence": x["confidence"], "review": x["confidence"] < ACCEPT}


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("cmd", choices=["triage", "scope", "verify"])
    ap.add_argument("input")
    ap.add_argument("--target", help="scan target root (triage/verify)")
    ap.add_argument("--findings", action="store_true", help="verify: input is deep-audit findings.json")
    ap.add_argument("--all-verdicts", action="store_true",
                    help="verify --findings: also send needs_validation/rejected records")
    ap.add_argument("--send", action="store_true", help="actually call TypeSafe (default: dry run)")
    ap.add_argument("--max", type=int, default=50)
    ap.add_argument("--parallel", type=int, default=4)
    ap.add_argument("--out")
    args = ap.parse_args()
    if args.cmd in ("triage", "verify") and not args.target:
        ap.error("--target is required for triage/verify")

    try:
        items, skipped, results = {"triage": build_triage, "scope": build_scope, "verify": build_verify}[args.cmd](args)
    except (OSError, json.JSONDecodeError, AttributeError, TypeError) as e:
        print(f"jev-annotate: cannot read {args.input}: {e}", file=sys.stderr)
        sys.exit(2)

    for it in items[args.max:]:
        skipped.append((it["id"], "over_max_cap"))
    items = items[:args.max]

    mode, sent = "dry_run", 0
    if args.send and items:
        flagged = gitleaks_flagged(items)
        if flagged is None:
            skipped += [(it["id"], "gitleaks_unavailable_fail_closed") for it in items]
            items = []
        else:
            skipped += [(items[i]["id"], "payload_contains_secret") for i in sorted(flagged)]
            items = [it for i, it in enumerate(items) if i not in flagged]
        key = api_key()
        if items and not key:
            skipped += [(it["id"], "no_api_key") for it in items]
            items = []
        if items:
            mode = "sent"

            def one(it):
                try:
                    return interpret(args.cmd, it, ask(key, {"state": it["state"], "questions": it["questions"]}))
                except Exception as e:  # one bad response (timeout, reset, non-JSON) must not lose the run
                    return {"id": it["id"], "error": f"{type(e).__name__}: {e}"}
            with ThreadPoolExecutor(max_workers=max(1, args.parallel)) as pool:
                results += list(pool.map(one, items))
            sent = len(items)
    elif not args.send:
        results += [{"id": it["id"], "would_send": {"state": it["state"], "questions": it["questions"]}}
                    for it in items]

    if args.cmd == "scope":
        results.sort(key=lambda r: -(r.get("jev_priority") or -1))
    counts = {}
    for _, why in skipped:
        counts[why] = counts.get(why, 0) + 1
    out = {"mode": mode, "command": args.cmd, "model": MODEL, "sent": sent, "skipped": counts,
           "skipped_ids": [{"id": i, "reason": r} for i, r in skipped], "results": results}
    text = json.dumps(out, indent=2)
    if args.out:
        with open(args.out, "w", encoding="utf-8") as fh:
            fh.write(text + "\n")
        print(f"Wrote {args.out}  mode={mode} sent={sent} skipped={counts}")
    else:
        print(text)


if __name__ == "__main__":
    main()
