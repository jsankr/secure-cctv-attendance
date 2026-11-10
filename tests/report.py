"""Builds a self-contained HTML test report from one or more pytest result files + the defect register.

    python tests/report.py results.json [more.json ...] -o report.html
"""
import argparse
import ast
import html
import re
import json
from collections import Counter, OrderedDict
from pathlib import Path

CATS = OrderedDict([
    ("HD", ("Cyber", "Security helpers (MFA, passwords, setup codes, uploads, secret scan)")),
    ("CR", ("Cyber", "Encryption & vault")),
    ("AS", ("Functional", "Anti-spoof model (suriAI/face-antispoof-onnx port)")),
    ("FE", ("Functional", "Recognition, blurring, selective unblur")),
    ("LV", ("Abuse", "Liveness & spoofing attacks")),
    ("MT", ("Functional", "Media handling")),
    ("PL", ("Cyber", "End-to-end privacy pipeline (real MediaMTX)")),
    ("FN", ("Functional", "API functional")),
    ("AB", ("Abuse", "API abuse cases")),
    ("CY", ("Cyber", "API cyber-security")),
    ("UI", ("Functional", "Console (roles, registration, XSS, CSP, accessibility)")),
])
OK = {"passed": "Pass", "failed": "FAIL", "skipped": "Skipped", "xfailed": "Known limitation", "xpassed": "Unexpected pass",
      "notrun": "Not run"}


def planned(tests_dir: Path):
    """Every test function in the suite (so tests that could not run are listed, not hidden)."""
    out = []
    for f in sorted(tests_dir.glob("test_*.py")):
        for n in ast.parse(f.read_text()).body:
            if isinstance(n, ast.FunctionDef) and n.name.startswith("test_"):
                m = re.match(r"test_([A-Z]{2})_(\d+)", n.name)
                out.append({"file": f.name, "name": n.name, "prefix": m.group(1) if m else "",
                            "id": f"{m.group(1)}-{m.group(2)}" if m else n.name,
                            "title": ((ast.get_docstring(n) or "").splitlines() or [""])[0]})
    return out


def esc(x):
    return html.escape(str(x if x is not None else ""))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("results", nargs="+")
    ap.add_argument("-o", "--out", default="report.html")
    ap.add_argument("--defects", default=str(Path(__file__).with_name("defects.json")))
    a = ap.parse_args()
    runs = [json.loads(Path(p).read_text()) for p in a.results]
    rows, seen = [], {}
    for r in runs:
        for t in r["results"]:
            seen[t["nodeid"]] = {**t, "run": r["meta"]["platform"]}  # later runs override earlier for the same test
    have = {t["nodeid"].split("::")[-1].split("[")[0] for t in seen.values()}
    for p in planned(Path(__file__).parent):
        if p["name"] not in have:
            seen[p["name"]] = {"nodeid": f"tests/{p['file']}::{p['name']}", "id": p["id"], "prefix": p["prefix"], "outcome": "notrun",
                               "duration_s": 0, "title": p["title"],
                               "message": "Not executed in this environment (dependencies unavailable). Run: python run.py --selftest"}
    rows = sorted(seen.values(), key=lambda t: (list(CATS).index(t["prefix"]) if t["prefix"] in CATS else 99, t["nodeid"]))
    reg = json.loads(Path(a.defects).read_text())
    tot = Counter(t["outcome"] for t in rows)
    by_cat = OrderedDict((k, Counter()) for k in CATS)
    for t in rows:
        by_cat.setdefault(t["prefix"], Counter())[t["outcome"]] += 1
    executed = tot["passed"] + tot["failed"] + tot["xfailed"] + tot["xpassed"]
    css = """body{font:14px/1.5 system-ui,Segoe UI,sans-serif;margin:0;background:#0b1020;color:#e6ebf5}main{max-width:1200px;margin:auto;padding:24px}
h1{font-size:24px}h2{margin-top:32px}table{border-collapse:collapse;width:100%;margin:12px 0}th,td{border-bottom:1px solid #26304a;padding:6px 8px;text-align:left;vertical-align:top}
th{color:#9aa6c4;font-weight:600}.Pass{color:#3ee6a0}.FAIL{color:#ff5d73;font-weight:700}.Skipped{color:#9aa6c4}.Known{color:#ffc857}
.cards{display:flex;gap:12px;flex-wrap:wrap}.card{background:#141b30;border:1px solid #26304a;border-radius:10px;padding:12px 16px;min-width:140px}
.card b{display:block;font-size:26px}code,pre{font:12px ui-monospace,monospace;white-space:pre-wrap}.muted{color:#9aa6c4}"""
    out = [f"<!doctype html><meta charset=utf-8><title>Sentinel Attend test report</title><style>{css}</style><main>",
           "<h1>Sentinel Attend — test report</h1>",
           "<p class=muted>" + " · ".join(f"{esc(r['meta']['platform'])}, Python {esc(r['meta']['python'])}, {esc(r['meta']['started'])}" for r in runs) + "</p>",
           "<div class=cards>" + "".join(f"<div class=card><b>{v}</b>{k}</div>" for k, v in (
               ("Tests", len(rows)), ("Executed", executed), ("Passed", tot["passed"]), ("Failed", tot["failed"]),
               ("Known limitations", tot["xfailed"]), ("Not run here", tot["notrun"]), ("Skipped", tot["skipped"]),
               ("Defects fixed", sum(d["status"] == "Fixed" for d in reg["defects"])))) + "</div>",
           "<h2>Summary by area</h2><table><tr><th>Area</th><th>Type</th><th>Tests</th><th>Pass</th><th>Fail</th><th>Known limitation</th><th>Not run</th><th>Skipped</th></tr>"]
    for k, c in by_cat.items():
        if not sum(c.values()):
            continue
        kind, name = CATS.get(k, ("Other", k))
        out.append(f"<tr><td>{esc(name)} ({k})</td><td>{kind}</td><td>{sum(c.values())}</td><td class=Pass>{c['passed']}</td>"
                   f"<td class=FAIL>{c['failed'] or ''}</td><td class=Known>{c['xfailed'] or ''}</td><td class=Skipped>{c['notrun'] or ''}</td>"
                   f"<td class=Skipped>{c['skipped'] or ''}</td></tr>")
    out.append("</table><h2>Defect register</h2><table><tr><th>ID</th><th>Severity</th><th>Area</th><th>What went wrong</th><th>Root cause</th><th>Fix</th><th>Found by</th><th>Verified by</th><th>Status</th></tr>")
    for d in reg["defects"]:
        out.append("<tr>" + "".join(f"<td>{esc(d[k])}</td>" for k in ("id", "severity", "area", "issue", "root_cause", "fix", "found_by", "verified_by", "status")) + "</tr>")
    out.append("</table><h2>Known limitations &amp; accepted risks</h2><table><tr><th>ID</th><th>Rating</th><th>Risk</th><th>Detail / mitigation</th></tr>")
    for r in reg["risks"]:
        out.append(f"<tr><td>{r['id']}</td><td>{esc(r['rating'])}</td><td>{esc(r['title'])}</td><td>{esc(r['detail'])}</td></tr>")
    out.append("</table><h2>Test-harness corrections</h2><table><tr><th>ID</th><th>Test</th><th>Issue</th><th>Fix</th></tr>")
    for t in reg["test_bugs"]:
        out.append(f"<tr><td>{t['id']}</td><td>{esc(t['test'])}</td><td>{esc(t['issue'])}</td><td>{esc(t['fix'])}</td></tr>")
    out.append("</table><h2>All test cases</h2><table><tr><th>ID</th><th>Purpose</th><th>Result</th><th>Time</th><th>Notes</th></tr>")
    for t in rows:
        res = OK.get(t["outcome"], t["outcome"])
        out.append(f"<tr><td><code>{esc(t['id'])}</code><div class=muted>{esc(t['nodeid'].split('::')[-1])}</div></td><td>{esc(t['title'])}</td>"
                   f"<td class='{res.split()[0]}'>{res}</td><td>{t['duration_s']}s</td><td><pre>{esc(t['message'][:600])}</pre></td></tr>")
    out.append("</table></main>")
    Path(a.out).write_text("\n".join(out), encoding="utf-8")
    print(f"report: {a.out}  ({len(rows)} tests: {dict(tot)})")


if __name__ == "__main__":
    main()
