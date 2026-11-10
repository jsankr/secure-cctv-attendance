#!/usr/bin/env python3
"""Pre-push secret scanner (no dependencies).

    python scripts/secret_scan.py [path]        exit 1 if anything suspicious is found

Checks every file git would publish (or every file under `path` when not in a git work tree) for:
  * private keys, cloud / SaaS tokens, JWTs, connection strings with passwords
  * assignments of non-placeholder values to names like password / secret / token / key
  * high-entropy string literals
  * files that must never be committed (databases, .env, key stores, data folders)
Password-style assignments inside tests/ are throw-away fixtures and are not reported (key, token, JWT,
private-key and entropy checks still apply there). Elsewhere, mark a reviewed line with `# scan:allow <reason>`.
"""
import math
import os
import re
import subprocess
import sys
from pathlib import Path

FORBIDDEN_FILES = re.compile(r"(^|/)(\.env|secrets\.json|FIRST-LOGIN\.txt|setup-code\.txt|.*\.(db|sqlite3?|pem|key|p12|pfx|jks|kdbx)|"
                             r"id_rsa|id_ed25519|\.laptop/.*|data/.*\.(mp4|enc|jpg))$", re.I)
PATTERNS = {
    "private key": re.compile(r"-----BEGIN (RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY"),
    "AWS key": re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    "GitHub token": re.compile(r"\b(ghp|gho|ghu|ghs|ghr|github_pat)_[A-Za-z0-9_]{20,}"),
    "Slack token": re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}"),
    "Google API key": re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b"),
    "Twilio SID/key": re.compile(r"\b(AC|SK)[0-9a-f]{32}\b"),
    "Stripe key": re.compile(r"\b(sk|rk)_live_[0-9A-Za-z]{20,}"),
    "JWT": re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"),
    "credential in URL": re.compile(r"\b[a-z][a-z0-9+.-]*://[^/\s:@'\"{}$<>]+:[^/\s@'\"{}$<>]{4,}@(?!127\.0\.0\.1|localhost|example)"),
    "Cloudflare tunnel token": re.compile(r"\beyJhIjoi[A-Za-z0-9_-]{40,}"),
}
ASSIGN = re.compile(r"(?i)\b([A-Z0-9_]*(password|passwd|secret|token|api_?key|private_?key|fernet|media_key)[A-Z0-9_]*)['\"]?\s*[:=]\s*(['\"]?)([^'\"\s#,)]{8,})")
CODE_EXT = {".py", ".js", ".sh", ".ts", ".mjs"}
PLACEHOLDER = re.compile(r"(?i)^(change-?me.*|<.*>|\$\{.*|\$\(.*|\$[A-Z_]+|x+|\*+|none|null|true|false|example.*|your.*|redacted|"
                         r"settings\..*|os\.environ.*|env\[.*|sec\[.*|s\[.*|self\..*|body\..*|args\..*|cfg\..*|str|bytes|int|"
                         r"secrets\.token.*|Field\(.*|getpass.*|request\..*|r\.json.*|\w+\(.*|\w+\[.*|\w+\.\w+.*)$")
LITERAL = re.compile(r"['\"]([A-Za-z0-9+/=_-]{32,})['\"]")
SKIP_EXT = {".onnx", ".png", ".jpg", ".jpeg", ".gif", ".ico", ".woff", ".woff2", ".zip", ".mp4", ".pdf"}
ALLOW = "scan:allow"


def entropy(s: str) -> float:
    return -sum((s.count(c) / len(s)) * math.log2(s.count(c) / len(s)) for c in set(s))


def files(root: Path):
    try:
        out = subprocess.run(["git", "-C", str(root), "ls-files", "-co", "--exclude-standard"],
                             capture_output=True, text=True, check=True).stdout.split("\n")
        return [root / f for f in out if f]
    except (subprocess.CalledProcessError, FileNotFoundError):
        return [p for p in root.rglob("*") if p.is_file() and "/.git/" not in str(p)]


def scan(root: Path):
    findings = []
    for p in files(root):
        rel = str(p.relative_to(root)).replace(os.sep, "/")
        if rel.startswith("scripts/secret_scan.py"):
            continue
        if FORBIDDEN_FILES.search(rel):
            findings.append((rel, 0, "file must not be committed"))
            continue
        if p.suffix.lower() in SKIP_EXT or not p.is_file():
            continue
        try:
            text = p.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            continue
        for n, line in enumerate(text.splitlines(), 1):
            if ALLOW in line:
                continue
            for name, rx in PATTERNS.items():
                if rx.search(line):
                    findings.append((rel, n, name))
            m = ASSIGN.search(line)
            quoted_ok = p.suffix.lower() not in CODE_EXT or m and m.group(3)  # in code only string literals count
            fixture = rel.startswith("tests/")  # throw-away test passwords; key/token patterns still apply there
            if m and quoted_ok and not fixture and not PLACEHOLDER.match(m.group(4)) and not m.group(4).startswith(("{", "(", "[")):
                findings.append((rel, n, f"value assigned to {m.group(1)}"))
            for lit in LITERAL.findall(line):
                if entropy(lit) > 4.5 and not re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", lit):  # git / sha256 pins are not secrets
                    findings.append((rel, n, "high-entropy literal"))
    return findings


if __name__ == "__main__":
    root = Path(sys.argv[1] if len(sys.argv) > 1 else Path(__file__).resolve().parents[1])
    f = scan(root)
    for rel, n, why in f:
        print(f"{rel}:{n}: {why}")
    print(f"secret scan: {len(f)} finding(s) in {root}")
    sys.exit(1 if f else 0)
