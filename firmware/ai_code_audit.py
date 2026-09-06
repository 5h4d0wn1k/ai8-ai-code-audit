"""
AI8 — AI Code Audit
Heuristic security linter for AI-generated Python code.
"""

import os
import re
import sys
import keyword

RULES = [
    {
        "id": "SQL-CONCAT",
        "pattern": re.compile(r'execute\s*\(\s*["\'].*(%s|\+|\.format\(|f["\'])'),
        "severity": "HIGH",
        "desc": "SQL string concatenation/formatting — SQL injection risk",
        "fix": "Use parameterized queries: cursor.execute('SELECT * FROM t WHERE id=?', (val,))",
    },
    {
        "id": "EVAL-EXEC",
        "pattern": re.compile(r'\b(eval|exec)\s*\('),
        "severity": "CRITICAL",
        "desc": "Use of eval()/exec() — arbitrary code execution",
        "fix": "Replace eval() with ast.literal_eval() or a safe parser; remove exec() entirely",
    },
    {
        "id": "HARDCODE-SECRET",
        "pattern": re.compile(r'(password|secret|api_key|token)\s*=\s*["\'][^"\']{4,}["\']', re.IGNORECASE),
        "severity": "CRITICAL",
        "desc": "Hardcoded secret/password in source",
        "fix": "Load secrets from environment variables or a secrets manager",
    },
    {
        "id": "PICKLE-DESERIAL",
        "pattern": re.compile(r'\bpickle\.(loads?|Unpickler)\s*\('),
        "severity": "HIGH",
        "desc": "Insecure deserialization via pickle — remote code execution",
        "fix": "Use JSON, msgpack, or a signed serialization format instead of pickle",
    },
    {
        "id": "OS-SYSTEM",
        "pattern": re.compile(r'\bos\.system\s*\('),
        "severity": "HIGH",
        "desc": "os.system() with potential unvalidated input — command injection",
        "fix": "Use subprocess.run() with a list of arguments (shell=False)",
    },
    {
        "id": "SUBPROCESS-SHELL",
        "pattern": re.compile(r'\bsubprocess\.(call|run|Popen)\s*\(.*shell\s*=\s*True'),
        "severity": "HIGH",
        "desc": "subprocess with shell=True — shell injection risk",
        "fix": "Use subprocess.run([...], shell=False) with argument list",
    },
    {
        "id": "PATH-TRAVERSAL",
        "pattern": re.compile(r'open\s*\(\s*(os\.path\.join\s*\(|.*\+.*["\']\/)|(\.\.\/|\.\.\\\\)'),
        "severity": "MEDIUM",
        "desc": "Potential path traversal — user-controlled file path",
        "fix": "Validate paths with os.path.realpath() and check against allowed base directory",
    },
    {
        "id": "WEAK-CRYPTO",
        "pattern": re.compile(r'\b(md5|sha1)\s*\(', re.IGNORECASE),
        "severity": "MEDIUM",
        "desc": "Weak hash algorithm (MD5/SHA1) — collision-vulnerable",
        "fix": "Use hashlib.sha256() or hashlib.sha3_256() for security-sensitive hashing",
    },
    {
        "id": "NO-INPUT-VALID",
        "pattern": re.compile(r'input\s*\(\s*["\'].*["\']\s*\)\s*$'),
        "severity": "LOW",
        "desc": "Raw input() without validation",
        "fix": "Validate and sanitize input before using it in any sensitive operation",
    },
    {
        "id": "DISABLED-CSRF",
        "pattern": re.compile(r'(csrf_exempt|CSRF_EXEMPT|csrf_protect.*False)', re.IGNORECASE),
        "severity": "MEDIUM",
        "desc": "CSRF protection disabled",
        "fix": "Remove CSRF exemption; ensure CSRF middleware is active on all state-changing endpoints",
    },
    {
        "id": "ASSERT-SECURITY",
        "pattern": re.compile(r'\bassert\b.*'),
        "severity": "LOW",
        "desc": "assert used for security check — stripped in optimized mode",
        "fix": "Use explicit if/raise for security-critical checks (assert is removed with -O flag)",
    },
    {
        "id": "TEMPFILE-INSECURE",
        "pattern": re.compile(r'\b(mktemp|tempfile\.mktemp)\s*\('),
        "severity": "MEDIUM",
        "desc": "Insecure temporary file creation — race condition",
        "fix": "Use tempfile.mkstemp() or tempfile.NamedTemporaryFile() instead",
    },
    {
        "id": "PROMPT-INJECTION",
        "pattern": re.compile(
            r'(system|prompt|instructions)\s*=\s*(f["\']|["\'].*\{)|'
            r'\.format\(.*user|f["\'].*(user_input|request|message|content)',
            re.IGNORECASE),
        "severity": "MEDIUM",
        "desc": "Untrusted/user-controlled text interpolated into an LLM prompt — prompt-injection sink",
        "fix": "Treat LLM instructions as untrusted data: keep system prompts static, sandbox user input, "
               "and never let user content override the system prompt",
    },
]

SAMPLE_BAD_CODE = '''
import os
import pickle
import hashlib

# Hardcoded API key — CRITICAL
API_KEY = "sk-live-supersecretkey12345"

def fetch_data(user_id):
    # SQL injection via string concatenation
    query = "SELECT * FROM users WHERE id = '" + user_id + "'"
    cursor.execute(query)
    return cursor.fetchall()

def run_code(user_input):
    # eval() — arbitrary code execution
    result = eval(user_input)
    return result

def load_config(path):
    # Insecure deserialization
    with open(path, "rb") as f:
        return pickle.load(f)

def process(data):
    # os.system with unsanitized input
    os.system("echo " + data)
    return True

def hash_password(password):
    # Weak crypto
    return hashlib.md5(password.encode()).hexdigest()

def read_file(filename):
    # Path traversal
    f = open(os.path.join("/data", "../" + filename))
    return f.read()

def insecure_temp():
    # Insecure temp file
    import tempfile
    return tempfile.mktemp()

def chat(request):
    # Prompt-injection sink: user text spliced into the system prompt
    system = f"You are a support agent. User says: {request.body}"
    reply = llm_complete(system)
    return reply
'''


def audit_code(source_code):
    findings = []
    lines = source_code.split("\n")
    for line_num, line in enumerate(lines, 1):
        stripped = line.strip()
        if stripped.startswith("#"):
            continue
        for rule in RULES:
            if rule["pattern"].search(line):
                findings.append({
                    "rule": rule["id"],
                    "severity": rule["severity"],
                    "line": line_num,
                    "code": stripped[:80],
                    "desc": rule["desc"],
                    "fix": rule["fix"],
                })
    return findings


def audit_file(path):
    """Audit a single source file, returning (findings, error_or_None)."""
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            source = fh.read()
    except OSError as exc:
        return [], str(exc)
    findings = audit_code(source)
    for finding in findings:
        finding["file"] = path
    return findings, None


def audit_target(target):
    """Audit a file or directory tree. Returns (findings, errors list)."""
    errors = []
    findings = []
    if os.path.isfile(target):
        fs, err = audit_file(target)
        if err:
            errors.append(f"{target}: {err}")
        findings.extend(fs)
        return findings, errors
    for root, _dirs, files in os.walk(target):
        for name in sorted(files):
            if name.endswith((".py", ".js", ".ts")):
                path = os.path.join(root, name)
                fs, err = audit_file(path)
                if err:
                    errors.append(f"{path}: {err}")
                findings.extend(fs)
    return findings, errors


def format_report(findings):
    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    findings.sort(key=lambda f: severity_order.get(f["severity"], 99))

    lines = []
    lines.append("=" * 64)
    lines.append("  AI8 — AI Code Audit Report")
    lines.append("=" * 64)
    lines.append("")
    lines.append(f"  Total findings : {len(findings)}")

    by_sev = {}
    for f in findings:
        by_sev.setdefault(f["severity"], []).append(f)
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
        if sev in by_sev:
            lines.append(f"  {sev:10s}     : {len(by_sev[sev])}")
    lines.append("")

    for i, f in enumerate(findings, 1):
        location = f.get("file", "fixture")
        lines.append(f"  [{f['severity']:8s}] #{f['rule']} ({location})")
        lines.append(f"    Line {f['line']}: {f['code']}")
        lines.append(f"    → {f['desc']}")
        lines.append(f"    Fix: {f['fix']}")
        lines.append("")

    lines.append("=" * 64)
    return "\n".join(lines)


def main(argv=None):
    import argparse
    import json

    parser = argparse.ArgumentParser(
        prog="ai8-ai-code-audit",
        description="Static rule-based linter for vulnerable AI/MLLM code patterns "
                    "(eval, unsafe deserialization, prompt-injection sinks). "
                    "Pure-Python, offline.")
    parser.add_argument("target", nargs="?", default=None,
                        help="file or directory to audit "
                             "(default: bundled vulnerable-code fixture)")
    parser.add_argument("--output", metavar="FILE",
                        help="write JSON findings to FILE (e.g. reports/ai8-report.json)")
    parser.add_argument("--exit-code-on-findings", action="store_true",
                        help="exit 2 when any finding is emitted")
    parser.add_argument("--quiet", action="store_true",
                        help="suppress human-readable output")
    args = parser.parse_args(argv)

    if args.target is None:
        findings = audit_code(SAMPLE_BAD_CODE)
        for finding in findings:
            finding["file"] = "fixtures/sample-bad-code.py (embedded)"
    else:
        findings, errors = audit_target(args.target)
        for err in errors:
            print(f"error: {err}", file=sys.stderr)

    if args.output:
        out_dir = os.path.dirname(os.path.abspath(args.output))
        os.makedirs(out_dir, exist_ok=True)
        with open(args.output, "w", encoding="utf-8") as fh:
            json.dump({
                "findings": findings,
                "finding_count": len(findings),
                "severity_summary": {
                    sev: sum(1 for f in findings if f["severity"] == sev)
                    for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW")
                },
            }, fh, indent=2)

    if not args.quiet:
        print(format_report(list(findings)))

    if args.exit_code_on_findings and findings:
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
