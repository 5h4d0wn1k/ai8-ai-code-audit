"""
AI8 — AI Code Audit
Heuristic security linter for AI-generated Python code.
"""

import re
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
        lines.append(f"  [{f['severity']:8s}] #{f['rule']}")
        lines.append(f"    Line {f['line']}: {f['code']}")
        lines.append(f"    → {f['desc']}")
        lines.append(f"    Fix: {f['fix']}")
        lines.append("")

    lines.append("=" * 64)
    return "\n".join(lines)


def main():
    findings = audit_code(SAMPLE_BAD_CODE)
    report = format_report(findings)
    print(report)
    return len(findings)


if __name__ == "__main__":
    n = main()
    raise SystemExit(0)
