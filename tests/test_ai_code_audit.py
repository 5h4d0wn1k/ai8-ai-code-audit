"""AI8 AI-code-audit engine tests — offline, pure stdlib."""

import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))), "firmware"))

from ai_code_audit import (  # noqa: E402
    SAMPLE_BAD_CODE,
    audit_code,
    audit_target,
    format_report,
    main,
    RULES,
)


def _msg(code):
    lines = code.strip().splitlines()
    return "\n".join("PYTHON:" + l for l in lines)


class TestEngine(unittest.TestCase):
    def test_bundled_sample_has_findings_with_keys(self):
        findings = audit_code(SAMPLE_BAD_CODE)
        self.assertGreaterEqual(len(findings), 8)
        for f in findings:
            for key in ("rule", "severity", "line", "code", "desc", "fix"):
                self.assertIn(key, f)

    def test_rule_trigger_all(self):
        code = (
            "import sqlite3, os, pickle, hashlib, tempfile\n"
            "API_KEY='sk-live-secret123'\n"
            "cursor.execute('SELECT * FROM users WHERE id='+uid)\n"
            "eval(user)\n"
            "pickle.loads(data)\n"
            "os.system(cmd)\n"
            "subprocess.run(cmd, shell=True)\n"
            "hashlib.md5(pw.encode()).hexdigest()\n"
            "open('/data/../'+fn)\n"
            "tempfile.mktemp()\n"
            "system=f'You are a bot. {request.body}'\n"
        )
        findings = audit_code(code)
        rules = {f["rule"] for f in findings}
        for want in ("HARDCODE-SECRET", "SQL-CONCAT", "EVAL-EXEC",
                     "PICKLE-DESERIAL", "OS-SYSTEM", "SUBPROCESS-SHELL",
                     "WEAK-CRYPTO", "PATH-TRAVERSAL", "TEMPFILE-INSECURE",
                     "PROMPT-INJECTION"):
            self.assertIn(want, rules)

    def test_clean_code_no_findings(self):
        clean = (
            "import sqlite3\n"
            "cur = conn.execute('SELECT * FROM t WHERE id = ?', (uid,))\n"
            "def add(a, b):\n"
            "    return a + b\n"
        )
        self.assertEqual(audit_code(clean), [])

    def test_rule_schema(self):
        for rule in RULES:
            for key in ("id", "pattern", "severity", "desc", "fix"):
                self.assertIn(key, rule)
            self.assertTrue(rule["pattern"].search("x") or True)

    def test_findings_have_line_numbers(self):
        code = (
            "import os\n"          # line 1
            "def go():\n"          # line 2
            "    return os.system(x)\n"  # line 3
        )
        findings = audit_code(code)
        self.assertTrue(findings)
        self.assertIn(findings[0]["line"], (3,))
        self.assertIn("os.system(x)", findings[0]["code"])

    def test_format_report_lists_rules(self):
        findings = audit_code(SAMPLE_BAD_CODE)
        report = format_report(list(findings))
        self.assertIn("AI8 — AI Code Audit Report", report)
        self.assertIn("Total findings", report)


class TestCLI(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)

    def test_audit_directory_recursive(self):
        src = os.path.join(self.tmp.name, "src")
        os.makedirs(src)
        bad = os.path.join(src, "a.py")
        with open(bad, "w", encoding="utf-8") as fh:
            fh.write("import os\nos.system(cmd)\n")
        good = os.path.join(src, "b.py")
        with open(good, "w", encoding="utf-8") as fh:
            fh.write("def ok():\n    return 1\n")
        findings, errors = audit_target(self.tmp.name)
        self.assertEqual(errors, [])
        rules = {f["rule"] for f in findings}
        self.assertIn("OS-SYSTEM", rules)
        self.assertEqual(len(findings), 1)

    def test_cli_writes_json_and_exit_codes(self):
        out = os.path.join(self.tmp.name, "report.json")
        self.assertEqual(main(["--quiet", "--output", out]), 0)
        with open(out, encoding="utf-8") as fh:
            data = json.load(fh)
        self.assertGreaterEqual(data["finding_count"], 8)
        self.assertIn("PROMPT-INJECTION",
                      {f["rule"] for f in data["findings"]})

    def test_cli_gate_returns_2_on_findings(self):
        out = os.path.join(self.tmp.name, "r.json")
        rc = main(["--exit-code-on-findings", "--quiet", "--output", out])
        self.assertEqual(rc, 2)

    def test_cli_clean_file_exits_0(self):
        v = os.path.join(self.tmp.name, "clean.py")
        with open(v, "w", encoding="utf-8") as fh:
            fh.write("def f():\n    return 0\n")
        out = os.path.join(self.tmp.name, "clean-report.json")
        rc = main(["--quiet", "--output", out, v])
        self.assertEqual(rc, 0)
        with open(out, encoding="utf-8") as fh:
            data = json.load(fh)
        self.assertEqual(data["finding_count"], 0)


if __name__ == "__main__":
    unittest.main()