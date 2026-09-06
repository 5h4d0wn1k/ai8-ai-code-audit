# AI8 — AI Code Audit

Heuristic security linter that detects common vulnerabilities in AI-generated Python code.

## Overview

- Scans Python source files for known dangerous patterns introduced by AI code generators
- Checks for SQL injection, eval/exec, hardcoded secrets, insecure deserialization, command injection, path traversal, weak crypto, and disabled CSRF
- Reports findings with line numbers, severity ratings, and suggested fixes
- Runs entirely offline on a built-in sample of vulnerable code
- Zero dependencies — pure Python standard library

## Features

- **12 detection rules** covering CRITICAL, HIGH, MEDIUM, and LOW severity classes
- **Line-level precision** — pinpoints exact source lines with issues
- **Severity-sorted output** — most dangerous findings surface first
- **Actionable fixes** — each finding includes a concrete remediation suggestion
- **Embedded demo** — self-test runs the linter on a sample bad-code string

## Installation

No external dependencies required — uses Python standard library only.

```bash
python3 firmware/ai_code_audit.py
```

## Usage

```python
from firmware.ai_code_audit import audit_code, format_report

with open("suspicious_code.py") as f:
    source = f.read()

findings = audit_code(source)
print(format_report(findings))
```

### CLI

```bash
# Offline demo — audits the bundled vulnerable-code fixture, prints report, exit 0
python3 firmware/ai_code_audit.py

# Audit a single file or a whole directory tree
python3 firmware/ai_code_audit.py path/to/file.py
python3 firmware/ai_code_audit.py path/to/project/

# JSON findings to reports/ (gitignored)
python3 firmware/ai_code_audit.py --quiet --output reports/ai8-report.json

# Gate CI on findings: exit 2 if anything is flagged
python3 firmware/ai_code_audit.py --exit-code-on-findings path/to/project/
echo $?    # 0 clean, 2 findings found, 1 error
```

### Exit Codes

- `0` — audit clean (or completed with `--exit-code-on-findings` and no findings)
- `1` — error (bad arguments / report write failure / unreadable file)
- `2` — `--exit-code-on-findings` and at least one finding emitted

### Live Lab Test Plan

Runs entirely offline — the linter analyzes the bundled fixture
`fixtures/sample-bad-code.py` (and any local files you point it at); nothing is
downloaded and no external scanning service is queried.

1. **Demo**: `python3 firmware/ai_code_audit.py` — expect findings across rules including `PROMPT-INJECTION` (an f-string LLM prompt sink). Exit `0`.
2. **Fixture scan**: `python3 firmware/ai_code_audit.py fixtures/sample-bad-code.py --exit-code-on-findings; echo $?` — expect `2` (fixture is intentionally vulnerable).
3. **Clean gate**: point the scanner at a directory of your own clean code — expect exit `0` and empty JSON `findings`.
4. **JSON report**: `python3 firmware/ai_code_audit.py --quiet --output reports/ai8-report.json` — verify `finding_count` and `severity_summary` match the on-screen report.
5. **Unit tests**: `python3 -m unittest discover -s tests -v` — all pass (rule triggers, clean-code negatives, line numbers, directory recursion, JSON report, exit-code gate).

## Metrics

- Real code paths exercised offline: rule engine over 13 `RULES` (incl. `HARDCODE-SECRET`, `SQL-CONCAT`, `EVAL-EXEC`, `PICKLE-DESERIAL`, `OS-SYSTEM`, `SUBPROCESS-SHELL`, `WEAK-CRYPTO`, `PATH-TRAVERSAL`, `TEMPFILE-INSECURE`, `PROMPT-INJECTION`), `audit_code`, `format_report`, recursive `audit_target`
- Metrics emitted: per-finding `rule`/`severity`/`line`/`code`/`desc`/`fix`, `finding_count`, `severity_summary`
- 10 unit tests; exit-code contract `0` clean / `1` error / `2` findings (gated)
- Zero third-party dependencies (pure stdlib), fully offline

## Example Output

```
================================================================
  AI8 — AI Code Audit Report
================================================================

  Total findings : 10
  CRITICAL     : 3
  HIGH         : 3
  MEDIUM       : 3
  LOW          : 1

  [CRITICAL] #HARDCODE-SECRET
    Line 5: API_KEY = "sk-live-supersecretkey12345"
    → Hardcoded secret/password in source
    Fix: Load secrets from environment variables or a secrets manager

  [CRITICAL] #EVAL-EXEC
    Line 14: result = eval(user_input)
    → Use of eval()/exec() — arbitrary code execution
    Fix: Replace eval() with ast.literal_eval() or a safe parser
  ...
```

## IMPORTANT: Read before use.

This tool is provided **exclusively** for authorized security research, code review, and defensive hardening. Use without explicit written authorization is illegal and unethical.

### Authorization Requirements

You must obtain explicit written permission before running this linter against codebases you do not own. Automated scanning of third-party repositories may violate terms of service.

### Legal Framework

Unauthorized access to or manipulation of computer systems is governed by the **Computer Fraud and Abuse Act (CFAA)** (18 U.S.C. § 1030), the **EU Directive on Attacks Against Information Systems** (2013/40/EU), and equivalent legislation in other jurisdictions. Penalties include imprisonment and significant fines.

### Acceptable Use

- Authorized code review and security auditing
- Defensive analysis of your own AI-generated code
- Academic research on AI code safety
- CTF competitions and educational lab environments

### Prohibited Use

- Scanning codebases without written authorization
- Using findings to exploit vulnerabilities in third-party systems
- Circumventing security controls identified by this linter
- Any use that violates applicable law or terms of service

### No Warranty

This software is provided "as is" without warranty of any kind. The authors assume no liability for damages arising from use or misuse of this tool.

### Responsible Disclosure

If you discover vulnerabilities in third-party code using this tool, follow coordinated disclosure practices. Report to the vendor directly and allow reasonable time for remediation before public disclosure.

## License

MIT License
