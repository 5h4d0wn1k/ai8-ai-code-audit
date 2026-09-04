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
