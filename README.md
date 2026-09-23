> **⚠️ EDUCATIONAL USE ONLY — AUTHORIZED TESTING ONLY.**
> This project exists for education, research, and **defense of systems you own
> or hold explicit written authorization to assess**. Unauthorized use is
> prohibited and may be illegal. Read [ETHICS.md](ETHICS.md) and
> [SCOPE.md](SCOPE.md) before use. Use at your own risk; **AS IS**, no warranty.

# AI8 — AI Code Audit

AI-assisted code audit and LLM security scanner — a heuristic linter that flags vulnerable patterns
in Python source trees, including SQL concatenation, `eval`/`exec`, hardcoded secrets, insecure
deserialization, command injection, path traversal, weak crypto, missing input validation, and
prompt-injection sinks. Runs offline, standard library only.

![MIT](https://img.shields.io/badge/license-MIT-blue.svg)
![GitHub stars](https://img.shields.io/github/stars/5h4d0wn1k/ai8-ai-code-audit)
![GitHub last commit](https://img.shields.io/github/last-commit/5h4d0wn1k/ai8-ai-code-audit)
![GitHub issues](https://img.shields.io/github/issues/5h4d0wn1k/ai8-ai-code-audit)

## Why

AI-generated code ships fast — and with it, classic vulnerable patterns that a model can reproduce
more confidently than a careful junior dev. AI8 is a defensive answer: a deterministic rule engine
that scans source files for dangerous constructs with line-level precision. Rules cover
`SQL-CONCAT`, `EVAL-EXEC`, `HARDCODE-SECRET`, `PICKLE-DESERIAL`, `OS-SYSTEM`,
`SUBPROCESS-SHELL`, `WEAK-CRYPTO`, `PATH-TRAVERSAL`, `TEMPFILE-INSECURE`, `DISABLED-CSRF`,
`NO-INPUT-VALID`, `ASSERT-SECURITY`, and `PROMPT-INJECTION`. It is an ai-security and code-audit
educational tool for defensively reviewing your own AI-generated code — scanning codebases you do
not own or lack authorization for is prohibited.

## Features

- **13 detection rules** — CRITICAL/HIGH/MEDIUM/LOW classes with per-finding `rule`, `severity`,
  `line`, `code`, `desc`, and `fix`.
- **Line-level precision** — findings point at the exact source line.
- **Recursive scan** — point it at a file or a whole directory tree.
- **Embedded demo** — runs the linter on a bundled vulnerable-code fixture.
- **CI gate** — `--exit-code-on-findings` (exit `0` clean, `2` findings, `1` error).

## Quickstart

Prerequisite: Python 3 (standard library only).

```bash
python3 firmware/ai_code_audit.py                 # offline demo on the bundled fixture
python3 firmware/ai_code_audit.py path/to/file.py
python3 firmware/ai_code_audit.py path/to/project/
python3 firmware/ai_code_audit.py --quiet --output reports/ai8-report.json path/to/project/
python3 firmware/ai_code_audit.py --exit-code-on-findings path/to/project/; echo $?
```

## Examples

- `fixtures/sample-bad-code.py` — intentionally vulnerable fixture used by the demo and tests
  (expect exit code `2` on the gated run).

## Tests

```bash
python3 -m unittest discover -s tests -v
```

## Project structure

- `firmware/ai_code_audit.py` — rule engine, recursive scanner, and CLI.
- `fixtures/` — vulnerable sample code.
- `tests/` — rule triggers, negatives, recursion, JSON, and exit-code tests.

## Documentation

- [CONTRIBUTING.md](CONTRIBUTING.md)
- [SECURITY.md](SECURITY.md)
- [ETHICS.md](ETHICS.md) · [SCOPE.md](SCOPE.md)

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Keep the scanner deterministic, offline, and spec-free.

## License

MIT — see [LICENSE](LICENSE).