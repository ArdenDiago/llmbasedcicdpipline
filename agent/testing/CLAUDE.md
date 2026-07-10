# CLAUDE.md — Test Runner Layer

## Purpose
Runs the target repo's test suite inside the sandbox container and
produces structured JSON results for downstream analysis.

## Tech
- Language: Python
- Supported runners: pytest (Python), Jest (JS/TS), Go test
- Entry: runner.py

## Flow
1. Detect project language and test framework from repo contents
2. Run test suite with JSON reporter — no dependency-install step: the
   sandbox container runs with `network_disabled=True` and `read_only=True`
   (see agent/sandbox/CLAUDE.md), so there is no network access and nowhere
   writable to install a package to. A target repo whose test suite needs
   third-party dependencies not already on the sandbox image's PATH will
   fail for that reason, not because of a real regression — this runner
   reports the framework-level `error` field (e.g. "no supported test
   framework detected", a missing runner binary, or a timeout) to flag
   infra-level failures where possible, but does **not** currently
   distinguish a target repo's own missing dependencies (which surface
   inside a successful pytest/Jest run as collection/import errors) from a
   genuine test failure. Known limitation — see the module's own findings.
3. Parse results into unified format
4. Return structured JSON: pass/fail counts, failure details, stack traces

## Output Format (JSON)
```json
{
  "framework": "pytest",
  "total": 42,
  "passed": 40,
  "failed": 2,
  "errors": 0,
  "failures": [
    {
      "test": "test_auth_login",
      "file": "tests/test_auth.py",
      "line": 23,
      "message": "AssertionError: expected 200 got 401",
      "traceback": "..."
    }
  ]
}
```

## Files
- runner.py           → Main entry, framework detection, dispatch
- parsers/pytest.py   → Parse pytest JSON output
- parsers/jest.py     → Parse Jest JSON output
- parsers/gotest.py   → Parse Go test JSON output

## Rules
- Never modify the target repo's test files
- Timeout per test suite: 5 minutes
- If no test suite found, report that — do not fabricate results
- Always capture stderr alongside test output
