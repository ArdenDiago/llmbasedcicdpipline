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
2. Install dependencies inside sandbox
3. Run test suite with JSON reporter
4. Parse results into unified format
5. Return structured JSON: pass/fail counts, failure details, stack traces

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
