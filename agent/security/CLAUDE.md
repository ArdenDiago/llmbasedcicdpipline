# CLAUDE.md — Security Scanning Layer

## Purpose
Runs multiple security scanners inside the sandbox and produces unified
JSON output for the LLM layer to analyze.

## Scanners
| Scanner | What it finds | Output |
|---|---|---|
| Trivy | Container vulns, misconfigs, secrets | JSON |
| Gitleaks | Hardcoded secrets, API keys, tokens | JSON |
| Bandit | Python security issues (OWASP) | JSON |
| Semgrep | Pattern-based vulnerability detection | JSON |

## Tech
- Language: Python
- Entry: run_scan.py
- CLI: python agent/security/run_scan.py --path <dir>

## Flow
1. Receive target directory path
2. Run each scanner in parallel (subprocess)
3. Parse each scanner's JSON output
4. Normalize into unified finding format
5. Deduplicate findings across scanners
6. Assign severity (critical/high/medium/low/info)
7. Return unified JSON

## Unified Finding Format (JSON)
```json
{
  "scanner": "bandit",
  "rule_id": "B105",
  "severity": "high",
  "confidence": "high",
  "file": "app/auth.py",
  "line": 45,
  "message": "Possible hardcoded password",
  "cwe": "CWE-259",
  "snippet": "password = 'admin123'"
}
```

## Files
- run_scan.py         → Entry point, orchestrates all scanners
- scanners/trivy.py   → Trivy runner and parser
- scanners/gitleaks.py → Gitleaks runner and parser
- scanners/bandit.py  → Bandit runner and parser
- scanners/semgrep.py → Semgrep runner and parser
- scanners/codeql.py  → CodeQL runner and parser — **evaluation-only**, not
                        wired into run_scan.py's SCANNERS dict or the live
                        sandbox pipeline. Used solely by evaluation/ to
                        benchmark detection quality against the deployed
                        four-scanner set; see the module's own docstring.
- normalize.py        → Unified format conversion and dedup

## Rules
- ALL scanner output MUST be JSON — no plaintext parsing
- Never suppress scanner findings
- Always include CWE ID when available
- Dedup by file+line+rule_id — keep highest severity if conflict
- Scanner timeout: 3 minutes each, 8 minutes total
