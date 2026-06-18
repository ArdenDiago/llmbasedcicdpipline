"""
Multi-model, multi-run LLM detection evaluation.
Runs each model N times (default 3), reports mean ± std per dataset.
Usage:
    python evaluation/run_llm_eval.py --runs 3
    python evaluation/run_llm_eval.py --models llama3 codellama:7b mistral:7b --runs 3
"""
from __future__ import annotations
import argparse
import json
import logging
import statistics
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))
from evaluation.metrics import detection

DATASETS = REPO / "evaluation" / "datasets"
EVAL_DATASETS = [
    "python_vulns",
    "python_vulns_extended",
    "js_vulns",
    "js_vulns_extended",
]

DEFAULT_MODELS = ["llama3", "codellama:7b", "mistral:7b"]

_SYSTEM_PROMPT = """\
You are a specialist security code auditor. Find EVERY security vulnerability \
in the given source file — do not stop after the first instance of a pattern; \
if a file has 5 SQL injections, report all 5.

RULES:
1. Report the EXACT line number of the vulnerable call or assignment, NOT \
the function definition line. Line numbers are shown in the source.
2. Find ALL occurrences of each vulnerability type throughout the file.
3. Only report real, exploitable vulnerabilities — not style issues.

CHECKLIST — test every function against each of these:
• CWE-89   SQL injection: execute()/query() built with f-string, %-format, or + concat
• CWE-78   Command injection: os.system/popen, subprocess shell=True, exec()/execSync() with user input
• CWE-95   Code injection: eval(user_input), exec(user_input) on user-controlled string
• CWE-94   Template injection: Jinja2 Template()/from_string(), Mako Template(), ejs.render(), pug.compile() with user string
• CWE-22   Path traversal: open()/readFileSync() with user-controlled path, os.path.join with untrusted input
• CWE-918  SSRF: requests.get/post(), urllib.urlopen(), axios/http with user-controlled URL
• CWE-79   XSS: response with unescaped user input in HTML (res.send, make_response, f-string into HTML)
• CWE-798  Hardcoded secrets: literal passwords, API keys, tokens, DB credentials in source
• CWE-502  Insecure deserialization: pickle.loads/load(), marshal.loads(), shelve.open()
• CWE-327  Weak crypto: md5()/sha1() used for passwords, signatures, or tokens
• CWE-352  CSRF: POST route that mutates state with no CSRF token validation
• CWE-601  Open redirect: redirect() with user-controlled destination URL
• CWE-611  XXE: lxml XMLParser(resolve_entities=True) or XMLParser(load_dtd=True)
• CWE-90   LDAP injection: ldap filter built with f-string or + concat from user input
• CWE-362  TOCTOU: os.path.exists/os.access check then open on same path; predictable /tmp name
• CWE-943  NoSQL injection: MongoDB find/findOne/deleteMany with raw user object or $where interpolation
• CWE-1321 Prototype pollution: bracket-notation assignment or Object.assign with user-controlled key
• CWE-347  JWT: jwt.decode() without verify, or jwt.verify() without pinned algorithm

OUTPUT: Return ONLY a raw JSON array — no markdown, no prose, no code fences.
Schema: [{"file":"<name>","line":<int>,"cwe":"CWE-XX","severity":"high"|"medium"|"low",\
"confidence":"high"|"medium"|"low","message":"<one sentence on the specific call>"}]
Return [] if genuinely no vulnerabilities are present."""

def _number_lines(content: str) -> str:
    lines = content.splitlines()
    width = len(str(len(lines)))
    return "\n".join(f"{i+1:{width}}: {line}" for i, line in enumerate(lines))

_USER_TEMPLATE = """\
Scan this entire file for ALL vulnerabilities from the checklist above. \
Check every function. Report each vulnerable call on its own line number.

File: {filename}

{numbered_content}"""

logger = logging.getLogger("run_llm_eval")


def _ollama_call(model: str, prompt: str) -> tuple[list[dict], int, int]:
    import ollama
    client = ollama.Client(host="http://localhost:11434")
    raw = client.generate(model=model, prompt=prompt,
                          options={"num_predict": 4000, "temperature": 0.1})
    text = raw.get("response", "") if isinstance(raw, dict) else getattr(raw, "response", "")
    tok_in  = int((raw.get("prompt_eval_count") if isinstance(raw, dict)
                   else getattr(raw, "prompt_eval_count", 0)) or 0)
    tok_out = int((raw.get("eval_count") if isinstance(raw, dict)
                   else getattr(raw, "eval_count", 0)) or 0)
    text = text.strip()
    # Strip markdown fences
    if text.startswith("```"):
        text = text.split("\n", 1)[-1].rsplit("```", 1)[0].strip()
    # Extract JSON array from anywhere in the response (handles prose wrapping)
    findings = []
    start = text.find("[")
    if start != -1:
        # Find the matching closing bracket
        depth, end = 0, -1
        for i, ch in enumerate(text[start:], start):
            if ch == "[":
                depth += 1
            elif ch == "]":
                depth -= 1
                if depth == 0:
                    end = i
                    break
        if end != -1:
            try:
                parsed = json.loads(text[start:end + 1])
                if isinstance(parsed, list):
                    findings = parsed
            except json.JSONDecodeError:
                pass
    return findings, tok_in, tok_out


def run_one_dataset(ds_name: str, model: str) -> dict:
    ds_dir = DATASETS / ds_name
    gt = json.loads((ds_dir / "ground_truth.json").read_text())
    source_dir = ds_dir / "source"
    findings: list[dict] = []
    total_in = total_out = 0
    for src in sorted(source_dir.iterdir()):
        if src.suffix not in (".py", ".js", ".ts"):
            continue
        prompt = _SYSTEM_PROMPT + "\n\n" + _USER_TEMPLATE.format(
            filename=src.name,
            numbered_content=_number_lines(src.read_text(errors="replace")))
        try:
            founds, ti, to = _ollama_call(model, prompt)
        except Exception as exc:
            logger.warning("call failed %s/%s: %s", ds_name, src.name, exc)
            continue
        for f in founds:
            f.setdefault("file", src.name)
            f.setdefault("scanner", model)
        findings.extend(founds)
        total_in += ti
        total_out += to
    m = detection(findings, gt)
    return {
        "tp": m.true_positives,
        "fp": m.false_positives,
        "fn": m.false_negatives,
        "precision": m.precision,
        "recall": m.recall,
        "f1": m.f1,
        "tokens_in": total_in,
        "tokens_out": total_out,
        "n": len(gt),
    }


def run_all(models: list[str], runs: int) -> dict:
    results: dict[str, dict[str, list]] = {}
    for model in models:
        results[model] = {ds: [] for ds in EVAL_DATASETS}
        for ds in EVAL_DATASETS:
            logger.info("model=%s  dataset=%s", model, ds)
            for run_i in range(runs):
                logger.info("  run %d/%d", run_i + 1, runs)
                r = run_one_dataset(ds, model)
                results[model][ds].append(r)
                logger.info("  F1=%.3f TP=%d FP=%d FN=%d", r["f1"], r["tp"], r["fp"], r["fn"])
    return results


def summarise(results: dict) -> str:
    lines = [
        f"{'model':<22} {'dataset':<28} {'runs'} {'F1 mean':>8} {'F1 std':>7} "
        f"{'P mean':>7} {'R mean':>7} {'TP':>4} {'FP':>4} {'FN':>4}",
        "-" * 100,
    ]
    for model, ds_map in results.items():
        for ds, runs_list in ds_map.items():
            f1s   = [r["f1"] for r in runs_list]
            precs = [r["precision"] for r in runs_list]
            recs  = [r["recall"] for r in runs_list]
            std   = statistics.stdev(f1s) if len(f1s) > 1 else 0.0
            tps   = round(statistics.mean([r["tp"] for r in runs_list]))
            fps   = round(statistics.mean([r["fp"] for r in runs_list]))
            fns   = round(statistics.mean([r["fn"] for r in runs_list]))
            lines.append(
                f"{model:<22} {ds:<28} {len(runs_list):>4}  "
                f"{statistics.mean(f1s):>7.3f}  {std:>6.3f}  "
                f"{statistics.mean(precs):>6.3f}  {statistics.mean(recs):>6.3f}  "
                f"{tps:>4} {fps:>4} {fns:>4}"
            )
        lines.append("")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--models", nargs="+", default=DEFAULT_MODELS)
    p.add_argument("--runs",   type=int,  default=3)
    p.add_argument("--out",    default="evaluation/results/llm_eval_v2_results.json")
    p.add_argument("--log-level", default="INFO")
    args = p.parse_args(argv)

    logging.basicConfig(level=args.log_level,
                        format="%(asctime)s %(levelname)s: %(message)s",
                        stream=sys.stderr)

    results = run_all(args.models, args.runs)

    out_path = REPO / args.out
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(results, indent=2))

    summary = summarise(results)
    print(summary)
    summary_path = out_path.with_suffix(".txt")
    summary_path.write_text(summary)
    logger.info("saved → %s", out_path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
