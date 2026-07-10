# CLAUDE.md — LLM Layer

## Purpose
Takes structured scan/test results and generates code fixes using LLMs.
Implements the model balancing strategy (escalation chain).

## Tech
- Language: Python
- Primary model: DeepSeek Coder via Ollama (local, free)
- Fallback models: Claude Haiku → Sonnet → Opus (paid, via API)
- Entry: analyzer.py

## Escalation Flow
1. DeepSeek Coder generates fix (always first attempt)
2. Self-evaluate confidence score (0.0 - 1.0)
3. If confidence < 0.5 → escalate to Haiku for classification
4. If Haiku classifies as complex → escalate to Sonnet for fix
5. If Sonnet fix fails validation → escalate to Opus (3rd attempt ONLY)

## Files
- analyzer.py         → Main entry, receives findings, dispatches to models
- ollama_client.py    → DeepSeek Coder / CodeLLaMA via Ollama API
- anthropic_client.py → Claude API client (Haiku/Sonnet/Opus)
- openai_client.py    → GPT-4o client (benchmark only)
- confidence.py       → Confidence scoring and escalation logic
- prompts/            → All prompt templates (Jinja2)

## Prompt Templates (agent/llm/prompts/)
- classify_error.j2       → Error classification prompt (dispatched)
- fix_single_file.j2      → Single-file fix generation (dispatched — the
                            only fix path analyzer.py currently has)
- fix_multi_file.j2       → Multi-file fix generation. Template exists and
                            has a routing entry in model_balancing.yml, but
                            **no orchestration code anywhere calls it** —
                            analyzer.py has no multi-file dispatch logic at
                            all. Aspirational until that's written.
- security_analysis.j2    → Security finding analysis. Same status as
                            fix_multi_file.j2 — template and config exist,
                            nothing dispatches it.
- pr_body.j2              → PR description generation (dispatched)
- confidence_eval.j2      → Independent confidence scoring via Haiku
                            (dispatched)

## Token Budgets
- Error classification:  max 500 in  / 100 out
- Single-file fix:       max 3000 in / 1000 out
- Multi-file fix:        max 8000 in / 2000 out
- PR body generation:    max 1000 in / 500 out
- Security analysis:     max 2000 in / 800 out

## Rules
- NEVER call Opus without two prior failed attempts
- NEVER modify prompts without running the evaluation suite
- All LLM calls must be logged with: model, tokens_in, tokens_out, latency
- Prompt templates are Jinja2 — keep logic out of templates
- Ollama must be running locally before any LLM calls
