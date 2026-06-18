#!/usr/bin/env python3
"""Curated arXiv reference fetcher for the paper.

Searches arXiv for each entry in ``QUERIES`` (a list of
``(bibkey, search_query, must_contain_in_title)`` tuples), downloads the
matching PDF to ``Paper/paper/refs/<bibkey>.pdf``, and emits a BibTeX file at
``Paper/paper/references.bib``.

The list is curated against the project research scope (LLM vulnerability
detection, automated program repair, code LLMs, datasets, fine-tuning, and
related areas). Anything that fails to match is reported at the end so we
can swap in a different query manually instead of guessing.
"""
from __future__ import annotations

import json
import re
import sys
import time
from pathlib import Path

import arxiv

ROOT = Path(__file__).resolve().parents[2]
REFS_DIR = ROOT / "Paper" / "paper" / "refs"
BIB_PATH = ROOT / "Paper" / "paper" / "references.bib"
META_PATH = ROOT / "Paper" / "paper" / "refs" / "_meta.json"

REFS_DIR.mkdir(parents=True, exist_ok=True)


# (bibkey, search query, must-contain substring in title for accept)
# Designed so each query returns a clear top-1 hit on arXiv.
QUERIES: list[tuple[str, str, str]] = [
    # --- Code LLMs (foundation) ---
    ("chen2021codex",
     "Evaluating Large Language Models Trained on Code",
     "Evaluating Large Language Models"),
    ("li2022alphacode",
     "Competition-Level Code Generation with AlphaCode",
     "AlphaCode"),
    ("roziere2023codellama",
     "Code Llama Open Foundation Models for Code",
     "Code Llama"),
    ("li2023starcoder",
     "StarCoder may the source be with you",
     "StarCoder"),
    ("guo2024deepseekcoder",
     "DeepSeek-Coder When the Large Language Model Meets Programming",
     "DeepSeek-Coder"),
    ("hui2024qwen25coder",
     "Qwen2.5-Coder Technical Report",
     "Qwen2.5-Coder"),
    ("nijkamp2022codegen",
     "CodeGen An Open Large Language Model for Code with Multi-Turn Program Synthesis",
     "CodeGen"),
    ("fried2022incoder",
     "InCoder A Generative Model for Code Infilling and Synthesis",
     "InCoder"),

    # --- LLM-based vulnerability detection ---
    ("steenhoek2024empirical",
     "An Empirical Study of Deep Learning Models for Vulnerability Detection",
     "Vulnerability Detection"),
    ("khare2023understanding",
     "Understanding the Effectiveness of Large Language Models in Detecting Security Vulnerabilities",
     "Security Vulnerabilities"),
    ("ullah2024llmsecbench",
     "LLMs Cannot Reliably Identify and Reason About Security Vulnerabilities",
     "Security Vulnerabilities"),
    ("zhou2024large",
     "Large Language Model for Vulnerability Detection Emerging Results and Future Directions",
     "Vulnerability Detection"),
    ("purba2023software",
     "Software Vulnerability Detection using Large Language Models",
     "Vulnerability"),

    # --- Automated Program Repair (classical + neural) ---
    ("legoues2012genprog",
     "GenProg A Generic Method for Automatic Software Repair",
     "GenProg"),
    ("liu2019tbar",
     "TBar Revisiting Template-based Automated Program Repair",
     "TBar"),
    ("zhu2021syntax",
     "A Syntax-Guided Edit Decoder for Neural Program Repair",
     "Edit Decoder"),
    ("jiang2021cure",
     "CURE Code-Aware Neural Machine Translation for Automatic Program Repair",
     "CURE"),
    ("xia2022less",
     "Less Training More Repairing Please Revisiting Automated Program Repair via Zero-shot Learning",
     "Less Training"),

    # --- LLM-based APR ---
    ("xia2023automated",
     "Automated Program Repair in the Era of Large Pre-trained Language Models",
     "Program Repair"),
    ("xia2023keep",
     "Keep the Conversation Going Fixing 162 out of 337 bugs for $0.42 each using ChatGPT",
     "Conversation"),
    ("silva2023repairllama",
     "RepairLLaMA Efficient Representations and Fine-Tuned Adapters for Program Repair",
     "RepairLLaMA"),
    ("pearce2023examining",
     "Examining Zero-Shot Vulnerability Repair with Large Language Models",
     "Vulnerability Repair"),
    ("fu2023vulrepair",
     "VulRepair A T5-Based Automated Software Vulnerability Repair",
     "VulRepair"),

    # --- Datasets / benchmarks ---
    ("fan2020bigvul",
     "AC C++ Code Vulnerability Dataset with Code Changes and CVE Summaries",
     "Vulnerability Dataset"),
    ("bhandari2021cvefixes",
     "CVEfixes Automated Collection of Vulnerabilities and Their Fixes from Open-Source Software",
     "CVEfixes"),
    ("zhou2019devign",
     "Devign Effective Vulnerability Identification by Learning Comprehensive Program Semantics via Graph Neural Networks",
     "Devign"),
    ("chakraborty2021reveal",
     "Deep Learning based Vulnerability Detection Are We There Yet",
     "Vulnerability Detection"),
    ("chen2023diversevul",
     "DiverseVul A New Vulnerable Source Code Dataset for Deep Learning Based Vulnerability Detection",
     "DiverseVul"),

    # --- Fine-tuning / PEFT ---
    ("hu2021lora",
     "LoRA Low-Rank Adaptation of Large Language Models",
     "LoRA"),
    ("dettmers2023qlora",
     "QLoRA Efficient Finetuning of Quantized LLMs",
     "QLoRA"),
    ("dettmers2022llmint8",
     "LLM.int8() 8-bit Matrix Multiplication for Transformers at Scale",
     "LLM.int8"),
    ("ding2022peft",
     "Delta Tuning A Comprehensive Study of Parameter Efficient Methods for Pre-trained Language Models",
     "Delta Tuning"),

    # --- LLM cost / routing / cascading ---
    ("chen2023frugalgpt",
     "FrugalGPT How to Use Large Language Models While Reducing Cost and Improving Performance",
     "FrugalGPT"),
    ("ong2024routellm",
     "RouteLLM Learning to Route LLMs with Preference Data",
     "RouteLLM"),

    # --- Security analysis / surveys ---
    ("lin2020dlsurvey",
     "Software Vulnerability Detection Using Deep Neural Networks A Survey",
     "Survey"),
    ("hanif2021rise",
     "The Rise of Software Vulnerability Tools and the Need for a Comprehensive Survey",
     "Vulnerability"),
    ("croft2023data",
     "Data Quality for Software Vulnerability Datasets",
     "Vulnerability"),

    # --- LLM general / RAG / instruction-tuning  ---
    ("touvron2023llama2",
     "Llama 2 Open Foundation and Fine-Tuned Chat Models",
     "Llama 2"),
    ("ouyang2022instructgpt",
     "Training language models to follow instructions with human feedback",
     "human feedback"),
    ("lewis2020rag",
     "Retrieval-Augmented Generation for Knowledge-Intensive NLP Tasks",
     "Retrieval-Augmented"),

    # --- Evaluation methodology ---
    ("liu2024exploring",
     "Exploring and Evaluating Hallucinations in LLM-Powered Code Generation",
     "Hallucinations"),
    ("nguyen2023empirical",
     "An Empirical Evaluation of Using Large Language Models for Automated Unit Test Generation",
     "Unit Test"),
]


def slugify(s: str) -> str:
    return re.sub(r"[^a-zA-Z0-9._-]+", "_", s).strip("_")[:200]


def search_one(query: str, must_contain: str, retries: int = 3):
    client = arxiv.Client(page_size=10, delay_seconds=3, num_retries=3)
    s = arxiv.Search(query=query, max_results=10,
                     sort_by=arxiv.SortCriterion.Relevance)
    last_err = None
    for attempt in range(retries):
        try:
            for r in client.results(s):
                if must_contain.lower() in r.title.lower():
                    return r
            return None
        except Exception as e:
            last_err = e
            time.sleep(5 * (attempt + 1))
    raise RuntimeError(f"arXiv search failed for '{query}': {last_err}")


def to_bibtex(bibkey: str, r) -> str:
    authors = " and ".join(a.name for a in r.authors)
    year = r.published.year if r.published else ""
    arxiv_id = r.get_short_id()  # e.g. 2305.10403v2
    base_id = arxiv_id.split("v")[0]
    title = r.title.replace("\n", " ").strip()
    title = re.sub(r"\s+", " ", title)
    return (
        f"@article{{{bibkey},\n"
        f"  author    = {{{authors}}},\n"
        f"  title     = {{{title}}},\n"
        f"  year      = {{{year}}},\n"
        f"  journal   = {{arXiv preprint arXiv:{base_id}}},\n"
        f"  eprint    = {{{base_id}}},\n"
        f"  archivePrefix = {{arXiv}},\n"
        f"  url       = {{https://arxiv.org/abs/{base_id}}}\n"
        f"}}\n"
    )


def main() -> int:
    bib_entries = []
    meta = []
    failures = []

    for i, (key, q, must) in enumerate(QUERIES, 1):
        print(f"[{i:02d}/{len(QUERIES)}] {key} — searching...", flush=True)
        try:
            r = search_one(q, must)
        except Exception as e:
            print(f"   !! search error: {e}")
            failures.append((key, q, str(e)))
            continue
        if r is None:
            print(f"   !! no match for '{must}' — skip")
            failures.append((key, q, "no title-match"))
            continue

        pdf_path = REFS_DIR / f"{key}.pdf"
        if pdf_path.exists() and pdf_path.stat().st_size > 1024:
            print(f"   ✓ already downloaded -> {pdf_path.name}")
        else:
            try:
                r.download_pdf(dirpath=str(REFS_DIR), filename=f"{key}.pdf")
                print(f"   ✓ downloaded {pdf_path.stat().st_size//1024} KB")
            except Exception as e:
                print(f"   !! download error: {e}")
                failures.append((key, q, f"download: {e}"))
                continue

        bib_entries.append(to_bibtex(key, r))
        meta.append({
            "bibkey": key,
            "title": r.title,
            "arxiv_id": r.get_short_id(),
            "authors": [a.name for a in r.authors],
            "year": r.published.year if r.published else None,
            "url": r.entry_id,
            "pdf": pdf_path.name,
        })
        time.sleep(1.5)  # be polite to arXiv

    BIB_PATH.write_text("% Auto-generated by scripts/fetch_references.py\n\n" + "\n".join(bib_entries))
    META_PATH.write_text(json.dumps(meta, indent=2))

    print()
    print(f"== Summary ==")
    print(f"  fetched: {len(bib_entries)} / {len(QUERIES)}")
    print(f"  bib:     {BIB_PATH}")
    if failures:
        print(f"  failed:  {len(failures)}")
        for key, q, err in failures:
            print(f"    - {key}: {err}  (q='{q}')")
    return 0 if len(bib_entries) >= 30 else 1


if __name__ == "__main__":
    sys.exit(main())
