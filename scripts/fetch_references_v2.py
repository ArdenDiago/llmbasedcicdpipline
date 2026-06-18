#!/usr/bin/env python3
"""Robust reference fetcher — direct arXiv IDs, no search needed.

For each entry in REFS, downloads the PDF from arxiv.org/pdf/<id> (or skips
download if the entry has no arxiv_id, in which case the BibTeX still gets
written) and emits a single ``references.bib``. PDFs are verified by size
and trailing ``%%EOF``; truncated files are re-downloaded next run.
"""
from __future__ import annotations

import json
import re
import sys
import time
from pathlib import Path

import requests

ROOT = Path(__file__).resolve().parents[2]
REFS_DIR = ROOT / "Paper" / "paper" / "refs"
BIB_PATH = ROOT / "Paper" / "paper" / "references.bib"
META_PATH = ROOT / "Paper" / "paper" / "refs" / "_meta.json"
REFS_DIR.mkdir(parents=True, exist_ok=True)

UA = ("Mozilla/5.0 (X11; Linux x86_64) "
      "AcademicReferenceFetcher/1.0 "
      "(contact: ardensavio.diago@mca.christuniversity.in)")

# (bibkey, arxiv_id_or_None, full_bibtex_entry)
# arxiv_id is the bare id (no v suffix). If None, no PDF download is
# attempted — but the BibTeX entry is still emitted for citation.
REFS: list[tuple[str, str | None, str]] = [
    # ===== Code LLMs =====
    ("chen2021codex", "2107.03374", r"""@article{chen2021codex,
  author = {Chen, Mark and Tworek, Jerry and Jun, Heewoo and Yuan, Qiming and Pinto, Henrique Ponde de Oliveira and others},
  title = {Evaluating Large Language Models Trained on Code},
  journal = {arXiv preprint arXiv:2107.03374},
  year = {2021},
  url = {https://arxiv.org/abs/2107.03374}
}"""),
    ("li2022alphacode", "2203.07814", r"""@article{li2022alphacode,
  author = {Li, Yujia and Choi, David and Chung, Junyoung and Kushman, Nate and Schrittwieser, Julian and others},
  title = {Competition-Level Code Generation with {AlphaCode}},
  journal = {Science},
  volume = {378},
  number = {6624},
  pages = {1092--1097},
  year = {2022},
  url = {https://arxiv.org/abs/2203.07814}
}"""),
    ("roziere2023codellama", "2308.12950", r"""@article{roziere2023codellama,
  author = {Rozi{\`e}re, Baptiste and Gehring, Jonas and Gloeckle, Fabian and Sootla, Sten and Gat, Itai and others},
  title = {Code {Llama}: Open Foundation Models for Code},
  journal = {arXiv preprint arXiv:2308.12950},
  year = {2023},
  url = {https://arxiv.org/abs/2308.12950}
}"""),
    ("li2023starcoder", "2305.06161", r"""@article{li2023starcoder,
  author = {Li, Raymond and Allal, Loubna Ben and Zi, Yangtian and Muennighoff, Niklas and Kocetkov, Denis and others},
  title = {{StarCoder}: May the Source be with You!},
  journal = {Transactions on Machine Learning Research},
  year = {2023},
  url = {https://arxiv.org/abs/2305.06161}
}"""),
    ("guo2024deepseekcoder", "2401.14196", r"""@article{guo2024deepseekcoder,
  author = {Guo, Daya and Zhu, Qihao and Yang, Dejian and Xie, Zhenda and Dong, Kai and others},
  title = {{DeepSeek-Coder}: When the Large Language Model Meets Programming -- The Rise of Code Intelligence},
  journal = {arXiv preprint arXiv:2401.14196},
  year = {2024},
  url = {https://arxiv.org/abs/2401.14196}
}"""),
    ("hui2024qwen25coder", "2409.12186", r"""@article{hui2024qwen25coder,
  author = {Hui, Binyuan and Yang, Jian and Cui, Zeyu and Yang, Jiaxi and Liu, Dayiheng and others},
  title = {{Qwen2.5-Coder} Technical Report},
  journal = {arXiv preprint arXiv:2409.12186},
  year = {2024},
  url = {https://arxiv.org/abs/2409.12186}
}"""),
    ("nijkamp2022codegen", "2203.13474", r"""@inproceedings{nijkamp2022codegen,
  author = {Nijkamp, Erik and Pang, Bo and Hayashi, Hiroaki and Tu, Lifu and Wang, Huan and others},
  title = {{CodeGen}: An Open Large Language Model for Code with Multi-Turn Program Synthesis},
  booktitle = {International Conference on Learning Representations (ICLR)},
  year = {2023},
  url = {https://arxiv.org/abs/2203.13474}
}"""),
    ("fried2022incoder", "2204.05999", r"""@inproceedings{fried2022incoder,
  author = {Fried, Daniel and Aghajanyan, Armen and Lin, Jessy and Wang, Sida and Wallace, Eric and others},
  title = {{InCoder}: A Generative Model for Code Infilling and Synthesis},
  booktitle = {International Conference on Learning Representations (ICLR)},
  year = {2023},
  url = {https://arxiv.org/abs/2204.05999}
}"""),

    # ===== LLM-based vulnerability detection =====
    ("steenhoek2024empirical", "2403.17218", r"""@inproceedings{steenhoek2024empirical,
  author = {Steenhoek, Benjamin and Rahman, Md Mahbubur and Roy, Monoshi Kumar and Alam, Mirza Sanjida and Barr, Earl T. and Le, Wei},
  title = {A Comprehensive Study of the Capabilities of Large Language Models for Vulnerability Detection},
  booktitle = {Proc. International Conference on Software Engineering (ICSE)},
  year = {2024},
  url = {https://arxiv.org/abs/2403.17218}
}"""),
    ("khare2023understanding", "2311.16169", r"""@article{khare2023understanding,
  author = {Khare, Avishree and Dutta, Saikat and Li, Ziyang and Solko-Breslin, Alaia and Alur, Rajeev and Naik, Mayur},
  title = {Understanding the Effectiveness of Large Language Models in Detecting Security Vulnerabilities},
  journal = {arXiv preprint arXiv:2311.16169},
  year = {2023},
  url = {https://arxiv.org/abs/2311.16169}
}"""),
    ("ullah2024llmsecbench", "2312.12575", r"""@inproceedings{ullah2024llmsecbench,
  author = {Ullah, Saad and Han, Mingji and Pujar, Saurabh and Pearce, Hammond and Coskun, Ayse and Stringhini, Gianluca},
  title = {{LLMs} Cannot Reliably Identify and Reason About Security Vulnerabilities (Yet?): A Comprehensive Evaluation, Framework, and Benchmarks},
  booktitle = {IEEE Symposium on Security and Privacy (S\&P)},
  year = {2024},
  url = {https://arxiv.org/abs/2312.12575}
}"""),
    ("zhou2024large", "2404.02525", r"""@inproceedings{zhou2024large,
  author = {Zhou, Xin and Cao, Sicong and Sun, Xiaobing and Lo, David},
  title = {Large Language Model for Vulnerability Detection and Repair: Literature Review and the Road Ahead},
  booktitle = {ACM Transactions on Software Engineering and Methodology},
  year = {2024},
  url = {https://arxiv.org/abs/2404.02525}
}"""),
    ("purba2023software", "2308.10523", r"""@inproceedings{purba2023software,
  author = {Purba, Moumita Das and Ghosh, Arpita and Radford, Benjamin J. and Chu, Bill},
  title = {Software Vulnerability Detection using Large Language Models},
  booktitle = {IEEE International Symposium on Software Reliability Engineering Workshops (ISSREW)},
  year = {2023},
  url = {https://arxiv.org/abs/2308.10523}
}"""),

    # ===== Automated Program Repair =====
    ("legoues2012genprog", None, r"""@article{legoues2012genprog,
  author = {Le Goues, Claire and Nguyen, ThanhVu and Forrest, Stephanie and Weimer, Westley},
  title = {{GenProg}: A Generic Method for Automatic Software Repair},
  journal = {IEEE Transactions on Software Engineering},
  volume = {38},
  number = {1},
  pages = {54--72},
  year = {2012}
}"""),
    ("liu2019tbar", None, r"""@inproceedings{liu2019tbar,
  author = {Liu, Kui and Koyuncu, Anil and Kim, Dongsun and Bissyand{\'e}, Tegawend{\'e} F.},
  title = {{TBar}: Revisiting Template-based Automated Program Repair},
  booktitle = {Proc. 28th ACM SIGSOFT International Symposium on Software Testing and Analysis (ISSTA)},
  pages = {31--42},
  year = {2019}
}"""),
    ("zhu2021recoder", None, r"""@inproceedings{zhu2021recoder,
  author = {Zhu, Qihao and Sun, Zeyu and Xiao, Yuan-an and Zhang, Wenjie and Yuan, Kang and Xiong, Yingfei and Zhang, Lu},
  title = {A Syntax-Guided Edit Decoder for Neural Program Repair},
  booktitle = {Proc. 29th ACM ESEC/FSE},
  year = {2021}
}"""),
    ("jiang2021cure", None, r"""@inproceedings{jiang2021cure,
  author = {Jiang, Nan and Lutellier, Thibaud and Tan, Lin},
  title = {{CURE}: Code-Aware Neural Machine Translation for Automatic Program Repair},
  booktitle = {Proc. 43rd International Conference on Software Engineering (ICSE)},
  pages = {1161--1173},
  year = {2021}
}"""),
    ("xia2022less", "2207.08281", r"""@inproceedings{xia2022less,
  author = {Xia, Chunqiu Steven and Zhang, Lingming},
  title = {Less Training, More Repairing Please: Revisiting Automated Program Repair via Zero-Shot Learning},
  booktitle = {Proc. ACM ESEC/FSE},
  year = {2022},
  url = {https://arxiv.org/abs/2207.08281}
}"""),
    ("xia2023automated", "2210.14179", r"""@inproceedings{xia2023automated,
  author = {Xia, Chunqiu Steven and Wei, Yuxiang and Zhang, Lingming},
  title = {Automated Program Repair in the Era of Large Pre-trained Language Models},
  booktitle = {Proc. International Conference on Software Engineering (ICSE)},
  year = {2023},
  url = {https://arxiv.org/abs/2210.14179}
}"""),
    ("xia2023keep", "2304.00385", r"""@article{xia2023keep,
  author = {Xia, Chunqiu Steven and Zhang, Lingming},
  title = {Keep the Conversation Going: Fixing 162 out of 337 bugs for \$0.42 each using {ChatGPT}},
  journal = {arXiv preprint arXiv:2304.00385},
  year = {2023},
  url = {https://arxiv.org/abs/2304.00385}
}"""),
    ("silva2023repairllama", "2312.15698", r"""@article{silva2023repairllama,
  author = {Silva, Andr{\'e} and Fang, Sen and Monperrus, Martin},
  title = {{RepairLLaMA}: Efficient Representations and Fine-Tuned Adapters for Program Repair},
  journal = {arXiv preprint arXiv:2312.15698},
  year = {2023},
  url = {https://arxiv.org/abs/2312.15698}
}"""),
    ("pearce2023examining", "2112.02125", r"""@inproceedings{pearce2023examining,
  author = {Pearce, Hammond and Tan, Benjamin and Ahmad, Baleegh and Karri, Ramesh and Dolan-Gavitt, Brendan},
  title = {Examining Zero-Shot Vulnerability Repair with Large Language Models},
  booktitle = {IEEE Symposium on Security and Privacy (S\&P)},
  year = {2023},
  url = {https://arxiv.org/abs/2112.02125}
}"""),
    ("fu2023vulrepair", "2205.13680", r"""@inproceedings{fu2023vulrepair,
  author = {Fu, Michael and Tantithamthavorn, Chakkrit and Le, Trung and Nguyen, Van and Phung, Dinh},
  title = {{VulRepair}: A {T5}-Based Automated Software Vulnerability Repair},
  booktitle = {Proc. ACM ESEC/FSE},
  year = {2022},
  url = {https://arxiv.org/abs/2205.13680}
}"""),

    # ===== Datasets / benchmarks =====
    ("fan2020bigvul", None, r"""@inproceedings{fan2020bigvul,
  author = {Fan, Jiahao and Li, Yi and Wang, Shaohua and Nguyen, Tien N.},
  title = {{A C/C++} Code Vulnerability Dataset with Code Changes and {CVE} Summaries},
  booktitle = {Proc. 17th International Conference on Mining Software Repositories (MSR)},
  pages = {508--512},
  year = {2020}
}"""),
    ("bhandari2021cvefixes", "2107.08760", r"""@inproceedings{bhandari2021cvefixes,
  author = {Bhandari, Guru and Naseer, Amara and Moonen, Leon},
  title = {{CVEfixes}: Automated Collection of Vulnerabilities and Their Fixes from Open-Source Software},
  booktitle = {17th International Conference on Predictive Models and Data Analytics in Software Engineering (PROMISE)},
  year = {2021},
  url = {https://arxiv.org/abs/2107.08760}
}"""),
    ("zhou2019devign", "1909.03496", r"""@inproceedings{zhou2019devign,
  author = {Zhou, Yaqin and Liu, Shangqing and Siow, Jingkai and Du, Xiaoning and Liu, Yang},
  title = {{Devign}: Effective Vulnerability Identification by Learning Comprehensive Program Semantics via Graph Neural Networks},
  booktitle = {Proc. NeurIPS},
  year = {2019},
  url = {https://arxiv.org/abs/1909.03496}
}"""),
    ("chakraborty2021reveal", "2009.07235", r"""@article{chakraborty2021reveal,
  author = {Chakraborty, Saikat and Krishna, Rahul and Ding, Yangruibo and Ray, Baishakhi},
  title = {Deep Learning Based Vulnerability Detection: Are We There Yet?},
  journal = {IEEE Transactions on Software Engineering},
  year = {2022},
  url = {https://arxiv.org/abs/2009.07235}
}"""),
    ("chen2023diversevul", "2304.00409", r"""@inproceedings{chen2023diversevul,
  author = {Chen, Yizheng and Ding, Zhoujie and Alowain, Lamya and Chen, Xinyun and Wagner, David},
  title = {{DiverseVul}: A New Vulnerable Source Code Dataset for Deep Learning Based Vulnerability Detection},
  booktitle = {Proc. 26th International Symposium on Research in Attacks, Intrusions and Defenses (RAID)},
  year = {2023},
  url = {https://arxiv.org/abs/2304.00409}
}"""),

    # ===== Static analysis tooling =====
    ("bessey2010fewbillion", None, r"""@article{bessey2010fewbillion,
  author = {Bessey, Al and Block, Ken and Chelf, Ben and Chou, Andy and Fulton, Bryan and others},
  title = {A Few Billion Lines of Code Later: Using Static Analysis to Find Bugs in the Real World},
  journal = {Communications of the ACM},
  volume = {53},
  number = {2},
  pages = {66--75},
  year = {2010}
}"""),
    ("avgustinov2016codeql", None, r"""@inproceedings{avgustinov2016codeql,
  author = {Avgustinov, Pavel and de Moor, Oege and Jones, Michael Peyton and Sch{\"a}fer, Max},
  title = {{QL}: Object-Oriented Queries on Relational Data},
  booktitle = {30th European Conference on Object-Oriented Programming (ECOOP)},
  year = {2016}
}"""),

    # ===== Fine-tuning / PEFT =====
    ("hu2021lora", "2106.09685", r"""@inproceedings{hu2021lora,
  author = {Hu, Edward J. and Shen, Yelong and Wallis, Phillip and Allen-Zhu, Zeyuan and Li, Yuanzhi and Wang, Shean and Wang, Lu and Chen, Weizhu},
  title = {{LoRA}: Low-Rank Adaptation of Large Language Models},
  booktitle = {International Conference on Learning Representations (ICLR)},
  year = {2022},
  url = {https://arxiv.org/abs/2106.09685}
}"""),
    ("dettmers2023qlora", "2305.14314", r"""@inproceedings{dettmers2023qlora,
  author = {Dettmers, Tim and Pagnoni, Artidoro and Holtzman, Ari and Zettlemoyer, Luke},
  title = {{QLoRA}: Efficient Finetuning of Quantized {LLMs}},
  booktitle = {Advances in Neural Information Processing Systems (NeurIPS)},
  year = {2023},
  url = {https://arxiv.org/abs/2305.14314}
}"""),
    ("dettmers2022llmint8", "2208.07339", r"""@inproceedings{dettmers2022llmint8,
  author = {Dettmers, Tim and Lewis, Mike and Belkada, Younes and Zettlemoyer, Luke},
  title = {{LLM.int8()}: 8-bit Matrix Multiplication for Transformers at Scale},
  booktitle = {Advances in Neural Information Processing Systems (NeurIPS)},
  year = {2022},
  url = {https://arxiv.org/abs/2208.07339}
}"""),
    ("ding2023parameter", "2203.06904", r"""@article{ding2023parameter,
  author = {Ding, Ning and Qin, Yujia and Yang, Guang and Wei, Fuchao and Yang, Zonghan and others},
  title = {Parameter-efficient fine-tuning of large-scale pre-trained language models},
  journal = {Nature Machine Intelligence},
  year = {2023},
  url = {https://arxiv.org/abs/2203.06904}
}"""),

    # ===== LLM cost / routing / cascading =====
    ("chen2023frugalgpt", "2305.05176", r"""@article{chen2023frugalgpt,
  author = {Chen, Lingjiao and Zaharia, Matei and Zou, James},
  title = {{FrugalGPT}: How to Use Large Language Models While Reducing Cost and Improving Performance},
  journal = {arXiv preprint arXiv:2305.05176},
  year = {2023},
  url = {https://arxiv.org/abs/2305.05176}
}"""),
    ("ong2024routellm", "2406.18665", r"""@article{ong2024routellm,
  author = {Ong, Isaac and Almahairi, Amjad and Wu, Vincent and Chiang, Wei-Lin and Wu, Tianhao and others},
  title = {{RouteLLM}: Learning to Route {LLMs} with Preference Data},
  journal = {arXiv preprint arXiv:2406.18665},
  year = {2024},
  url = {https://arxiv.org/abs/2406.18665}
}"""),

    # ===== Surveys / data quality =====
    ("croft2023data", "2301.05456", r"""@inproceedings{croft2023data,
  author = {Croft, Roland and Babar, M. Ali and Kholoosi, M. Mehdi},
  title = {Data Quality for Software Vulnerability Datasets},
  booktitle = {Proc. International Conference on Software Engineering (ICSE)},
  year = {2023},
  url = {https://arxiv.org/abs/2301.05456}
}"""),
    ("hanif2021rise", "2103.16064", r"""@inproceedings{hanif2021rise,
  author = {Hanif, Hazim and Md Nasir, Mohd Hairul Nizam and Ab Razak, Mohd Faizal and Firdaus, Ahmad and Anuar, Nor Badrul},
  title = {The Rise of Software Vulnerability: Taxonomy of Software Vulnerabilities Detection and Machine Learning Approaches},
  booktitle = {Journal of Network and Computer Applications},
  year = {2021},
  url = {https://arxiv.org/abs/2103.16064}
}"""),

    # ===== LLM general / RAG =====
    ("touvron2023llama2", "2307.09288", r"""@article{touvron2023llama2,
  author = {Touvron, Hugo and Martin, Louis and Stone, Kevin and Albert, Peter and Almahairi, Amjad and others},
  title = {{Llama 2}: Open Foundation and Fine-Tuned Chat Models},
  journal = {arXiv preprint arXiv:2307.09288},
  year = {2023},
  url = {https://arxiv.org/abs/2307.09288}
}"""),
    ("ouyang2022instructgpt", "2203.02155", r"""@inproceedings{ouyang2022instructgpt,
  author = {Ouyang, Long and Wu, Jeffrey and Jiang, Xu and Almeida, Diogo and Wainwright, Carroll L. and others},
  title = {Training language models to follow instructions with human feedback},
  booktitle = {Advances in Neural Information Processing Systems (NeurIPS)},
  year = {2022},
  url = {https://arxiv.org/abs/2203.02155}
}"""),
    ("lewis2020rag", "2005.11401", r"""@inproceedings{lewis2020rag,
  author = {Lewis, Patrick and Perez, Ethan and Piktus, Aleksandra and Petroni, Fabio and Karpukhin, Vladimir and others},
  title = {Retrieval-Augmented Generation for Knowledge-Intensive {NLP} Tasks},
  booktitle = {Advances in Neural Information Processing Systems (NeurIPS)},
  year = {2020},
  url = {https://arxiv.org/abs/2005.11401}
}"""),

    # ===== Evaluation methodology =====
    ("liu2024exploring", "2404.00971", r"""@article{liu2024exploring,
  author = {Liu, Fang and Liu, Yang and Shi, Lin and Huang, Houkun and Wang, Ruifeng and others},
  title = {Exploring and Evaluating Hallucinations in {LLM}-Powered Code Generation},
  journal = {arXiv preprint arXiv:2404.00971},
  year = {2024},
  url = {https://arxiv.org/abs/2404.00971}
}"""),
    ("nguyen2023empirical", "2305.00418", r"""@article{nguyen2023empirical,
  author = {Nguyen, Andre and Stoddart, John and Heimdahl, Mats P.E. and Whalen, Mike and Cofer, Darren},
  title = {An Empirical Evaluation of Using {LLMs} for Automated Unit Test Generation},
  journal = {arXiv preprint arXiv:2305.00418},
  year = {2023},
  url = {https://arxiv.org/abs/2305.00418}
}"""),

    # ===== DevSecOps / CI security =====
    ("rajapakse2022challenges", "2103.08266", r"""@article{rajapakse2022challenges,
  author = {Rajapakse, Roshan Namal and Zahedi, Mansooreh and Babar, M. Ali and Shen, Haifeng},
  title = {Challenges and solutions when adopting {DevSecOps}: A systematic review},
  journal = {Information and Software Technology},
  year = {2022},
  url = {https://arxiv.org/abs/2103.08266}
}"""),
    ("rahman2019gangoftwelve", None, r"""@inproceedings{rahman2019gangoftwelve,
  author = {Rahman, Akond and Parnin, Chris and Williams, Laurie},
  title = {The Seven Sins: Security Smells in Infrastructure as Code Scripts},
  booktitle = {Proc. 41st International Conference on Software Engineering (ICSE)},
  year = {2019}
}"""),
]


def is_valid_pdf(path: Path) -> bool:
    if not path.exists() or path.stat().st_size < 50_000:
        return False
    with open(path, "rb") as f:
        head = f.read(4)
        if head != b"%PDF":
            return False
        f.seek(-1024, 2)  # last 1KB
        tail = f.read()
        return b"%%EOF" in tail


def download(arxiv_id: str, out: Path, max_attempts: int = 4) -> bool:
    """Download with exponential backoff. Try v2 → v1 → bare id."""
    candidates = [
        f"https://arxiv.org/pdf/{arxiv_id}.pdf",
        f"https://arxiv.org/pdf/{arxiv_id}v2.pdf",
        f"https://arxiv.org/pdf/{arxiv_id}v1.pdf",
    ]
    for attempt in range(max_attempts):
        for url in candidates:
            try:
                with requests.get(url, headers={"User-Agent": UA},
                                  timeout=120, stream=True) as resp:
                    if resp.status_code == 429:
                        wait = 30 * (attempt + 1)
                        print(f"      429 — backing off {wait}s")
                        time.sleep(wait)
                        break  # break inner, retry outer
                    if resp.status_code != 200:
                        continue
                    out.write_bytes(resp.content)
                if is_valid_pdf(out):
                    return True
                print(f"      truncated; size={out.stat().st_size}")
            except Exception as e:
                print(f"      err {url}: {e}")
            time.sleep(2)
        time.sleep(5 * (attempt + 1))
    return False


def main() -> int:
    bib_blocks = ["% Auto-generated by scripts/fetch_references_v2.py\n"]
    meta = []
    fails = []

    for i, (key, aid, bib) in enumerate(REFS, 1):
        bib_blocks.append(bib + "\n")

        if aid is None:
            print(f"[{i:02d}/{len(REFS)}] {key} — venue paper, no PDF")
            meta.append({"bibkey": key, "arxiv_id": None, "pdf": None})
            continue

        out = REFS_DIR / f"{key}.pdf"
        if is_valid_pdf(out):
            print(f"[{i:02d}/{len(REFS)}] {key} — ✓ valid PDF, skip")
            meta.append({"bibkey": key, "arxiv_id": aid, "pdf": out.name})
            continue

        print(f"[{i:02d}/{len(REFS)}] {key} — downloading {aid}...")
        ok = download(aid, out)
        if ok:
            print(f"      ✓ {out.stat().st_size//1024} KB")
            meta.append({"bibkey": key, "arxiv_id": aid, "pdf": out.name})
        else:
            print(f"      ✗ failed after retries")
            fails.append(key)
            if out.exists():
                out.unlink()
        time.sleep(3)  # polite spacing between IDs

    BIB_PATH.write_text("\n".join(bib_blocks))
    META_PATH.write_text(json.dumps(meta, indent=2))

    pdfs_ok = sum(1 for m in meta if m["pdf"])
    print()
    print(f"== Summary ==")
    print(f"  bib entries:  {len(REFS)}")
    print(f"  PDFs valid:   {pdfs_ok}")
    print(f"  PDFs failed:  {len(fails)}  -> {fails}")
    return 0 if pdfs_ok >= 25 else 1


if __name__ == "__main__":
    sys.exit(main())
