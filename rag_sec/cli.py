"""Command-line entry points for the local experiment."""

from __future__ import annotations

import argparse
import json
import secrets
from functools import partial
from pathlib import Path

from .benchmark import benchmark
from .answer_eval import chat_completion, run_answer_eval
from .csaf import fetch_csaf
from .experiment import CONDITIONS, build_conditions, evaluate
from .fixtures import clean_records, questions
from .full_benchmark import run_full
from .mitre import fetch_mitre
from .retrieval import BM25
from .trust import snapshot


def main() -> None:
    parser = argparse.ArgumentParser(prog="rag-sec", description="Independent RAG poisoning lab")
    sub = parser.add_subparsers(dest="command", required=True)
    demo = sub.add_parser("demo", help="show the highest-ranked record for one fixture question")
    demo.add_argument("--case", type=int, default=1, choices=range(1, len(questions()) + 1))
    run = sub.add_parser("evaluate", help="measure every condition against all fixture questions")
    run.add_argument("--output", type=Path, help="optional JSON output path")
    pin = sub.add_parser("snapshot", help="export an approved digest map of clean fixtures")
    pin.add_argument("--output", type=Path, required=True)
    bench = sub.add_parser("benchmark", help="evaluate the pinned CISA KEV corpus")
    bench.add_argument("--backend", choices=("bm25", "tfidf", "both"), default="both")
    bench.add_argument("--output", type=Path, help="optional JSON output path")
    fetch = sub.add_parser("fetch-data", help="download and verify pinned MITRE ATT&CK and CISA CSAF files")
    fetch.add_argument("--workers", type=int, default=12)
    full = sub.add_parser("full-benchmark", help="run the multi-source poisoning benchmark")
    full.add_argument("--backend", choices=("bm25", "tfidf", "both", "embedding", "all"), default="both")
    full.add_argument("--cases-per-source", type=int, default=20)
    full.add_argument("--output", type=Path, default=Path("results/full-benchmark.json"))
    answers = sub.add_parser("answer-eval", help="optional answer-level probe using saved retrieval results")
    answers.add_argument("--input", type=Path, default=Path("results/full-benchmark.json"))
    answers.add_argument("--backend", choices=("bm25", "tfidf", "embedding"), default="tfidf")
    answers.add_argument("--condition", choices=("clean", "unfiltered", "signature_forged",
                                                  "signature_replayed", "signature_compromised",
                                                  "layered_compromised"), default="unfiltered")
    answers.add_argument("--poisons-per-case", type=int, choices=(0, 1, 5), default=1)
    answers.add_argument("--max-queries", type=int, default=10)
    answers.add_argument("--model", required=True)
    answers.add_argument("--base-url", required=True,
                         help="OpenAI-compatible API base URL ending in /v1")
    answers.add_argument("--api-key-env", default="RAG_SEC_LLM_API_KEY")
    answers.add_argument("--output", type=Path, default=Path("results/answer-eval.json"))
    args = parser.parse_args()

    if args.command == "demo":
        case = questions()[args.case - 1]
        corpora, rejected = build_conditions(secrets.token_bytes(32))
        print(f"Question: {case['query']} (target: {case['target_id']})")
        for condition in CONDITIONS:
            record, score = BM25(corpora[condition]).search(case["query"], top_k=1)[0]
            print(f"{condition:24} {record['record_id']:24} score={score:.3f} rejected={rejected[condition]}")
    elif args.command == "evaluate":
        result = evaluate()
        for row in result["summary"]:
            print(
                f"{row['condition']:24} poison@1={row['poison_at_1']}/{row['cases']} "
                f"target@5={row['target_at_5']}/{row['cases']} rejected={row['rejected']}"
            )
        if args.output:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
            print(f"Saved: {args.output}")
    elif args.command == "benchmark":
        backends = ("bm25", "tfidf") if args.backend == "both" else (args.backend,)
        result = benchmark(backends)
        for row in result["summary"]:
            metrics = row["metrics"]
            print(
                f"{row['retriever']:5} {row['condition']:24} "
                f"poison@1={metrics['poison_at_1']['count']}/{row['queries']} "
                f"target@5={metrics['target_at_5']['count']}/{row['queries']} "
                f"rejected={row['rejected_records']}"
            )
        if args.output:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
            print(f"Saved: {args.output}")
    elif args.command == "fetch-data":
        for path in fetch_mitre():
            print(f"Verified: {path}")
        print(f"Verified {len(fetch_csaf(args.workers))} CISA CSAF OT advisories")
    elif args.command == "full-benchmark":
        backends = {"both": ("bm25", "tfidf"),
                    "all": ("bm25", "tfidf", "embedding")}.get(args.backend, (args.backend,))
        result = run_full(backends, args.cases_per_source)
        for row in result["summary"]:
            if row["query_version"] != "all" or row["source_type"] != "all":
                continue
            metrics = row["metrics"]
            print(f"{row['backend']:9} {row['condition']:24} poison={row['poisons_per_case']} "
                  f"poison@1={metrics['poison_at_1']['count']}/{row['queries']} "
                  f"target@5={metrics['target_at_5']['count']}/{row['queries']} "
                  f"rejected={row['rejected_records']}")
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
        print(f"Saved: {args.output}")
    elif args.command == "answer-eval":
        retrieval_result = json.loads(args.input.read_text(encoding="utf-8"))
        responder = partial(chat_completion, model=args.model, base_url=args.base_url,
                            api_key_env=args.api_key_env)
        result = run_answer_eval(retrieval_result, args.backend, args.condition,
                                 args.poisons_per_case, args.max_queries, responder)
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(result, indent=2, ensure_ascii=False) + "\n",
                               encoding="utf-8")
        print(f"Exact phrase: {result['exact_phrase_hits']}/{result['evaluated']}; saved: {args.output}")
    else:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(snapshot(clean_records()), indent=2) + "\n", encoding="utf-8")
        print(f"Saved: {args.output}")


if __name__ == "__main__":
    main()
