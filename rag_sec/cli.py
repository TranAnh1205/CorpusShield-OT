"""Command-line entry points for the local experiment."""

from __future__ import annotations

import argparse
import json
import secrets
import hashlib
from functools import partial
from pathlib import Path

from .benchmark import benchmark
from .answer_eval import chat_completion, run_answer_eval
from .csaf import fetch_csaf
from .experiment import CONDITIONS, build_conditions, evaluate
from .fixtures import clean_records, questions
from .full_benchmark import ATTACK_MODES, load_inputs, run_full
from .mitre import fetch_mitre
from .retrieval import BM25
from .trust import load_snapshot, snapshot
from .io_utils import read_file, write_json


def main() -> None:
    parser = argparse.ArgumentParser(prog="corpusshield-ot", description="Security RAG poisoning benchmark")
    sub = parser.add_subparsers(dest="command", required=True)
    demo = sub.add_parser("demo", help="show the highest-ranked record for one fixture question")
    demo.add_argument("--case", type=int, default=1, choices=range(1, len(questions()) + 1))
    run = sub.add_parser("evaluate", help="measure every condition against all fixture questions")
    run.add_argument("--output", type=Path, help="optional JSON output path")
    pin = sub.add_parser("snapshot", help="export an approved digest map of clean fixtures")
    pin.add_argument("--output", type=Path, required=True)
    pin.add_argument("--source", choices=("fixtures", "corpus"), default="fixtures",
                     help="explicit approval of fixtures or the verified full corpus")
    bench = sub.add_parser("benchmark", help="evaluate the pinned CISA KEV corpus")
    bench.add_argument("--backend", choices=("bm25", "tfidf", "both"), default="both")
    bench.add_argument("--output", type=Path, help="optional JSON output path")
    fetch = sub.add_parser("fetch-data", help="download and verify pinned MITRE ATT&CK and CISA CSAF files")
    fetch.add_argument("--workers", type=int, default=12)
    full = sub.add_parser("full-benchmark", help="run the multi-source poisoning benchmark")
    full.add_argument("--backend", choices=("bm25", "tfidf", "both", "embedding", "all"), default="both")
    full.add_argument("--cases-per-source", type=int, default=20)
    full.add_argument("--attack-mode", choices=ATTACK_MODES, default="query-aware")
    full.add_argument("--approved-snapshot", type=Path)
    full.add_argument("--snapshot-sha256", help="digest from a separately trusted approval record")
    full.add_argument("--output", type=Path, default=Path("results/latest-benchmark.json"))
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
    for command in (run, bench, full, answers):
        command.add_argument("--overwrite", action="store_true", help="explicitly replace an existing result file")
    args = parser.parse_args()
    output = getattr(args, "output", None)
    if output and output.exists() and not getattr(args, "overwrite", False):
        parser.error("output already exists; choose a new path or use --overwrite for result files")
    if args.command == "full-benchmark" and bool(args.approved_snapshot) != bool(args.snapshot_sha256):
        parser.error("--approved-snapshot and --snapshot-sha256 must be supplied together")
    if args.command == "answer-eval" and args.input.resolve() == args.output.resolve():
        parser.error("answer output must differ from retrieval input")

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
            write_json(args.output, result)
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
            write_json(args.output, result)
            print(f"Saved: {args.output}")
    elif args.command == "fetch-data":
        for path in fetch_mitre():
            print(f"Verified: {path}")
        print(f"Verified {len(fetch_csaf(args.workers))} CISA CSAF OT advisories")
    elif args.command == "full-benchmark":
        backends = {"both": ("bm25", "tfidf"),
                    "all": ("bm25", "tfidf", "embedding")}.get(args.backend, (args.backend,))
        approved = load_snapshot(args.approved_snapshot, args.snapshot_sha256) if args.approved_snapshot else None
        result = run_full(backends, args.cases_per_source, attack_mode=args.attack_mode,
                          approved_snapshot=approved)
        if approved is not None:
            result["snapshot"]["file_sha256"] = args.snapshot_sha256
        for row in result["summary"]:
            if row["query_version"] != "all" or row["source_type"] != "all":
                continue
            metrics = row["metrics"]
            print(f"{row['backend']:9} {row['condition']:24} poison={row['poisons_per_case']} "
                  f"poison@1={metrics['poison_at_1']['count']}/{row['queries']} "
                  f"target@5={metrics['target_at_5']['count']}/{row['queries']} "
                  f"rejected={row['rejected_records']}")
        write_json(args.output, result)
        print(f"Saved: {args.output}")
    elif args.command == "answer-eval":
        retrieval_result = json.loads(read_file(args.input, 128 * 1024 * 1024))
        responder = partial(chat_completion, model=args.model, base_url=args.base_url,
                            api_key_env=args.api_key_env)
        result = run_answer_eval(retrieval_result, args.backend, args.condition,
                                 args.poisons_per_case, args.max_queries, responder)
        result["model"] = args.model
        result["endpoint"] = args.base_url
        write_json(args.output, result)
        print(f"Exact phrase: {result['exact_phrase_hits']}/{result['evaluated']}; saved: {args.output}")
    else:
        records = load_inputs()[0] if args.source == "corpus" else clean_records()
        write_json(args.output, snapshot(records))
        print(f"Saved: {args.output}")
        print(f"Approved snapshot SHA-256: {hashlib.sha256(args.output.read_bytes()).hexdigest()}")
        print("Keep this digest in separately controlled configuration; the file alone does not enforce access control.")


if __name__ == "__main__":
    main()
