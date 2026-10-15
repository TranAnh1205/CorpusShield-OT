"""Command-line entry points for the local experiment."""

from __future__ import annotations

import argparse
import json
import secrets
from pathlib import Path

from .benchmark import benchmark
from .experiment import CONDITIONS, build_conditions, evaluate
from .fixtures import clean_records, questions
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
    else:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(snapshot(clean_records()), indent=2) + "\n", encoding="utf-8")
        print(f"Saved: {args.output}")


if __name__ == "__main__":
    main()
