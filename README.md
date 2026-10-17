# CorpusShield-OT

**A reproducible corpus-poisoning benchmark and provenance defense for security RAG.**

Repository: [TranAnh1205/CorpusShield-OT](https://github.com/TranAnh1205/CorpusShield-OT)

CorpusShield-OT studies whether malicious records inserted into a cybersecurity knowledge base reach a retriever's top results, and whether ingestion controls keep them out. The corpus contains **2,743 records** from CISA Known Exploited Vulnerabilities (KEV), MITRE ATT&CK Enterprise/ICS, and CISA CSAF operational-technology advisories. The project implements its own data loaders, BM25 and TF-IDF retrievers, attack generator, HMAC verification, approved-corpus snapshot, and evaluation pipeline. A pinned MiniLM model provides an optional dense-retrieval backend.

The experiment measures **retrieval exposure**, not whether an LLM follows a malicious instruction. An optional answer-level probe is provided separately.

## What is implemented

| Component | Scope |
|---|---|
| Corpus | 1,745 KEV records, 698 active ATT&CK techniques with mitigations, 300 CSAF OT advisories |
| Cases | 60 fixed targets: 20 KEV, 10 Enterprise, 10 ICS, 20 CSAF; original and reworded query for each |
| Attacks | Query-aware and query-blind template source spoofing; 1 or 5 injected records per case, with all cases attacked together |
| Retrievers | BM25, TF-IDF, and pinned `all-MiniLM-L6-v2` embeddings |
| Trust conditions | Clean, unfiltered, forged HMAC, replayed HMAC, compromised signer, compromised signer with protected snapshot |
| Reporting | Top-1/top-5 poison and target metrics, ranks, scores, per-source breakdowns, and case-cluster bootstrap intervals |

HMAC-SHA256 authenticates every field in a canonical record, including its ID, publisher, title, body, reference URL, and kind. The separate snapshot pins approved IDs and content hashes. It rejects new or changed records even when the simulated signing key is compromised, assuming the snapshot itself remains protected.

## Quick start

Python 3.11+ is required. The lexical benchmark has no third-party runtime dependencies. KEV is included; ATT&CK and CSAF are downloaded from pinned upstream commits into the Git-ignored `data/raw/` directory.

```bash
python -m rag_sec fetch-data
python -m rag_sec full-benchmark --backend both --output results/latest-benchmark.json
python -m unittest discover -s tests -v
```

The [CI workflow](.github/workflows/ci.yml) installs locked dependencies, fetches pinned source files, runs tests, audits code and dependencies, and exercises a persisted approval snapshot on main pushes and pull requests.

For dense retrieval, install the optional dependencies and run the pinned model:

```bash
uv sync --extra embedding
uv run --extra embedding python -m rag_sec full-benchmark --backend embedding --output results/embedding-latest.json
```

The first dense run downloads model weights if they are not already cached. Use `--cases-per-source 2` for a short pipeline check, or `--backend all` to run all three retrievers together. `demo`, `evaluate`, and `benchmark` are smaller offline exercises; command details are in [the CLI reference](docs/REFERENCE.md).

## Measured results

The full run evaluates **120 queries per condition and retriever**. The table shows the one-poison-per-case setting. `Poison@1` counts queries with any injected record ranked first; `Target@5` counts queries with the exact target in the top five.

| Retriever | Clean Target@5 | Unfiltered Poison@1 | Forged / replayed Poison@1 | Compromised Poison@1 | Compromised + snapshot Poison@1 |
|---|---:|---:|---:|---:|---:|
| BM25 | 120/120 | 120/120 | 0/120 | 120/120 | 0/120 |
| TF-IDF | 118/120 | 120/120 | 0/120 | 120/120 | 0/120 |
| MiniLM embeddings | 88/120 | 111/120 | 0/120 | 111/120 | 0/120 |

At five poisons per case, the unfiltered Poison@1 counts are 120/120 for BM25 and TF-IDF and 115/120 for embeddings. Forged and replayed signatures are rejected; a compromised signer passes HMAC alone; the independently protected snapshot rejects all 300 injected records. The dense retriever's lower clean Target@5 (88/120) is part of its baseline and should be considered when comparing attack results. These outcomes reflect a **query-aware, template-built attack**, not a general robustness guarantee.

The [full benchmark report](docs/FULL_BENCHMARK.md) explains every condition and limitation. [Lexical results](results/full-benchmark.json) contain 2,640 per-query rows; [embedding results](results/embedding-benchmark.json) contain 1,320. Both include source revisions and detailed top-k output.

## Project layout

```text
rag_sec/
  kev.py, mitre.py, csaf.py    Verify and normalize the three source feeds
  retrieval.py, tfidf.py       Lexical retrievers
  dense.py                     Optional pinned MiniLM retriever
  records.py, trust.py         Canonical records, HMAC, and approved snapshot
  full_benchmark.py            Multi-source cases, attacks, defenses, metrics
  answer_eval.py               Optional answer-level API probe
data/
  csaf-manifest.json           Pinned advisory selection and Git blob hashes
  raw/                         Downloaded upstream data; excluded from Git
results/                       Committed retrieval outputs
tests/                         Data, retrieval, and trust-boundary regressions
docs/                          Architecture, evaluation, CLI, and threat model
```

## Data, reproducibility, and scope

The [data provenance notes](data/README.md) list upstream repositories, pinned commits, checksums, and terms. ATT&CK and CSAF raw files are rebuilt locally; the Git repository contains the CSAF selection manifest and result metadata, not redistributed advisory bodies. The KEV source is [CC0](https://github.com/cisagov/kev-data/blob/7606917390b43dc02b251d88dbceed6296a919fc/LICENSE); ATT&CK has its [own license](data/MITRE-ATTACK-LICENSE.txt); the embedding model has an [Apache-2.0 model card](https://huggingface.co/sentence-transformers/all-MiniLM-L6-v2). CorpusShield-OT is not endorsed by CISA or MITRE.

The HMAC key in benchmark runs is a **fixed simulation key** for reproducibility, not a production secret-management design. HMAC does not distinguish approved content from malicious content signed with a stolen key. The snapshot works only when created from a known-clean baseline and protected from the attacker. The benchmark does not measure generated-answer harm, first-ingestion poisoning, adaptive semantic attacks, reranking, or edge-device latency. See the [threat model](docs/SECURITY.md).

An optional `answer-eval` command validates saved provenance and top-five contexts before passing them to an OpenAI-compatible chat endpoint. It requires an API key in `RAG_SEC_LLM_API_KEY`, limits calls, and samples across sources and query versions. Exact-phrase presence can include quotations and negations: it is not attack success. No live LLM result is claimed here.

## Security review and reproducible approvals

See the [security review](docs/SECURITY_REVIEW.md) for fixes, verification evidence, and remaining gaps. Downloads have size limits, pinned checksums, atomic writes, and no redirects. API endpoints require HTTPS except explicit loopback HTTP. Existing result files require `--overwrite`; snapshots require a new path.

Create an approval from reviewed source data, keep its printed SHA-256 in separately controlled configuration, then use both inputs:

```bash
python -m rag_sec snapshot --source corpus --output results/approved-corpus.json
python -m rag_sec full-benchmark --backend both --attack-mode query-blind --approved-snapshot results/approved-corpus.json --snapshot-sha256 <TRUSTED_SHA256> --output results/query-blind-latest.json
```

The command exports hashes; it does not perform human approval or establish filesystem permissions. Without these flags the benchmark uses an explicitly labelled simulated in-process snapshot. Schema 2 results include code hashes, Git state, corpus/case hashes, environment, and indexing/query timings. Run from a source checkout: standalone wheel deployment with bundled data is not supported yet.

## Roadmap

- Evaluate generated guidance with a human-reviewed rubric and report answer-level success separately.
- Test semantic and adaptive poisons that do not copy the target query.
- Measure verification latency and memory on constrained OT hardware.
- Add an audited approval workflow and per-source public-key signatures.

The original code in this repository does not yet have a reuse license. Choose one before inviting others to redistribute or modify it; upstream data and model terms remain separate.
