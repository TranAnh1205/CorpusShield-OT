"""Minimal count-based TF-IDF cosine retriever for a second lexical baseline."""

from __future__ import annotations

import math
from collections import Counter

from .records import validate_record, validate_search
from .retrieval import tokenize


class TFIDF:
    def __init__(self, records: list[dict[str, str]]):
        if not records:
            raise ValueError("retriever requires at least one record")
        self.records = [validate_record(item) for item in records]
        counts = [Counter(tokenize(r["heading"] + " " + r["body"])) for r in self.records]
        df = Counter(term for row in counts for term in row)
        self.idf = {term: math.log((1 + len(counts)) / (1 + frequency)) + 1 for term, frequency in df.items()}
        self.vectors = [{term: (1 + math.log(frequency)) * self.idf[term]
                         for term, frequency in row.items()} for row in counts]
        self.norms = [math.sqrt(sum(value * value for value in row.values())) for row in self.vectors]

    def search(self, query: str, top_k: int = 5) -> list[tuple[dict[str, str], float]]:
        validate_search(query, top_k)
        counts = Counter(tokenize(query))
        qvec = {term: (1 + math.log(frequency)) * self.idf[term]
                for term, frequency in counts.items() if term in self.idf}
        qnorm = math.sqrt(sum(value * value for value in qvec.values()))
        scored = []
        for position, (record, vector, norm) in enumerate(zip(self.records, self.vectors, self.norms, strict=True)):
            dot = sum(value * vector.get(term, 0.0) for term, value in qvec.items())
            score = dot / (qnorm * norm) if qnorm and norm else 0.0
            scored.append((position, score, record))
        scored.sort(key=lambda row: (-row[1], row[0]))
        return [(record.copy(), score) for _, score, record in scored[:top_k]]
