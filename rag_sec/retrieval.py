"""Small deterministic BM25 retriever with no model download."""

from __future__ import annotations

import math
import re
from collections import Counter

from .records import validate_record, validate_search

TOKEN = re.compile(r"[a-z0-9]+", re.IGNORECASE)


def tokenize(text: str) -> list[str]:
    return TOKEN.findall(text.casefold())


class BM25:
    def __init__(self, records: list[dict[str, str]], k1: float = 1.2, b: float = 0.75):
        if not records:
            raise ValueError("retriever requires at least one record")
        if (not isinstance(k1, (int, float)) or not isinstance(b, (int, float))
                or not math.isfinite(k1) or k1 <= 0 or not math.isfinite(b) or not 0 <= b <= 1):
            raise ValueError("BM25 requires finite k1 > 0 and 0 <= b <= 1")
        self.records = [validate_record(item) for item in records]
        self.k1, self.b = k1, b
        self.terms = [Counter(tokenize(r["heading"] + " " + r["body"])) for r in self.records]
        self.lengths = [sum(counts.values()) for counts in self.terms]
        self.avg_length = sum(self.lengths) / len(self.records)
        self.df = Counter(term for counts in self.terms for term in counts)

    def search(self, query: str, top_k: int = 5) -> list[tuple[dict[str, str], float]]:
        validate_search(query, top_k)
        words = sorted(set(tokenize(query)))
        scored = []
        for position, (record, counts, length) in enumerate(
            zip(self.records, self.terms, self.lengths, strict=True)
        ):
            score = 0.0
            for word in words:
                frequency = counts[word]
                if frequency:
                    idf = math.log(1 + (len(self.records) - self.df[word] + 0.5)
                                   / (self.df[word] + 0.5))
                    scale = self.k1 * (1 - self.b + self.b * length / self.avg_length)
                    score += idf * frequency * (self.k1 + 1) / (frequency + scale)
            scored.append((position, score, record))
        scored.sort(key=lambda row: (-row[1], row[0]))
        return [(record.copy(), score) for _, score, record in scored[:top_k]]
