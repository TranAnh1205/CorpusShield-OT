"""Optional dense retrieval with shared embeddings across attack conditions."""

from __future__ import annotations

import hashlib

from .records import canonical_bytes, validate_record, validate_search

MODEL_NAME = "sentence-transformers/all-MiniLM-L6-v2"
MODEL_REVISION = "1110a243fdf4706b3f48f1d95db1a4f5529b4d41"


class DenseStore:
    def __init__(self):
        try:
            from sentence_transformers import SentenceTransformer
        except ImportError as error:
            raise RuntimeError("install the embedding extra: python -m pip install -e '.[embedding]'") from error
        self.model = SentenceTransformer(MODEL_NAME, revision=MODEL_REVISION)
        self.documents = {}
        self.queries = {}

    def prepare(self, records: list[dict[str, str]], queries: list[str]) -> None:
        for query in queries:
            validate_search(query, 1)
        texts = {}
        for record in records:
            item = validate_record(record)
            digest = hashlib.sha256(canonical_bytes(item)).hexdigest()
            texts[digest] = item["heading"] + " " + item["body"]
        missing = {key: value for key, value in texts.items() if key not in self.documents}
        if missing:
            vectors = self.model.encode(list(missing.values()), normalize_embeddings=True,
                                        convert_to_numpy=True, show_progress_bar=False)
            self.documents.update(zip(missing, vectors, strict=True))
        new_queries = list(dict.fromkeys(query for query in queries if query not in self.queries))
        if new_queries:
            vectors = self.model.encode(new_queries, normalize_embeddings=True,
                                        convert_to_numpy=True, show_progress_bar=False)
            self.queries.update(zip(new_queries, vectors, strict=True))

    def index(self, records: list[dict[str, str]]) -> "DenseIndex":
        return DenseIndex(records, self)


class DenseIndex:
    def __init__(self, records: list[dict[str, str]], store: DenseStore):
        import numpy as np

        if not records:
            raise ValueError("retriever requires at least one record")
        self.records = [validate_record(item) for item in records]
        self.store = store
        self.matrix = np.stack([
            store.documents[hashlib.sha256(canonical_bytes(item)).hexdigest()]
            for item in self.records
        ])

    def search(self, query: str, top_k: int = 5) -> list[tuple[dict[str, str], float]]:
        import numpy as np

        validate_search(query, top_k)
        vector = self.store.queries.get(query)
        if vector is None:
            self.store.prepare([], [query])
            vector = self.store.queries[query]
        scores = self.matrix @ vector
        positions = np.argsort(-scores, kind="stable")[:top_k]
        return [(self.records[int(position)].copy(), float(scores[position])) for position in positions]
