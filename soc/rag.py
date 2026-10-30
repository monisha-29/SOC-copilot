"""Tiny retrieval layer: TF-IDF over ATT&CK techniques + CVE entries.

Swap in sentence-transformers + FAISS/Chroma later if you want embedding-based RAG
(and discuss OWASP LLM08 vector/embedding weaknesses in the report).
"""
import json
from pathlib import Path

from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import linear_kernel

DATA = Path(__file__).resolve().parent.parent / "data"


class KnowledgeBase:
    def __init__(self):
        self.techniques = json.loads((DATA / "attack_techniques.json").read_text(encoding="utf-8"))
        self.cves = json.loads((DATA / "cve_db.json").read_text(encoding="utf-8"))
        self.technique_ids = {t["id"] for t in self.techniques} | {"none"}
        self.cve_ids = {c["id"] for c in self.cves}
        self.docs = (
            [{"kind": "technique", "id": t["id"], "text": f'{t["id"]} {t["name"]} ({t["tactic"]}): {t["description"]}'}
             for t in self.techniques]
            + [{"kind": "cve", "id": c["id"], "text": f'{c["id"]} {c["name"]}: {c["description"]}'} for c in self.cves]
        )
        self.vec = TfidfVectorizer(ngram_range=(1, 2), sublinear_tf=True, stop_words="english")
        self.mat = self.vec.fit_transform([d["text"] for d in self.docs])

    def retrieve(self, query, k=4):
        sims = linear_kernel(self.vec.transform([query]), self.mat).ravel()
        top = sims.argsort()[::-1][:k]
        return [self.docs[i] for i in top if sims[i] > 0]
