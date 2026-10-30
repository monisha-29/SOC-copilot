"""Interactive UI for the SOC Copilot: type or paste any alert (or an injection) and watch configs A-D handle it.

    python app.py                                  # then open http://localhost:8000
    python app.py --backend ollama --model llama3.2:3b
    python app.py --backend mock                   # no model needed; plumbing demo only, NOT real results

Standard library + the project's own modules only (scikit-learn is already in requirements.txt).
It reuses soc/pipeline.py unchanged, so what you see here is exactly what evaluate.py runs.
"""
import argparse
import json
import re
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from soc import guardrails as G
from soc import prompts as P
from soc.llm import get_llm
from soc.pipeline import CONFIGS, Pipeline
from soc.rag import KnowledgeBase

ROOT = Path(__file__).parent
KB = None
DEFAULTS = {"backend": "mock", "model": None}


def load_jsonl(p):
    f = ROOT / p
    if not f.exists():
        return []
    return [json.loads(l) for l in f.read_text(encoding="utf-8").splitlines() if l.strip()]


class RecordingLLM:
    """Wraps a backend and remembers exactly what was sent, so the UI can show it."""

    def __init__(self, inner):
        self.inner, self.system, self.user = inner, None, None

    def chat(self, system, user):
        self.system, self.user = system, user
        return self.inner.chat(system, user)


def examples():
    out = []
    for r in load_jsonl("data/alerts.jsonl")[:8]:
        out.append({"group": "Normal alerts", "label": f'{r["id"]} - {r["text"][:55]}',
                    "text": r["text"], "expect": r.get("severity")})
    for r in load_jsonl("data/attacks.jsonl")[:10]:
        out.append({"group": "Original attacks", "label": f'{r["id"]} {r.get("category", "")}',
                    "text": r["text"], "marker": r.get("success_regex")})
    for r in load_jsonl("data/heldout_attacks.jsonl"):
        out.append({"group": "Held-out attacks", "label": f'{r["id"]} {r["category"]}',
                    "text": r["text"], "marker": r.get("success_regex"), "expect": r.get("gold_severity")})
    return out


def ollama_status(host="http://localhost:11434"):
    try:
        with urllib.request.urlopen(host + "/api/tags", timeout=2) as r:
            return [m["name"] for m in json.loads(r.read()).get("models", [])]
    except Exception:
        return None


def analyse(body):
    cfg = body.get("config", "A")
    backend = body.get("backend") or DEFAULTS["backend"]
    model = body.get("model") or DEFAULTS["model"]
    text = body.get("text", "").strip()
    if cfg not in CONFIGS or not text:
        return {"error": "need a text and a config in A-E"}
    c = CONFIGS[cfg]
    rec = RecordingLLM(get_llm(backend, model))
    pipe = Pipeline(cfg, rec, KB)
    try:
        r = pipe.analyse(text)
    except Exception as e:  # noqa: BLE001  (e.g. Ollama not running / timeout)
        return {"config": cfg, "name": c["name"], "error": f"{type(e).__name__}: {e}"}

    resp = {
        "config": cfg, "name": c["name"], "features": {k: bool(c.get(k)) for k in ("hardened", "rag", "guard")},
        "released": r["released"], "parsed": r["parsed"], "raw": r["raw"], "blocked": r["blocked"],
        "flags": r["flags"], "latency": round(r["latency"], 2),
        "sent_system": rec.system, "sent_user": rec.user,
    }
    if c["guard"]:
        resp["input_hits"] = G.detect_injection(text)
        resp["redacted"] = G.redact_pii(text)
    # quick verdicts the UI can badge
    rel = r["released"] or ""
    resp["leaked_secret"] = bool(rel and G.SECRET_RX.search(rel))
    marker = body.get("marker")
    resp["marker_hit"] = bool(marker and rel and re.search(marker, rel, re.I))
    return resp


class H(BaseHTTPRequestHandler):
    def _send(self, code, data, ctype="application/json"):
        b = data if isinstance(data, bytes) else json.dumps(data).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", ctype + "; charset=utf-8")
        self.send_header("Content-Length", str(len(b)))
        self.end_headers()
        self.wfile.write(b)

    def do_GET(self):
        if self.path in ("/", "/index.html"):
            self._send(200, (ROOT / "ui" / "index.html").read_bytes(), "text/html")
        elif self.path == "/api/info":
            self._send(200, {"backend": DEFAULTS["backend"], "model": DEFAULTS["model"],
                             "ollama_models": ollama_status(),
                             "configs": {k: v["name"] for k, v in CONFIGS.items() if k != "E"},
                             "examples": examples()})
        else:
            self._send(404, {"error": "not found"})

    def do_POST(self):
        if self.path != "/api/analyse":
            return self._send(404, {"error": "not found"})
        n = int(self.headers.get("Content-Length", 0))
        try:
            body = json.loads(self.rfile.read(n) or b"{}")
        except ValueError:
            return self._send(400, {"error": "bad json"})
        self._send(200, analyse(body))

    def log_message(self, *a):
        pass


def main():
    global KB
    ap = argparse.ArgumentParser()
    ap.add_argument("--backend", default="mock", choices=["mock", "ollama", "openai"])
    ap.add_argument("--model", default=None)
    ap.add_argument("--port", type=int, default=8000)
    a = ap.parse_args()
    DEFAULTS.update(backend=a.backend, model=a.model)
    KB = KnowledgeBase()
    srv = ThreadingHTTPServer(("127.0.0.1", a.port), H)
    print(f"SOC Copilot UI -> http://localhost:{a.port}   (backend={a.backend}, model={a.model})")
    if a.backend == "mock":
        print("NOTE: mock backend is a scripted stand-in, not a real model. Use --backend ollama for real behaviour.")
    srv.serve_forever()


if __name__ == "__main__":
    main()
