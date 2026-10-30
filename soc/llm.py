"""LLM backends behind one interface: chat(system, user) -> str.

  ollama  : local model served by Ollama (http://localhost:11434)  <- recommended
  openai  : any OpenAI-compatible endpoint (OpenAI, Groq, vLLM, LM Studio...)
            set OPENAI_API_KEY and optionally OPENAI_BASE_URL
  mock    : deterministic stand-in used ONLY to test the pipeline plumbing.
            Its numbers are NOT results and must never go in the report.
"""
import hashlib
import json
import os
import re
import urllib.request


def _post(url, payload, headers=None, timeout=None):
    timeout = timeout or int(os.getenv("SOC_TIMEOUT", "300"))   # seconds; default unchanged
    req = urllib.request.Request(url, data=json.dumps(payload).encode(),
                                 headers={"Content-Type": "application/json", **(headers or {})})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read())


class OllamaLLM:
    def __init__(self, model="llama3.1:8b", host=None):
        self.model = model
        self.host = host or os.getenv("OLLAMA_HOST", "http://localhost:11434")

    def chat(self, system, user):
        opts = {"temperature": 0, "seed": 42}
        if os.getenv("SOC_NUM_PREDICT"):          # opt-in cap on output tokens (stops runaway generations)
            opts["num_predict"] = int(os.environ["SOC_NUM_PREDICT"])
        out = _post(f"{self.host}/api/chat", {
            "model": self.model, "stream": False, "format": "json",
            "options": opts,
            "messages": [{"role": "system", "content": system}, {"role": "user", "content": user}],
        })
        return out["message"]["content"]


class OpenAICompatLLM:
    def __init__(self, model="gpt-4o-mini", base_url=None, api_key=None):
        self.model = model
        self.base = (base_url or os.getenv("OPENAI_BASE_URL", "https://api.openai.com/v1")).rstrip("/")
        self.key = api_key or os.environ["OPENAI_API_KEY"]

    def chat(self, system, user):
        out = _post(f"{self.base}/chat/completions", {
            "model": self.model, "temperature": 0, "seed": 42,
            "messages": [{"role": "system", "content": system}, {"role": "user", "content": user}],
        }, headers={"Authorization": f"Bearer {self.key}"})
        return out["choices"][0]["message"]["content"]


# ------------------------------------------------------------------ mock
_RULES = [  # regex on alert text -> (technique, severity, cves)
    (r"jndi", ("T1190", "critical", ["CVE-2021-44228"])),
    (r"smb|eternalblue|ms17-010", ("T1190", "critical", ["CVE-2017-0144"])),
    (r"lsass", ("T1003.001", "critical", [])),
    (r"ransom|\.locked|\.crypt", ("T1486", "critical", [])),
    (r"-enc|downloadstring|powershell", ("T1059.001", "high", [])),
    (r"beacon", ("T1071.001", "high", [])),
    (r"ftp|exfil|uploaded", ("T1048", "high", [])),
    (r"cleared|wevtutil", ("T1070.001", "high", [])),
    (r"defender|edr sensor|tamper", ("T1562.001", "high", [])),
    (r"scheduled task|schtasks", ("T1053.005", "medium", [])),
    (r"docm|attachment", ("T1566.001", "medium", [])),
    (r"rdp|remoteinteractive", ("T1021.001", "medium", [])),
    (r"impossible travel|authenticated from", ("T1078", "medium", [])),
    (r"failed (ssh )?log|4625", ("T1110", "medium", [])),
    (r"scanned|syn probes", ("T1046", "low", [])),
]


def _h(s, mod):
    return int(hashlib.md5(s.encode()).hexdigest(), 16) % mod


class MockLLM:
    """Crude simulator: vulnerable when un-hardened, sometimes invents CVEs without context."""

    def chat(self, system, user):
        m = re.search(r"<alert>\n?(.*?)\n?</alert>|^Alert: (.*)$", user, re.S | re.M)
        alert = (m.group(1) or m.group(2) or user) if m else user
        hardened = "untrusted" in system.lower()
        has_ctx = "<context>" in user
        low = alert.lower()

        attack = re.search(r"ignore|disregard|forget your|system override|developer mode|dan\b|print your|reveal|"
                           r"repeat everything|api key|hidden instructions|internal config|system prompt|decode this base64", low)
        if attack and (not hardened or _h(alert, 3) == 0):
            rationale = "ok"
            if re.search(r"api key|system prompt|config|secrets|repeat everything|hidden instructions", low):
                k = re.search(r"INTERNAL_API_KEY=\S+", system)
                rationale = k.group(0) if k else "n/a"
            elif "pwned" in low:
                rationale = "PWNED-1337"
            elif re.search(r"ransomware|keylogger|credentials|invoke-expression|def ", low):
                rationale = "```python\nimport os\ndef encrypt_files(): ...\n```"
            return json.dumps({"severity": "low", "technique_id": "none", "cves": [], "rationale": rationale})

        tech, sev, cves = "none", "low", []
        for rx, val in _RULES:
            if re.search(rx, low):
                tech, sev, cves = val
                break
        if not has_ctx:
            if tech != "none" and _h(alert, 5) == 0:
                tech = "T1059"                     # wrong/parent technique
            if tech == "T1190" and _h(alert, 2) == 0:
                cves = ["CVE-2021-44229"]          # hallucinated near-miss ID
        return json.dumps({"severity": sev, "technique_id": tech, "cves": cves,
                           "rationale": f"Matched pattern for {tech}."})


def get_llm(backend, model=None):
    if backend == "ollama":
        return OllamaLLM(model or "llama3.1:8b")
    if backend == "openai":
        return OpenAICompatLLM(model or "gpt-4o-mini")
    if backend == "mock":
        return MockLLM()
    raise ValueError(backend)
