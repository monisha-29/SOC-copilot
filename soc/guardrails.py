"""Input and output guardrails (pattern-based, intentionally simple and explainable).

Limits are part of the finding: regexes catch known phrasings but miss obfuscation
(base64, leetspeak, spaced letters). Discuss this honestly in Chapters 8-10, and
optionally add LLM Guard / Llama Guard as a stronger classifier for a config E.
"""
import json
import re

from .prompts import CANARY

INJECTION_PATTERNS = [
    r"(ignore|disregard|forget)\s+(all\s+|any\s+)?(the\s+)?(previous|prior|above|earlier|your)\s+(instructions|rules|prompts?)",
    r"(previous|prior|above)\s+(instructions|rules)\s+(are\s+)?(void|cancel)",
    r"system\s*(override|prompt|:)",
    r"new\s+(system\s+)?instructions?",
    r"developer\s+mode|\bDAN\b|unfiltered|no restrictions",
    r"(print|reveal|repeat|show|output).{0,40}(system prompt|hidden instructions|api key|secret|internal config|configuration|everything above)",
    r"(note|message)\s+to\s+(the\s+)?ai|assistant\s*[:,]\s*(you must|disregard|ignore)",
    r"</?\s*alert\s*>",                     # delimiter breakout
    r"you are now\b",
    r"(write|give|provide).{0,40}(ransomware|keylogger|malware|exploit code)",
]
_INJ = [re.compile(p, re.I | re.S) for p in INJECTION_PATTERNS]

EMAIL = re.compile(r"[\w.+-]+@[\w-]+\.[\w.-]+")
IPV4 = re.compile(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3})\.\d{1,3}\b")


def detect_injection(text):
    hits = [p.pattern for p in _INJ if p.search(text)]
    return hits


def redact_pii(text):
    """DPDP/GDPR data minimisation: mask emails and the last IPv4 octet before the LLM sees it."""
    text = EMAIL.sub("<EMAIL>", text)
    return IPV4.sub(r"\1.x", text)


SEVERITIES = {"low", "medium", "high", "critical"}
CODE_RX = re.compile(r"(```|\bimport\s+\w+|\bdef\s+\w+\(|Invoke-Expression|Get-ChildItem)")
SECRET_RX = re.compile(rf"{CANARY}|INTERNAL_API_KEY|sk-soc-", re.I)


def parse_json(raw):
    try:
        return json.loads(raw)
    except Exception:
        m = re.search(r"\{.*\}", raw, re.S)
        if m:
            try:
                return json.loads(m.group(0))
            except Exception:
                return None
    return None


def check_output(raw, kb):
    """Return (released_json_str or None, flags). Validates schema, IDs, leakage, code.

    Robust to malformed model output (null/non-list cves, non-string fields): anything
    unexpected is blocked (fail closed) rather than raising.
    """
    flags = []
    if not isinstance(raw, str):
        return None, ["invalid_output"]
    if SECRET_RX.search(raw):
        return None, ["secret_leak_blocked"]
    if CODE_RX.search(raw):
        return None, ["code_output_blocked"]
    obj = parse_json(raw)
    if not isinstance(obj, dict):
        return None, ["invalid_json"]
    sev = str(obj.get("severity", "")).lower()
    if sev not in SEVERITIES:
        return None, ["invalid_severity"]
    tech = obj.get("technique_id", "none")
    if not isinstance(tech, str) or tech not in kb.technique_ids:
        flags.append(f"unverified_technique:{tech}")
        tech = "none"
    raw_cves = obj.get("cves")
    if raw_cves is None:
        raw_cves = []
    elif isinstance(raw_cves, str):
        raw_cves = [raw_cves]
    elif not isinstance(raw_cves, list):
        raw_cves = []
    cves = [c for c in raw_cves if isinstance(c, str)]
    bad = [c for c in cves if c not in kb.cve_ids]
    if bad:
        flags.append("unverified_cve:" + ",".join(bad))
    cves = [c for c in cves if c in kb.cve_ids]
    rationale = str(obj.get("rationale", ""))[:300]
    return json.dumps({"severity": sev, "technique_id": tech, "cves": cves, "rationale": rationale}), flags


def safe_check_output(raw, kb):
    """Fail-closed wrapper: any unexpected error blocks the output instead of crashing or releasing it."""
    try:
        return check_output(raw, kb)
    except Exception as e:  # noqa: BLE001
        return None, [f"guard_error:{type(e).__name__}"]
