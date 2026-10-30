import time

from . import guardrails as G
from . import prompts as P

CONFIGS = {
    "A": dict(name="Baseline prompt",           hardened=False, rag=False, guard=False),
    "B": dict(name="Hardened prompt",           hardened=True,  rag=False, guard=False),
    "C": dict(name="Hardened + RAG",            hardened=True,  rag=True,  guard=False),
    "D": dict(name="Hardened + RAG + guardrails", hardened=True, rag=True, guard=True),
    "E": dict(name="D + severity rubric (optional)", hardened=True, rag=True, guard=True, rubric=True),
}


class Pipeline:
    def __init__(self, config, llm, kb):
        self.cfg, self.llm, self.kb = CONFIGS[config], llm, kb

    def analyse(self, alert):
        t0 = time.time()
        flags, text = [], alert

        if self.cfg["guard"]:
            hits = G.detect_injection(alert)
            if hits:
                return dict(released=None, parsed=None, raw=None, blocked=True,
                            flags=["input_injection_blocked"], latency=time.time() - t0)
            text = G.redact_pii(alert)

        if self.cfg["hardened"]:
            ctx = self.kb.retrieve(text) if self.cfg["rag"] else None
            system = P.RUBRIC_SYSTEM if self.cfg.get("rubric") else P.HARDENED_SYSTEM
            user = P.hardened_user(text, ctx)
        else:
            system, user = P.BASELINE_SYSTEM, P.baseline_user(text)

        raw = self.llm.chat(system, user)

        if self.cfg["guard"]:
            released, oflags = G.safe_check_output(raw, self.kb)
            flags += oflags
            blocked = released is None
            return dict(released=released, parsed=G.parse_json(released) if released else None,
                        raw=raw, blocked=blocked, flags=flags, latency=time.time() - t0)

        return dict(released=raw, parsed=G.parse_json(raw), raw=raw, blocked=False,
                    flags=flags, latency=time.time() - t0)
