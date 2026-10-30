# SOC Copilot

An LLM assistant that triages security alerts, and an experiment on how well different defences protect it from prompt injection (hidden instructions planted in the alert text).

Four versions are compared (model: llama3.2:3b via Ollama):

- **A** baseline prompt
- **B** hardened prompt
- **C** B + retrieval of real ATT&CK/CVE entries
- **D** C + regex input/output guardrails

## Results

| Config | Known attacks (29) | New attacks (34) | Severity acc. | Technique acc. |
|---|---|---|---|---|
| A | 7 (24%) | 16 (47%) | 18% | 8% |
| B | 6 (21%) | 6 (18%) | 36% | 12% |
| C | 5 (17%) | 8 (24%) | 34% | 59% |
| D | 0 (0%) | 8 (24%) | 35% | 60% |

- Retrieval improves accuracy the most.
- Guardrails stop every known attack but only 1 of 34 new ones, and they wrongly flag harmless alerts.
- Limits: one run, one small model, synthetic alerts, attack sets not blind, single-rater labels.

## Setup

Python 3.10+.

    pip install -r requirements.txt

## Run

See the saved results (no model needed):

    python rescore.py results/ollama_llama3.2-3b
    python rescore.py results/ollama_llama3.2-3b_heldout_attacks --attacks data/heldout_attacks.jsonl
    python label_report.py
    python check_filter.py data/benign_hard.jsonl --benign
    python make_dashboard.py          # then open dashboard/index.html

Demo app (open http://localhost:8000):

    python app.py --backend mock                        # scripted demo, not real results
    python app.py --backend ollama --model llama3.2:3b  # real model

Re-run the experiments (needs [Ollama](https://ollama.com), about 20-30 min per run):

    ollama pull llama3.2:3b
    python evaluate.py --backend ollama --model llama3.2:3b
    python evaluate.py --backend ollama --model llama3.2:3b --attacks data/heldout_attacks.jsonl --skip-utility

Results go to `results/`; earlier runs are never overwritten.

## Files

| Path | Purpose |
|---|---|
| `soc/` | pipeline, prompts, guardrails, retrieval, model backends |
| `data/` | synthetic alerts, attack sets, ATT&CK/CVE knowledge base |
| `evaluate.py` | runs the experiments |
| `rescore.py`, `label_report.py`, `check_filter.py` | offline analysis |
| `analysis/` | hand labels for the new-attack run |
| `dashboard/`, `make_dashboard.py` | results page |
| `app.py`, `ui/` | demo app |
