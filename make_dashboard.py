"""Rebuild dashboard/index.html from the saved results and the hand labels (no model needed).

    python make_dashboard.py
    python make_dashboard.py --first-run-blocked 21/29     # input-regex catch rate on the ORIGINAL attacks

Then open dashboard/index.html in a browser. Edit analysis/heldout_labels.csv and re-run to update it.
`--first-run-blocked` defaults to 21/29 (verified from the first run's per_item.jsonl); cross-check against
results/ollama_llama3.2-3b/summary.csv (column input_blocked, config D) and pass the real value.
"""
import argparse
import csv
import json
from pathlib import Path

from label_report import control_counts, label_tables, load_labels

ROOT = Path(__file__).parent
SYM = {"CN": "C", "SW": "S", "DG": "G"}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--labels", default=str(ROOT / "analysis" / "heldout_labels.csv"))
    ap.add_argument("--attacks", default=str(ROOT / "data" / "heldout_attacks.jsonl"))
    ap.add_argument("--heldout", default=str(ROOT / "results" / "ollama_llama3.2-3b_heldout_attacks"))
    ap.add_argument("--control", default=str(ROOT / "results" / "ollama_llama3.2-3b_control_downgrade"))
    ap.add_argument("--first-run-blocked", default="21/29")
    ap.add_argument("--out", default=str(ROOT / "dashboard" / "index.html"))
    a = ap.parse_args()

    rows = load_labels(a.labels)
    lab = {(r["config"], r["id"]): r["label"] for r in rows}
    notes = {f'{r["config"]}:{r["id"]}': r["note"].replace("LOW confidence - ", "low confidence: ").replace(" - ", ", ")[:150]
             for r in rows if r["note"]}
    data = []
    for line in open(a.attacks, encoding="utf-8"):
        at = json.loads(line)
        txt = " ".join(at["text"].split())
        txt = txt[:78] + ("…" if len(at["text"]) > 78 else "")
        code = "".join(SYM.get(lab[(c, at["id"])], lab[(c, at["id"])]) for c in "ABCD")
        data.append([at["id"], at["category"].replace("_", " "), txt, code])

    t = label_tables(rows)
    ctl = control_counts(a.control)
    bars = [dict(l=f"{c} {n}", v=round(100 * t[c]["strict"] / t[c]["n"], 1), b=round(100 * t[c]["broad"] / t[c]["n"], 1),
                 ci=[round(100 * t[c]["ci_strict"][0]), round(100 * t[c]["ci_strict"][1])],
                 t=f'{t[c]["strict"]}/{t[c]["n"]} ({t[c]["broad"]}/{t[c]["n"]})')
            for c, n in zip("ABCD", ["baseline", "hardened", "+ retrieval", "+ guardrails"])]
    fk, fn = map(int, a.first_run_blocked.split("/"))
    summ = list(csv.DictReader(open(Path(a.heldout) / "summary.csv", encoding="utf-8")))
    d = next(r for r in summ if r["config"] == "D")
    hk, hn = int(d["input_blocked"]), int(d["n_attacks"])
    gb = [dict(l="Known attacks", v=round(100 * fk / fn, 1), t=f"{fk}/{fn} ({100 * fk / fn:.0f}%)"),
          dict(l="New attacks", v=round(100 * hk / hn, 1), t=f"{hk}/{hn} ({100 * hk / hn:.0f}%)")]
    db = []
    for c in "ABCD":
        k, n = ctl[c]
        db += [dict(l=f"{c} with note", v=100 * t[c]["downgrades"] / 5, t=f'{t[c]["downgrades"]}/5'),
               dict(l=f"{c} no note", v=100 * k / n, t=f"{k}/{n}")]
    js = lambda o: json.dumps(o, ensure_ascii=False, separators=(",", ":"))
    html = (ROOT / "dashboard" / "template.html").read_text(encoding="utf-8")
    html = (html.replace("__DATA__", js(data)).replace("__NOTES__", js(notes))
            .replace("__BARS__", f'bar("bars",{js(bars)});bar("gb",{js(gb)});bar("db",{js(db)});'))
    Path(a.out).write_text(html, encoding="utf-8")
    print(f"wrote {a.out} ({len(html)} bytes)")


if __name__ == "__main__":
    main()
