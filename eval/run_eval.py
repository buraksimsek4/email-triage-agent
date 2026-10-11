"""Score a classifier against the labeled email set in eval/dataset/.

Two ways to feed predictions in:

  1. A predictor function (automatic):
       python eval/run_eval.py --split dev --predictor triage.baseline:predict
     The function receives a pathlib.Path to one .eml file and returns either a dict or
     an object with `verdict` and `category` attributes (e.g. the pydantic Verdict model).

  2. A predictions CSV (manual checklist or output from another tool):
       python eval/run_eval.py --split dev --predictions my_predictions.csv
     Columns: file,verdict,category  (file matches the `file` column in labels.csv).

Results are written to eval/results/<timestamp>_<split>_<name>.json and .md.
Only stdlib is used so this runs before the rest of the project exists.
"""

from __future__ import annotations

import argparse
import csv
import importlib
import json
import sys
import time
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

EVAL_DIR = Path(__file__).resolve().parent
DATASET_DIR = EVAL_DIR / "dataset"
RESULTS_DIR = EVAL_DIR / "results"

VERDICTS = {"malicious", "suspicious", "benign"}
CATEGORIES = {"credential_phishing", "bec", "malware_delivery", "spam", "benign"}
PHISHING_CATEGORIES = {"credential_phishing", "bec", "malware_delivery"}
LABELS = ["phishing", "spam", "benign"]


def load_labels(split: str) -> list[dict[str, str]]:
    with open(DATASET_DIR / "labels.csv", newline="", encoding="utf-8") as f:
        rows = [r for r in csv.DictReader(f) if r["split"] == split]
    if not rows:
        sys.exit(f"No rows with split={split!r} in labels.csv")
    return rows


def category_to_label(category: str) -> str:
    if category in PHISHING_CATEGORIES:
        return "phishing"
    if category in ("spam", "benign"):
        return category
    return "error"


def load_predictor(spec: str) -> Callable[[Path], Any]:
    module_name, _, func_name = spec.partition(":")
    if not func_name:
        sys.exit("--predictor must look like 'package.module:function'")
    return getattr(importlib.import_module(module_name), func_name)


def field(result: Any, name: str) -> Any:
    return result.get(name) if isinstance(result, dict) else getattr(result, name, None)


def predict_all(rows: list[dict[str, str]], predictor: Callable[[Path], Any]) -> dict[str, dict]:
    predictions = {}
    for row in rows:
        start = time.perf_counter()
        try:
            result = predictor(DATASET_DIR / row["file"])
            pred = {"verdict": field(result, "verdict"), "category": field(result, "category")}
            meta = field(result, "meta")
            pred["cost_usd"] = field(meta, "cost_usd") if meta is not None else None
        except Exception as exc:  # a crash must show up in the report, not vanish
            pred = {"verdict": None, "category": None, "error": f"{type(exc).__name__}: {exc}"}
        pred["latency_ms"] = round((time.perf_counter() - start) * 1000, 1)
        predictions[row["file"]] = pred
    return predictions


def load_predictions_csv(path: Path) -> dict[str, dict]:
    with open(path, newline="", encoding="utf-8") as f:
        return {r["file"]: {"verdict": r["verdict"].strip(), "category": r["category"].strip()}
                for r in csv.DictReader(f)}


def safe_div(a: float, b: float) -> float | None:
    return round(a / b, 4) if b else None


def score(rows: list[dict[str, str]], predictions: dict[str, dict]) -> dict:
    tp = fp = fn = tn = 0
    benign_total = benign_flagged = 0
    category_correct = 0
    invalid = 0
    confusion: Counter[tuple[str, str]] = Counter()
    mistakes = []

    for row in rows:
        pred = predictions.get(row["file"], {"verdict": None, "category": None, "error": "missing"})
        verdict, category = pred.get("verdict"), pred.get("category")
        if verdict not in VERDICTS or category not in CATEGORIES:
            invalid += 1
        predicted_label = category_to_label(category) if category in CATEGORIES else "error"
        confusion[(row["label"], predicted_label)] += 1

        # Binary task: is this phishing? Spam counts as "not phishing".
        is_phish, said_phish = row["label"] == "phishing", predicted_label == "phishing"
        tp += is_phish and said_phish
        fn += is_phish and not said_phish
        fp += not is_phish and said_phish
        tn += not is_phish and not said_phish

        # SOC view: any legitimate mail that was not called benign costs analyst time.
        if row["label"] == "benign":
            benign_total += 1
            benign_flagged += verdict != "benign"

        category_correct += category == row["category"]
        if category != row["category"] or predicted_label != row["label"]:
            mistakes.append({"file": row["file"], "expected": f"{row['label']}/{row['category']}",
                             "got": f"{verdict}/{category}", "error": pred.get("error"),
                             "notes": row["notes"]})

    precision, recall = safe_div(tp, tp + fp), safe_div(tp, tp + fn)
    f1 = (round(2 * precision * recall / (precision + recall), 4)
          if precision and recall else None)
    latencies = [p["latency_ms"] for p in predictions.values() if "latency_ms" in p]
    costs = [p["cost_usd"] for p in predictions.values() if p.get("cost_usd") is not None]
    return {
        "n": len(rows),
        "phishing_detection": {"tp": tp, "fp": fp, "fn": fn, "tn": tn, "precision": precision,
                               "recall": recall, "f1": f1, "fpr": safe_div(fp, fp + tn)},
        "benign_flag_rate": safe_div(benign_flagged, benign_total),
        "category_accuracy": safe_div(category_correct, len(rows)),
        "invalid_or_missing_predictions": invalid,
        "confusion_matrix": {t: {p: confusion[(t, p)] for p in LABELS + ["error"]} for t in LABELS},
        "avg_latency_ms": round(sum(latencies) / len(latencies), 1) if latencies else None,
        "avg_cost_usd": round(sum(costs) / len(costs), 6) if costs else None,
        "mistakes": mistakes,
    }


def to_markdown(name: str, split: str, m: dict) -> str:
    d = m["phishing_detection"]
    lines = [
        f"# Eval: {name} ({split} split, n={m['n']})", "",
        "| Metric | Value |", "|---|---|",
        f"| Phishing precision | {d['precision']} |",
        f"| Phishing recall | {d['recall']} |",
        f"| Phishing F1 | {d['f1']} |",
        f"| Phishing FPR (non-phishing called phishing) | {d['fpr']} |",
        f"| Benign flag rate (legit mail not called benign) | {m['benign_flag_rate']} |",
        f"| Category accuracy | {m['category_accuracy']} |",
        f"| Invalid or missing predictions | {m['invalid_or_missing_predictions']} |",
        f"| Avg latency (ms) | {m['avg_latency_ms']} |",
        f"| Avg cost (USD) | {m['avg_cost_usd']} |", "",
        "## Confusion matrix (rows = truth, columns = prediction)", "",
        "| | " + " | ".join(LABELS + ["error"]) + " |",
        "|---" * (len(LABELS) + 2) + "|",
    ]
    for truth, cols in m["confusion_matrix"].items():
        lines.append(f"| **{truth}** | " + " | ".join(str(v) for v in cols.values()) + " |")
    lines += ["", "## Mistakes", ""]
    lines += [f"- `{x['file']}`: expected {x['expected']}, got {x['got']}"
              + (f" ({x['error']})" if x["error"] else "") for x in m["mistakes"]] or ["None."]
    return "\n".join(lines) + "\n"


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--split", required=True, choices=["dev", "test"],
                        help="Tune on dev. Report test only, and only for final numbers.")
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--predictor", help="package.module:function")
    source.add_argument("--predictions", type=Path, help="CSV with file,verdict,category")
    parser.add_argument("--name", help="Label for this run in the results file name")
    args = parser.parse_args()

    rows = load_labels(args.split)
    if args.predictor:
        predictions = predict_all(rows, load_predictor(args.predictor))
        name = args.name or args.predictor.replace(":", ".")
    else:
        predictions = load_predictions_csv(args.predictions)
        name = args.name or args.predictions.stem

    metrics = score(rows, predictions)
    RESULTS_DIR.mkdir(exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    base = RESULTS_DIR / f"{stamp}_{args.split}_{name}"
    report = {"name": name, "split": args.split, "created_utc": stamp, **metrics}
    base.with_suffix(".json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    markdown = to_markdown(name, args.split, metrics)
    base.with_suffix(".md").write_text(markdown, encoding="utf-8")
    print(markdown)
    print(f"Saved {base}.json and .md")


if __name__ == "__main__":
    main()
