"""
Bastion — model benchmark (Week 6, #16)
=======================================
Compares the Random Forest baseline against alternative classifiers on the
SAME data, SAME stratified split, and the same 9 FEATURE_COLUMNS the live
extractor produces. Reports, per model:

    macro-F1 · accuracy · train time · inference latency (µs/flow) · model size

Candidates (each included only if its library is importable, so the script runs
out of the box and simply reports what's available):

    random_forest      sklearn RandomForest  — the baseline (always)
    extra_trees        sklearn ExtraTrees    — RF cousin (always)
    hist_gradient_boost sklearn HistGBoost   — gradient boosting, no extra dep (always)
    xgboost            XGBoost               — if `xgboost` is installed
    mlp                sklearn MLP           — small net; a flat-feature stand-in
                                               (see the LSTM note below)

On LSTM / sequence models
-------------------------
The issue lists "XGBoost/LSTM". An LSTM models an *ordered sequence* (e.g. the
packet-by-packet timeline of a flow). Our feature representation is a single
aggregated vector per flow (FEATURE_COLUMNS), which has no time axis for an LSTM
to exploit — feeding flat flow vectors to an LSTM just makes it a worse MLP.
So we benchmark a small **MLP** as the neural-net point of comparison and record
honestly that a true LSTM belongs to a *different feature pipeline* (raw packet
sequences), which is future work, not a drop-in swap at this layer.

Usage:
    python models/benchmark.py                        # synthetic data
    python models/benchmark.py --data cicddos --csv "data/CICDDoS2019/*.csv"
    python models/benchmark.py --n-per-class 2500 --seed 42
"""

from __future__ import annotations

import argparse
import json
import pathlib
import sys
import time
from datetime import datetime, timezone

import numpy as np
import pandas as pd
from sklearn.ensemble import (RandomForestClassifier, ExtraTreesClassifier,
                              HistGradientBoostingClassifier)
from sklearn.neural_network import MLPClassifier
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split
from sklearn.metrics import f1_score, accuracy_score, classification_report

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))

from features.extract import FEATURE_COLUMNS  # noqa: E402
from models.datasets import make_synthetic, load_cicddos2019  # noqa: E402

RESULTS_PATH = HERE / "benchmark.json"


def candidates(seed: int) -> dict:
    """Name -> estimator. XGBoost added only if the library is present."""
    models = {
        "random_forest": RandomForestClassifier(
            n_estimators=200, max_depth=18, min_samples_leaf=2,
            max_features="sqrt", class_weight="balanced", n_jobs=-1,
            random_state=seed),
        "extra_trees": ExtraTreesClassifier(
            n_estimators=200, max_depth=18, min_samples_leaf=2,
            class_weight="balanced", n_jobs=-1, random_state=seed),
        "hist_gradient_boost": HistGradientBoostingClassifier(
            max_depth=12, learning_rate=0.12, max_iter=300,
            random_state=seed),
        # MLP needs scaled inputs (the tree models don't care) -> pipe a scaler.
        "mlp": make_pipeline(StandardScaler(), MLPClassifier(
            hidden_layer_sizes=(64, 32), max_iter=400, early_stopping=True,
            random_state=seed)),
    }
    try:
        from xgboost import XGBClassifier  # noqa: F401
        models["xgboost"] = ("xgb", seed)  # built lazily below (needs label encoding)
    except Exception:
        print("[benchmark] xgboost not installed — skipping it "
              "(pip install xgboost to include). Benchmarking the rest.")
    return models


def _fit_predict(name, est, X_tr, y_tr, X_te, seed):
    """Fit, return (y_pred, train_s, infer_us_per_flow, size_bytes)."""
    import pickle
    # XGBoost needs integer labels; wrap it with an encoder transparently.
    if isinstance(est, tuple) and est[0] == "xgb":
        from xgboost import XGBClassifier
        from sklearn.preprocessing import LabelEncoder
        le = LabelEncoder().fit(y_tr)
        clf = XGBClassifier(n_estimators=300, max_depth=8, learning_rate=0.12,
                            subsample=0.9, colsample_bytree=0.9, n_jobs=-1,
                            eval_metric="mlogloss", random_state=seed)
        t0 = time.perf_counter(); clf.fit(X_tr, le.transform(y_tr)); train_s = time.perf_counter() - t0
        t1 = time.perf_counter(); pred_i = clf.predict(X_te); infer = time.perf_counter() - t1
        y_pred = le.inverse_transform(pred_i)
        size = len(pickle.dumps(clf))
    else:
        t0 = time.perf_counter(); est.fit(X_tr, y_tr); train_s = time.perf_counter() - t0
        t1 = time.perf_counter(); y_pred = est.predict(X_te); infer = time.perf_counter() - t1
        size = len(pickle.dumps(est))
    us_per_flow = (infer / max(1, len(X_te))) * 1e6
    return y_pred, train_s, us_per_flow, size


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--data", choices=["synthetic", "cicddos"], default="synthetic")
    ap.add_argument("--csv", help="glob for CICDDoS2019 CSVs (with --data cicddos)")
    ap.add_argument("--n-per-class", type=int, default=2500)
    ap.add_argument("--test-size", type=float, default=0.25)
    ap.add_argument("--seed", type=int, default=42)
    args = ap.parse_args()

    if args.data == "synthetic":
        df = make_synthetic(n_per_class=args.n_per_class, seed=args.seed)
        source = f"synthetic (n_per_class={args.n_per_class}, seed={args.seed})"
    else:
        if not args.csv:
            ap.error("--data cicddos requires --csv <glob>")
        df = load_cicddos2019(args.csv)
        source = f"CICDDoS2019 ({args.csv})"

    X = df[FEATURE_COLUMNS].to_numpy(dtype=float)
    y = df["label"].to_numpy()
    X_tr, X_te, y_tr, y_te = train_test_split(
        X, y, test_size=args.test_size, random_state=args.seed, stratify=y)
    print(f"dataset: {len(df)} rows · {dict(pd.Series(y).value_counts())}")
    print(f"split: {len(X_tr)} train / {len(X_te)} test\n")

    rows = []
    for name, est in candidates(args.seed).items():
        y_pred, train_s, infer_us, size = _fit_predict(name, est, X_tr, y_tr, X_te, args.seed)
        macro = f1_score(y_te, y_pred, average="macro")
        acc = accuracy_score(y_te, y_pred)
        rep = classification_report(y_te, y_pred, output_dict=True, zero_division=0)
        per_class_f1 = {c: round(rep[c]["f1-score"], 4) for c in sorted(set(y))}
        rows.append({
            "model": name, "macro_f1": round(macro, 4), "accuracy": round(acc, 4),
            "train_s": round(train_s, 3), "infer_us_per_flow": round(infer_us, 2),
            "size_kb": round(size / 1024, 1), "per_class_f1": per_class_f1,
        })
        print(f"{name:<20} macroF1={macro:.4f}  acc={acc:.4f}  "
              f"train={train_s:6.2f}s  infer={infer_us:7.1f}µs/flow  size={size/1024:7.1f}KB")

    rows.sort(key=lambda r: -r["macro_f1"])
    baseline = next(r["macro_f1"] for r in rows if r["model"] == "random_forest")

    print("\n=== ranking (by macro-F1) — Δ vs random_forest baseline ===")
    print(f"{'rank':<5}{'model':<20}{'macroF1':<10}{'Δ vs RF':<10}{'infer µs':<10}{'size KB'}")
    for i, r in enumerate(rows, 1):
        delta = r["macro_f1"] - baseline
        print(f"{i:<5}{r['model']:<20}{r['macro_f1']:<10.4f}{delta:+.4f}   "
              f"{r['infer_us_per_flow']:<10.1f}{r['size_kb']}")

    winner = rows[0]
    note = ("RF is within noise of the best alternative — keep it: it is the "
            "simplest, is already wired into classify_row, and needs no extra dependency."
            if abs(winner["macro_f1"] - baseline) < 0.01 else
            f"{winner['model']} leads RF by {winner['macro_f1'] - baseline:+.4f} macro-F1 — "
            f"worth considering if the gap holds on real CICDDoS2019 data.")
    print(f"\nverdict: {note}")
    print("LSTM: out of scope at this layer — needs raw packet sequences, not "
          "aggregated flow vectors (see module docstring). Future work.")

    RESULTS_PATH.write_text(json.dumps({
        "source": source, "n_rows": len(df),
        "test_size": args.test_size, "seed": args.seed,
        "baseline_macro_f1": baseline,
        "results": rows,
        "lstm": "out of scope — requires sequence features, not flow aggregates",
        "benchmarked_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
    }, indent=2))
    print(f"\nsaved: {RESULTS_PATH.name}")


if __name__ == "__main__":
    main()
