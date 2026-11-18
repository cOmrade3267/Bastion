"""
Bastion — Random Forest trainer (issue #10)
===========================================
Trains the detection classifier on FEATURE_COLUMNS and saves an artifact that
classify_row() loads for live inference.

    # test run, no download needed:
    python train_rf.py --data synthetic

    # real data once you have the CSVs:
    python train_rf.py --data cicddos --csv "data/CICDDoS2019/*.csv"

Outputs (in detection/models/):
    rf_model.joblib   the trained model + feature order + class list
    metrics.json      per-class precision/recall/F1, accuracy, importances
    confusion.csv     confusion matrix (rows=true, cols=pred) for the eval notebook

Design notes grounded in the CICDDoS2019 literature:
  - trained on 9 behavioral features only — NO IP/port/timestamp identifiers,
    which are the usual source of fake ~1.0 F1 (leakage).
  - preprocessing that could leak (none needed beyond sanitation) is kept out
    of the fit; the split is stratified; class_weight balances the classes.
"""

from __future__ import annotations

import argparse
import json
import pathlib
import sys
from datetime import datetime, timezone

import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.metrics import classification_report, confusion_matrix, f1_score

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))

from features.extract import FEATURE_COLUMNS  # noqa: E402
from models.datasets import make_synthetic, load_cicddos2019  # noqa: E402

MODEL_PATH = HERE / "rf_model.joblib"
METRICS_PATH = HERE / "metrics.json"
CONFUSION_PATH = HERE / "confusion.csv"


def build_model(seed: int) -> RandomForestClassifier:
    # Modest depth + min_samples_leaf guards against the dataset's shortcut
    # features; balanced weights handle CICDDoS2019's heavy class imbalance.
    return RandomForestClassifier(
        n_estimators=200,
        max_depth=18,
        min_samples_leaf=2,
        max_features="sqrt",
        class_weight="balanced",
        n_jobs=-1,
        random_state=seed,
    )


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--data", choices=["synthetic", "cicddos"], default="synthetic")
    ap.add_argument("--csv", help="glob for CICDDoS2019 CSVs (with --data cicddos)")
    ap.add_argument("--n-per-class", type=int, default=2500, help="synthetic size")
    ap.add_argument("--test-size", type=float, default=0.25)
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--cv", action="store_true", help="also run 5-fold CV")
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
    print(f"dataset: {len(df)} rows · classes: "
          f"{dict(pd.Series(y).value_counts())}")

    X_tr, X_te, y_tr, y_te = train_test_split(
        X, y, test_size=args.test_size, random_state=args.seed, stratify=y)

    clf = build_model(args.seed)
    clf.fit(X_tr, y_tr)
    y_pred = clf.predict(X_te)

    labels = sorted(np.unique(y))
    report = classification_report(y_te, y_pred, labels=labels,
                                   output_dict=True, zero_division=0)
    macro_f1 = f1_score(y_te, y_pred, average="macro", labels=labels)
    cm = confusion_matrix(y_te, y_pred, labels=labels)
    importances = dict(sorted(
        zip(FEATURE_COLUMNS, clf.feature_importances_.round(4)),
        key=lambda kv: -kv[1]))

    # --- report to console ---
    print("\n=== per-class metrics (held-out test) ===")
    print(classification_report(y_te, y_pred, labels=labels, zero_division=0))
    print(f"macro-F1: {macro_f1:.4f}   accuracy: {report['accuracy']:.4f}")
    print("\nconfusion matrix (rows=true, cols=pred):")
    print(pd.DataFrame(cm, index=labels, columns=labels).to_string())
    print("\ntop feature importances:")
    for k, v in importances.items():
        print(f"  {k:<18} {v}")

    if args.cv:
        cv = cross_val_score(build_model(args.seed), X, y, cv=5, scoring="f1_macro")
        print(f"\n5-fold CV macro-F1: {cv.mean():.4f} ± {cv.std():.4f}")

    # --- persist ---
    import joblib
    joblib.dump({
        "model": clf,
        "features": list(FEATURE_COLUMNS),
        "classes": list(clf.classes_),
        "trained_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "source": source,
    }, MODEL_PATH)

    METRICS_PATH.write_text(json.dumps({
        "source": source,
        "n_rows": len(df),
        "class_counts": {k: int(v) for k, v in pd.Series(y).value_counts().items()},
        "accuracy": report["accuracy"],
        "macro_f1": macro_f1,
        "per_class": {c: report[c] for c in labels},
        "feature_importances": importances,
        "trained_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
    }, indent=2))
    pd.DataFrame(cm, index=labels, columns=labels).to_csv(CONFUSION_PATH)

    print(f"\nsaved: {MODEL_PATH.name}, {METRICS_PATH.name}, {CONFUSION_PATH.name}")
    if source.startswith("synthetic"):
        print("NOTE: metrics are on SYNTHETIC data — real CICDDoS2019 numbers "
              "will differ. Re-run with --data cicddos --csv <path> for real.")


if __name__ == "__main__":
    main()
