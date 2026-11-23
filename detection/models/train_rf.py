"""
Bastion — Random Forest trainer (issue #10)
===========================================
Trains the detection classifier on FEATURE_COLUMNS and saves an artifact that
classify_row() loads for live inference.

    # test run, no download needed (random stratified split):
    python train_rf.py --data synthetic

    # real data, CICDDoS2019 OFFICIAL split (train day vs test day):
    python train_rf.py --data cicddos \
        --train-csv "data/CICDDoS2019/CSV-01-12/*.csv" \
        --test-csv  "data/CICDDoS2019/CSV-03-11/*.csv" --cv

    # real data, single pile with a random stratified split instead:
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
  - the honest protocol is the dataset's OWN train/test day split (--train-csv /
    --test-csv): the model never sees the test day, so numbers don't flatter.
    A random split of one pile (--csv) can leak near-duplicate flows across the
    split and inflate scores — use it only for a quick sanity pass.
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
from models.datasets import make_synthetic, load_cicddos2019, load_insdn  # noqa: E402

_LOADERS = {"cicddos": load_cicddos2019, "insdn": load_insdn}

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


def _xy(df: pd.DataFrame):
    return df[FEATURE_COLUMNS].to_numpy(dtype=float), df["label"].to_numpy()


def load_split(args):
    """Return (X_tr, y_tr, X_te, y_te, source, protocol).

    Three protocols:
      * synthetic               -> generate, then random stratified split
      * cicddos + train/test csv -> the dataset's own train-day/test-day split
      * cicddos + --csv          -> one pile, random stratified split
    """
    if args.data == "synthetic":
        df = make_synthetic(n_per_class=args.n_per_class, seed=args.seed)
        X, y = _xy(df)
        X_tr, X_te, y_tr, y_te = train_test_split(
            X, y, test_size=args.test_size, random_state=args.seed, stratify=y)
        source = f"synthetic (n_per_class={args.n_per_class}, seed={args.seed})"
        return X_tr, y_tr, X_te, y_te, source, "random split"

    # --- real datasets (cicddos | insdn): both are CICFlowMeter CSVs ---
    loader = _LOADERS[args.data]
    name = args.data.upper()

    if args.train_csv or args.test_csv:
        if not (args.train_csv and args.test_csv):
            raise SystemExit("--train-csv and --test-csv must be given together")
        df_tr = loader(args.train_csv)
        df_te = loader(args.test_csv)
        X_tr, y_tr = _xy(df_tr)
        X_te, y_te = _xy(df_te)
        print(f"train set: {len(df_tr)} rows · {dict(pd.Series(y_tr).value_counts())}")
        print(f"test  set: {len(df_te)} rows · {dict(pd.Series(y_te).value_counts())}")
        source = f"{name} explicit split (train={args.train_csv} | test={args.test_csv})"
        return X_tr, y_tr, X_te, y_te, source, "explicit train/test split"

    if not args.csv:
        raise SystemExit(f"--data {args.data} requires either --csv <glob>, "
                         "or both --train-csv and --test-csv")
    df = loader(args.csv)
    X, y = _xy(df)
    X_tr, X_te, y_tr, y_te = train_test_split(
        X, y, test_size=args.test_size, random_state=args.seed, stratify=y)
    print(f"dataset: {len(df)} rows · {dict(pd.Series(y).value_counts())}")
    source = f"{name} ({args.csv}) random split test_size={args.test_size}"
    return X_tr, y_tr, X_te, y_te, source, "random stratified split"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--data", choices=["synthetic", "cicddos", "insdn"], default="synthetic")
    ap.add_argument("--csv", help="glob for real CSVs (cicddos/insdn) — one pile, random split")
    ap.add_argument("--train-csv", help="glob for the CICDDoS2019 TRAINING day (CSV-01-12)")
    ap.add_argument("--test-csv", help="glob for the CICDDoS2019 TESTING day (CSV-03-11)")
    ap.add_argument("--n-per-class", type=int, default=2500, help="synthetic size")
    ap.add_argument("--test-size", type=float, default=0.25,
                    help="random-split test fraction (ignored for --train-csv/--test-csv)")
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--cv", action="store_true",
                    help="also run 5-fold CV on the TRAINING set")
    args = ap.parse_args()

    X_tr, y_tr, X_te, y_te, source, protocol = load_split(args)
    print(f"protocol: {protocol}")
    print(f"split: {len(X_tr)} train / {len(X_te)} test rows")

    clf = build_model(args.seed)
    clf.fit(X_tr, y_tr)
    y_pred = clf.predict(X_te)

    # Report over the union of labels seen in train or test, so a class that is
    # absent from one side still shows up (with zeros) instead of vanishing.
    labels = sorted(set(map(str, y_tr)) | set(map(str, y_te)))
    y_te_s = y_te.astype(str)
    y_pred_s = y_pred.astype(str)
    report = classification_report(y_te_s, y_pred_s, labels=labels,
                                   output_dict=True, zero_division=0)
    macro_f1 = f1_score(y_te_s, y_pred_s, average="macro", labels=labels)
    cm = confusion_matrix(y_te_s, y_pred_s, labels=labels)
    importances = dict(sorted(
        zip(FEATURE_COLUMNS, clf.feature_importances_.round(4)),
        key=lambda kv: -kv[1]))

    # --- report to console ---
    print("\n=== per-class metrics (held-out test) ===")
    print(classification_report(y_te_s, y_pred_s, labels=labels, zero_division=0))
    print(f"macro-F1: {macro_f1:.4f}   accuracy: {report['accuracy']:.4f}")
    print("\nconfusion matrix (rows=true, cols=pred):")
    print(pd.DataFrame(cm, index=labels, columns=labels).to_string())
    print("\ntop feature importances:")
    for k, v in importances.items():
        print(f"  {k:<18} {v}")

    missing = [c for c in labels if c not in set(map(str, y_tr))]
    if missing:
        print(f"\nWARNING: classes absent from the TRAINING set (model can't "
              f"predict them): {missing}. CICDDoS2019 has no slowloris — add "
              f"CIC-IDS2017 DoS CSVs to the --train-csv glob to cover it.")

    cv_summary = None
    if args.cv:
        cv = cross_val_score(build_model(args.seed), X_tr, y_tr, cv=5,
                             scoring="f1_macro")
        cv_summary = {
            "folds": 5,
            "macro_f1_mean": float(cv.mean()),
            "macro_f1_std": float(cv.std()),
            "scores": [float(s) for s in cv],
        }
        print(f"\n5-fold CV macro-F1 (train set): {cv.mean():.4f} ± {cv.std():.4f}")

    # --- persist ---
    import joblib
    now = datetime.now(timezone.utc).isoformat(timespec="seconds")
    joblib.dump({
        "model": clf,
        "features": list(FEATURE_COLUMNS),
        "classes": list(clf.classes_),
        "trained_at": now,
        "source": source,
    }, MODEL_PATH)

    y_all = np.concatenate([y_tr, y_te]).astype(str)
    METRICS_PATH.write_text(json.dumps({
        "source": source,
        "protocol": protocol,
        "n_rows": int(len(X_tr) + len(X_te)),
        "train_rows": int(len(X_tr)),
        "test_rows": int(len(X_te)),
        "class_counts": {k: int(v) for k, v in pd.Series(y_all).value_counts().items()},
        "accuracy": report["accuracy"],
        "macro_f1": macro_f1,
        "cross_validation": cv_summary,  # null unless --cv was passed
        "per_class": {c: report[c] for c in labels},
        "feature_importances": importances,
        "trained_at": now,
    }, indent=2))
    pd.DataFrame(cm, index=labels, columns=labels).to_csv(CONFUSION_PATH)

    print(f"\nsaved: {MODEL_PATH.name}, {METRICS_PATH.name}, {CONFUSION_PATH.name}")
    if source.startswith("synthetic"):
        print("NOTE: metrics are on SYNTHETIC data — real CICDDoS2019 numbers "
              "will differ. Re-run with --data cicddos and the real CSVs.")


if __name__ == "__main__":
    main()
