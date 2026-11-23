"""
Bastion — detection classifier
===============================
Maps one feature row to (AttackType, confidence).

Two backends behind one stable interface, `classify_row`:
  1. the trained Random Forest (rf_model.joblib) if present — train it with
     train_rf.py (issue #10);
  2. a transparent rule-based fallback, so the pipeline runs even with no model
     committed.

Callers (emitter, pipeline) never change when the model is swapped in.
"""

from __future__ import annotations

import pathlib
import sys

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT))

from shared.schema import AttackType  # noqa: E402

MODEL_PATH = pathlib.Path(__file__).resolve().parent / "rf_model.joblib"
_bundle = None
_tried = False


def _load_model():
    """Lazy-load the RF bundle once; return None if absent/unloadable."""
    global _bundle, _tried
    if _tried:
        return _bundle
    _tried = True
    if MODEL_PATH.exists():
        try:
            import joblib
            _bundle = joblib.load(MODEL_PATH)
        except Exception as e:  # pragma: no cover
            print(f"[classify] could not load model ({e}); using rule fallback")
            _bundle = None
    return _bundle


def classify_row(f: dict) -> tuple[AttackType, float]:
    """Return (attack_type, confidence in [0,1]) for one feature row.

    Uses the trained RF if available, else the rule-based fallback.
    """
    bundle = _load_model()
    if bundle is not None:
        X = [[float(f.get(c, 0.0)) for c in bundle["features"]]]
        proba = bundle["model"].predict_proba(X)[0]
        i = int(proba.argmax())
        cls = bundle["classes"][i]
        conf = round(min(0.999, float(proba[i])), 3)
        return AttackType(cls), conf
    return _rule_based(f)


def _rule_based(f: dict) -> tuple[AttackType, float]:
    """Rule-based stand-in used only when the RF model is absent/unloadable.

    Coarse heuristics over the shared FEATURE_COLUMNS, mapped to the InSDN
    taxonomy {benign, dos, ddos, probe}. The trained RF (rf_model.joblib) is the
    real classifier; this fallback just keeps the pipeline running and emitting
    contract-valid events when no model is committed.

      * probe  — horizontal scan: many distinct destination ports, small/sparse
                 packets (reconnaissance, not a volumetric flood).
      * ddos   — very high packet rate, i.e. a sustained volumetric flood.
      * dos    — elevated but lower-rate flood from a single flow.
    """
    pps = float(f.get("pkts_per_s", 0.0))
    ports = float(f.get("unique_dst_ports", 1.0))
    pkts = float(f.get("pkt_count", 0.0))
    size = float(f.get("mean_pkt_size", 0.0))

    # Port scanning / probing: fanned out across many destination ports.
    if ports > 10 and size < 300:
        return AttackType.PROBE, _conf(min(0.95, ports / 50 + 0.5))
    # Volumetric flood — split dos vs ddos by rate/volume magnitude.
    if pps > 2000 or pkts > 20000:
        return AttackType.DDOS, _conf(min(0.95, pps / 5000 + 0.5))
    if pps > 500:
        return AttackType.DOS, _conf(min(0.9, pps / 2000 + 0.5))
    return AttackType.BENIGN, _conf(0.7)


def _conf(x: float) -> float:
    return round(max(0.5, min(0.99, x)), 3)


if __name__ == "__main__":
    import pathlib as _pl
    sys.path.insert(0, str(_pl.Path(__file__).resolve().parents[1]))
    from features.extract import synthetic_flows, FEATURE_COLUMNS

    backend = "RF model" if _load_model() else "rule fallback"
    print(f"backend: {backend}\n")
    df = synthetic_flows(8, seed=1)
    for _, row in df.iterrows():
        at, conf = classify_row({c: row[c] for c in FEATURE_COLUMNS})
        print(f"{row['src_ip']:<12} truth={row['label']:<10} "
              f"pred={at.value:<10} conf={conf}")
