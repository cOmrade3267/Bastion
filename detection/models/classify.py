"""
Bastion — detection classifier (Week 2 placeholder)
===================================================
Maps one feature row to (AttackType, confidence).

This is a transparent rule-based PLACEHOLDER so the end-to-end pipeline runs
and emits events before the real model exists. It gets replaced by the trained
Random Forest in Week 4 (#10) behind this same `classify_row` interface — keep
the signature stable so the emitter/pipeline don't change.
"""

from __future__ import annotations

import sys
import pathlib

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT))

from shared.schema import AttackType  # noqa: E402


def classify_row(f: dict) -> tuple[AttackType, float]:
    """Return (attack_type, confidence in [0,1]) for one feature row.

    Rule-based stand-in for the RF model. Thresholds mirror the synthetic
    profiles in features/extract.py; they are NOT tuned for real traffic.
    """
    syn = float(f.get("syn_ratio", 0.0))
    udp = float(f.get("udp_ratio", 0.0))
    pps = float(f.get("pkts_per_s", 0.0))
    duration = float(f.get("duration_s", 0.0))
    iat = float(f.get("mean_iat_ms", 0.0))

    if syn > 0.6 and pps > 500:
        return AttackType.SYN_FLOOD, _conf(syn)
    if udp > 0.6 and pps > 500:
        return AttackType.UDP_FLOOD, _conf(udp)
    if duration > 30 and pps < 50 and iat > 400:
        # low-and-slow signature
        return AttackType.SLOWLORIS, _conf(min(1.0, iat / 5000 + 0.5))
    return AttackType.BENIGN, _conf(0.7)


def _conf(x: float) -> float:
    """Clamp a raw score into a believable confidence band [0.5, 0.99]."""
    return round(max(0.5, min(0.99, x)), 3)


if __name__ == "__main__":
    import pathlib as _pl
    sys.path.insert(0, str(_pl.Path(__file__).resolve().parents[1]))
    from features.extract import synthetic_flows, FEATURE_COLUMNS

    df = synthetic_flows(8, seed=1)
    for _, row in df.iterrows():
        at, conf = classify_row({c: row[c] for c in FEATURE_COLUMNS})
        print(f"{row['src_ip']:<12} truth={row['label']:<10} "
              f"pred={at.value:<10} conf={conf}")
