"""
Bastion — training data for the RF model
========================================
Produces a labeled table in the shared FEATURE_COLUMNS space, from either:

  * make_synthetic(...)        -> noisy generated flows (dev/testing, no download)
  * load_cicddos2019(paths)    -> real CICDDoS2019 CSVs mapped down to our 9 features

Training on FEATURE_COLUMNS (not CICFlowMeter's 80) is deliberate: it is exactly
what the live extractor (features/extract.py) produces, so the trained model
drops straight into classify_row() for live inference. We intentionally keep NO
socket identifiers (IP/port/timestamp) — the CICDDoS2019 literature shows those
leak and give fake ~1.0 F1.
"""

from __future__ import annotations

import glob as _glob
import sys
import pathlib

import numpy as np
import pandas as pd

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))  # so `features` is importable

from features.extract import synthetic_flows, FEATURE_COLUMNS  # noqa: E402

# Synthetic generator classes — the InSDN taxonomy the live model uses
# (shared/schema.py AttackType). Kept in sync with features.extract profiles.
CLASSES = ["benign", "dos", "ddos", "probe"]


# --------------------------------------------------------------------------- #
# Synthetic (noisy) — a realistic-ish stand-in until real CSVs are provided
# --------------------------------------------------------------------------- #
def make_synthetic(n_per_class: int = 2500, seed: int = 0,
                   noise: float = 0.28, label_noise: float = 0.02) -> pd.DataFrame:
    """Generate a noisy, partially-overlapping dataset in FEATURE_COLUMNS space.

    Noise and a small amount of label flipping are added on purpose so the model
    has to generalize (and the reported metrics aren't a suspicious 1.0).
    """
    rng = np.random.default_rng(seed)
    base = synthetic_flows(n=n_per_class * len(CLASSES), seed=seed)
    n = len(base)

    # Build columns as arrays (no in-place assignment on a slice) then assemble.
    data = {}
    for col in FEATURE_COLUMNS:
        factor = np.clip(1.0 + rng.normal(0, noise, size=n), 0.3, 2.2)
        data[col] = base[col].to_numpy(dtype=float) * factor
    data["syn_ratio"] = np.clip(data["syn_ratio"], 0.0, 1.0)
    data["udp_ratio"] = np.clip(data["udp_ratio"], 0.0, 1.0)
    data["pkt_count"] = np.clip(np.round(data["pkt_count"]), 1, None)
    data["unique_dst_ports"] = np.clip(np.round(data["unique_dst_ports"]), 1, None)

    labels = base["label"].to_numpy().copy()
    if label_noise > 0:  # flip a small fraction to random other classes
        k = int(n * label_noise)
        idx = rng.choice(n, size=k, replace=False)
        labels[idx] = rng.choice(CLASSES, size=k)

    return pd.DataFrame({**{c: data[c] for c in FEATURE_COLUMNS}, "label": labels})


# --------------------------------------------------------------------------- #
# CICDDoS2019 loader — maps CICFlowMeter columns -> FEATURE_COLUMNS
# --------------------------------------------------------------------------- #
# CICDDoS2019 attack-label substrings -> our 4 classes. Reflective/amplification
# types outside our schema (MSSQL, LDAP, NetBIOS, NTP, DNS, SNMP, Portmap) are
# dropped with a count, since the live detector only knows these four.
_LABEL_MAP = [
    ("benign", "benign"),
    ("syn", "syn_flood"),
    ("udplag", "udp_flood"),
    ("udp-lag", "udp_flood"),
    ("udp", "udp_flood"),
    ("slowloris", "slowloris"),
    ("slowhttptest", "slowloris"),
]


def _norm_label(raw: str):
    s = str(raw).strip().lower()
    for key, cls in _LABEL_MAP:
        if key in s:
            return cls
    return None  # out-of-schema attack -> dropped


def _col(df: pd.DataFrame, *names):
    """Return the first matching column (case/space-insensitive) or None."""
    norm = {c.strip().lower(): c for c in df.columns}
    for n in names:
        if n.strip().lower() in norm:
            return norm[n.strip().lower()]
    return None


def _resolve_files(paths):
    if isinstance(paths, (str, pathlib.Path)):
        files = sorted(_glob.glob(str(paths)))
    else:
        files = [f for p in paths for f in sorted(_glob.glob(str(p)))]
    if not files:
        raise FileNotFoundError(f"no CSVs matched: {paths}")
    return files


def _load_cicflowmeter(paths, label_norm, tag: str) -> pd.DataFrame:
    """Load CICFlowMeter-style CSVs -> FEATURE_COLUMNS + label.

    Shared by the CICDDoS2019 and InSDN loaders — both are CICFlowMeter output,
    so only the label taxonomy differs (`label_norm` maps a raw label string to
    one of our classes, or None to drop the row). Handles leading-space column
    names and Inf/NaN from rate features. Keeps NO socket identifiers
    (IP/port/timestamp): the literature shows those leak and give fake ~1.0 F1.
    """
    files = _resolve_files(paths)
    frames = []
    dropped_total = 0
    for fp in files:
        raw = pd.read_csv(fp, low_memory=False)
        raw.columns = [c.strip() for c in raw.columns]

        c_dur = _col(raw, "Flow Duration")
        c_fwd = _col(raw, "Total Fwd Packets", "Tot Fwd Pkts")
        c_bwd = _col(raw, "Total Backward Packets", "Tot Bwd Pkts")
        c_lfwd = _col(raw, "Total Length of Fwd Packets", "TotLen Fwd Pkts")
        c_lbwd = _col(raw, "Total Length of Bwd Packets", "TotLen Bwd Pkts")
        c_pps = _col(raw, "Flow Packets/s", "Flow Pkts/s")
        c_syn = _col(raw, "SYN Flag Count", "SYN Flag Cnt")
        c_proto = _col(raw, "Protocol")
        c_iat = _col(raw, "Flow IAT Mean")
        c_size = _col(raw, "Average Packet Size", "Pkt Size Avg", "Packet Length Mean")
        c_label = _col(raw, "Label")
        # Skip (don't crash on) CSVs in the folder that aren't CICFlowMeter output
        # — e.g. a custom-feature or pre-aggregated file mixed into the same dir.
        missing = [n for n, c in (("Label", c_label), ("Fwd Packets", c_fwd),
                                  ("Flow Duration", c_dur)) if c is None]
        if missing:
            print(f"[{tag}] skip {fp}: not CICFlowMeter-shaped "
                  f"(missing {', '.join(missing)})")
            continue

        n_pkts = raw[c_fwd].fillna(0) + (raw[c_bwd].fillna(0) if c_bwd else 0)
        n_pkts = n_pkts.clip(lower=1)
        n_bytes = raw[c_lfwd].fillna(0) + (raw[c_lbwd].fillna(0) if c_lbwd else 0)
        dur_s = raw[c_dur].astype(float) / 1e6 if c_dur else 0.0

        out = pd.DataFrame({
            "duration_s": dur_s,
            "pkt_count": n_pkts,
            "byte_count": n_bytes,
            "pkts_per_s": raw[c_pps] if c_pps else n_pkts / dur_s.replace(0, np.nan),
            "syn_ratio": (raw[c_syn].fillna(0) / n_pkts).clip(0, 1) if c_syn else 0.0,
            "udp_ratio": (raw[c_proto] == 17).astype(float) if c_proto else 0.0,
            "unique_dst_ports": 1,  # per-flow rows: live extraction provides the real value
            "mean_iat_ms": (raw[c_iat].astype(float) / 1000.0) if c_iat else 0.0,
            "mean_pkt_size": raw[c_size] if c_size else (n_bytes / n_pkts),
        })
        out["label"] = raw[c_label].map(label_norm)
        before = len(out)
        out = out.dropna(subset=["label"])
        dropped_total += before - len(out)
        frames.append(out)

    df = pd.concat(frames, ignore_index=True)
    # Clean Inf/NaN from rate features (fit nothing here — pure sanitation)
    df = df.replace([np.inf, -np.inf], np.nan)
    for col in FEATURE_COLUMNS:
        df[col] = pd.to_numeric(df[col], errors="coerce")
    df = df.dropna(subset=FEATURE_COLUMNS).drop_duplicates().reset_index(drop=True)
    print(f"[{tag}] loaded {len(df)} rows from {len(files)} file(s); "
          f"dropped {dropped_total} out-of-schema rows")
    return df[[*FEATURE_COLUMNS, "label"]]


def load_cicddos2019(paths) -> pd.DataFrame:
    """Load CICDDoS2019 CSVs -> FEATURE_COLUMNS + 4 flood-type labels.

    NOTE: maps to the RETIRED {syn_flood,udp_flood,slowloris,benign} taxonomy.
    The project pivoted to InSDN (#35) and the live contract (shared/schema.py
    AttackType) now carries {benign,dos,ddos,probe}, so a model trained on this
    loader's labels is NOT contract-compatible. Kept for reference/reproduction
    only; use load_insdn() for the current pipeline.
    """
    return _load_cicflowmeter(paths, _norm_label, "cicddos")


# --------------------------------------------------------------------------- #
# InSDN loader — CICFlowMeter CSVs, SDN attack taxonomy -> our classes
# --------------------------------------------------------------------------- #
# InSDN labels: Normal, DoS, DDoS, Probe, BFA, Web-Attack, BOTNET, U2R.
# We keep the DDoS-relevant + large classes (benign/dos/ddos/probe) and drop the
# small non-DDoS ones (BFA, Web-Attack, BOTNET, U2R) with a count. Order matters:
# match "ddos" before "dos" (ddos contains the substring "dos").
_INSDN_LABEL_MAP = [
    ("normal", "benign"),
    ("ddos", "ddos"),
    ("dos", "dos"),
    ("probe", "probe"),
]
INSDN_CLASSES = ["benign", "dos", "ddos", "probe"]


def _norm_insdn_label(raw: str):
    s = str(raw).strip().lower()
    for key, cls in _INSDN_LABEL_MAP:
        if key in s:
            return cls
    return None  # out-of-schema (BFA/Web-Attack/BOTNET/U2R) -> dropped


def load_insdn(paths) -> pd.DataFrame:
    """Load InSDN CSVs -> FEATURE_COLUMNS + {benign,dos,ddos,probe} labels.

    InSDN is CICFlowMeter output (84 cols) mapped down to the same 9 features
    the live extractor produces, so a model trained here drops into live
    inference. Small non-DDoS classes are dropped (see _INSDN_LABEL_MAP).
    """
    return _load_cicflowmeter(paths, _norm_insdn_label, "insdn")
