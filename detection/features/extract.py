"""
Bastion — detection feature extraction (Week 2 skeleton)
========================================================
Turns captured traffic into per-flow feature rows. Two sources:

  * synthetic_flows(n)      -> generated rows for dev/testing without the lab
  * extract_from_pcap(path) -> real features from a capture (Scapy, lazy import)

The feature columns here are the thing the Week 3 sync (#9) compares
column-for-column against the dashboard's training matrix. Keep FEATURE_COLUMNS
as the single source of truth for that list.

Scope: synthetic path is complete and runnable now. The pcap path is a stub
with the real interface in place — it fills in once the VM lab produces
captures (#1) and real SYN-flood traffic exists (#4).
"""

from __future__ import annotations

import numpy as np
import pandas as pd

# The agreed numeric feature set (metadata like src_ip is carried separately).
FEATURE_COLUMNS: list[str] = [
    "duration_s",
    "pkt_count",
    "byte_count",
    "pkts_per_s",
    "syn_ratio",        # fraction of packets with only SYN set
    "udp_ratio",        # fraction of packets that are UDP
    "unique_dst_ports",
    "mean_iat_ms",      # mean inter-arrival time
    "mean_pkt_size",
]

# How the synthetic generator shapes each class. Rough, plausible distributions
# so the placeholder classifier has something separable to work on.
_CLASS_PROFILES = {
    "syn_flood": dict(duration=(2, 8), pps=(2000, 8000), syn=(0.85, 0.99),
                      udp=(0.0, 0.05), ports=(200, 1000), iat=(0.1, 0.5), size=(40, 64)),
    "udp_flood": dict(duration=(2, 8), pps=(3000, 9000), syn=(0.0, 0.05),
                      udp=(0.85, 0.99), ports=(1, 20), iat=(0.1, 0.4), size=(512, 1400)),
    "slowloris": dict(duration=(60, 300), pps=(1, 20), syn=(0.2, 0.5),
                      udp=(0.0, 0.05), ports=(1, 5), iat=(500, 5000), size=(100, 300)),
    "benign":    dict(duration=(1, 120), pps=(5, 200), syn=(0.05, 0.3),
                      udp=(0.1, 0.4), ports=(1, 40), iat=(5, 200), size=(200, 1200)),
}


def _rng(seed: int | None) -> np.random.Generator:
    return np.random.default_rng(seed)


def synthetic_flows(n: int = 8, seed: int | None = None) -> pd.DataFrame:
    """Generate `n` labeled synthetic flows (roughly balanced across classes).

    Returns a DataFrame with FEATURE_COLUMNS plus `src_ip` and `label`
    (`label` is ground truth for testing; real inference won't have it).
    """
    rng = _rng(seed)
    classes = list(_CLASS_PROFILES)
    rows = []
    for i in range(n):
        label = classes[i % len(classes)]
        p = _CLASS_PROFILES[label]
        pps = rng.uniform(*p["pps"])
        duration = rng.uniform(*p["duration"])
        pkt_count = max(1, int(pps * duration))
        mean_size = rng.uniform(*p["size"])
        rows.append({
            "src_ip": f"10.0.0.{10 + i}",
            "duration_s": round(duration, 3),
            "pkt_count": pkt_count,
            "byte_count": int(pkt_count * mean_size),
            "pkts_per_s": round(pps, 2),
            "syn_ratio": round(rng.uniform(*p["syn"]), 3),
            "udp_ratio": round(rng.uniform(*p["udp"]), 3),
            "unique_dst_ports": int(rng.uniform(*p["ports"])),
            "mean_iat_ms": round(rng.uniform(*p["iat"]), 3),
            "mean_pkt_size": round(mean_size, 1),
            "label": label,
        })
    return pd.DataFrame(rows, columns=["src_ip", *FEATURE_COLUMNS, "label"])


def extract_from_pcap(path: str) -> pd.DataFrame:
    """Extract per-flow features from a pcap. STUB — fills in with the lab (#1/#4).

    The interface is final: returns a DataFrame with `src_ip` + FEATURE_COLUMNS
    (no `label`, since real captures are unlabeled). Raises if Scapy is missing
    so the dependency surfaces clearly rather than silently no-op'ing.
    """
    try:
        from scapy.all import rdpcap  # noqa: F401  (lazy: only capture needs it)
    except ImportError as e:  # pragma: no cover - environment dependent
        raise RuntimeError(
            "Scapy is required for pcap extraction. `pip install scapy` and "
            "run on the monitor VM. See detection/capture/README.md."
        ) from e

    raise NotImplementedError(
        "pcap feature extraction is not implemented yet — Week 2 target (#4). "
        "Group packets into flows by (src_ip, dst_ip, dst_port, proto), then "
        "compute FEATURE_COLUMNS per flow. Use synthetic_flows() until then."
    )


if __name__ == "__main__":
    df = synthetic_flows(8, seed=1)
    with pd.option_context("display.width", 200, "display.max_columns", 20):
        print(df.to_string(index=False))
