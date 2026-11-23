"""
Bastion — detection feature extraction (Week 2 skeleton)
========================================================
Turns captured traffic into per-flow feature rows. Two sources:

  * synthetic_flows(n)           -> generated rows for dev/testing without the lab
  * extract_from_pcap(path)      -> real features from a capture (Scapy, lazy import)
  * extract_from_live(iface, s)  -> real features sniffed live (Week-5 loop)

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
# in the InSDN taxonomy {benign, dos, ddos, probe} — the same classes the live
# model emits (shared/schema.py AttackType) — so a model trained on synthetic
# flows classifies into valid contract classes. Shapes line up with the
# rule-based fallback heuristics in models/classify.py:
#   probe -> many unique dst ports + small packets (scan)
#   ddos  -> very high packet rate, small packets (volumetric flood)
#   dos   -> elevated single-flow rate
_CLASS_PROFILES = {
    "benign": dict(duration=(1, 120), pps=(5, 200), syn=(0.05, 0.3),
                   udp=(0.1, 0.4), ports=(1, 40), iat=(5, 200), size=(200, 1200)),
    "dos":    dict(duration=(2, 12), pps=(600, 1800), syn=(0.5, 0.9),
                   udp=(0.0, 0.2), ports=(1, 10), iat=(0.3, 2.0), size=(120, 700)),
    "ddos":   dict(duration=(2, 15), pps=(2500, 9000), syn=(0.4, 0.95),
                   udp=(0.05, 0.5), ports=(50, 500), iat=(0.05, 0.4), size=(40, 220)),
    "probe":  dict(duration=(5, 90), pps=(5, 120), syn=(0.2, 0.6),
                   udp=(0.0, 0.2), ports=(20, 300), iat=(20, 800), size=(40, 250)),
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


def extract_from_pcap(path: str, min_packets: int = 1) -> pd.DataFrame:
    """Extract per-source-IP flow features from a pcap.

    Groups packets by source IP (the attacker in a flood) and computes
    FEATURE_COLUMNS for each. Returns a DataFrame with `src_ip` + FEATURE_COLUMNS
    (no `label` — real captures are unlabeled). Sources with fewer than
    `min_packets` packets are dropped.

    Scapy is imported lazily so the synthetic path and the rest of the pipeline
    don't require it; a clear error surfaces if a pcap is parsed without it.
    """
    try:
        from scapy.all import rdpcap
    except ImportError as e:  # pragma: no cover - environment dependent
        raise RuntimeError(
            "Scapy is required for pcap extraction. `pip install scapy` "
            "(see detection/requirements.txt / detection/capture/README.md)."
        ) from e
    return _aggregate_packets(rdpcap(path), min_packets=min_packets)


def extract_from_live(interface: str, seconds: float = 5.0,
                      min_packets: int = 1) -> pd.DataFrame:
    """Sniff `seconds` of live traffic on `interface`, return flow features.

    Same FEATURE_COLUMNS and per-source-IP aggregation as `extract_from_pcap`,
    so the trained model and the whole pipeline work on live traffic unchanged.
    This is the capture half of the Week-5 real-time loop (pipeline.py --source
    live --window N). Needs Scapy and root/CAP_NET_RAW, so it is not exercised
    in CI — the synthetic path covers development.
    """
    try:
        from scapy.all import sniff
    except ImportError as e:  # pragma: no cover - environment dependent
        raise RuntimeError(
            "Scapy is required for live capture. `pip install scapy` and run "
            "with root/CAP_NET_RAW (see detection/capture/README.md)."
        ) from e
    packets = sniff(iface=interface, timeout=seconds)
    return _aggregate_packets(packets, min_packets=min_packets)


def _aggregate_packets(packets, min_packets: int = 1) -> pd.DataFrame:
    """Aggregate Scapy packets into per-source-IP flow rows (FEATURE_COLUMNS).

    Shared by `extract_from_pcap` and `extract_from_live`: groups by source IP
    (the attacker in a flood). Returns a DataFrame with `src_ip` +
    FEATURE_COLUMNS (no `label` — captures are unlabeled). Sources with fewer
    than `min_packets` packets are dropped.
    """
    from scapy.all import IP, TCP, UDP  # lazy; caller ensured scapy is present
    flows: dict[str, dict] = {}
    for p in packets:
        if IP not in p:
            continue
        ip = p[IP]
        f = flows.get(ip.src)
        if f is None:
            f = flows[ip.src] = {
                "times": [], "bytes": 0, "syn": 0, "udp": 0, "dst_ports": set(),
            }
        f["times"].append(float(p.time))
        f["bytes"] += len(p)
        if TCP in p:
            flags = p[TCP].flags
            if "S" in flags and "A" not in flags:   # SYN without ACK
                f["syn"] += 1
            f["dst_ports"].add(int(p[TCP].dport))
        elif UDP in p:
            f["udp"] += 1
            f["dst_ports"].add(int(p[UDP].dport))

    rows = []
    for src, f in flows.items():
        n = len(f["times"])
        if n < min_packets:
            continue
        t = sorted(f["times"])
        duration = max(t[-1] - t[0], 0.0)
        pps = n / duration if duration > 0 else float(n)
        iats = [(t[i] - t[i - 1]) * 1000.0 for i in range(1, n)]  # ms
        mean_iat = sum(iats) / len(iats) if iats else 0.0
        rows.append({
            "src_ip": src,
            "duration_s": round(duration, 3),
            "pkt_count": n,
            "byte_count": f["bytes"],
            "pkts_per_s": round(pps, 2),
            "syn_ratio": round(f["syn"] / n, 3),
            "udp_ratio": round(f["udp"] / n, 3),
            "unique_dst_ports": len(f["dst_ports"]),
            "mean_iat_ms": round(mean_iat, 3),
            "mean_pkt_size": round(f["bytes"] / n, 1),
        })
    return pd.DataFrame(rows, columns=["src_ip", *FEATURE_COLUMNS])


if __name__ == "__main__":
    df = synthetic_flows(8, seed=1)
    with pd.option_context("display.width", 200, "display.max_columns", 20):
        print(df.to_string(index=False))
