"""
Bastion — synthetic pcap generator (TEST FIXTURE, not real capture)
===================================================================
Crafts a small labeled pcap containing one source per attack class, so the
real pcap feature extractor (features/extract.py :: extract_from_pcap) can be
exercised without the VM lab. Scapy writes pcaps without root.

This is for development/testing only — real captures come from the monitor VM
(see capture.py / README.md).

    python synth_pcap.py --out /tmp/bastion_synth.pcap
    python ../pipeline.py --source pcap --path /tmp/bastion_synth.pcap --dry-run
"""

from __future__ import annotations

import argparse
import random

VICTIM = "10.0.0.1"


def _syn_flood(src, base, n=2000, rate=4000.0):
    from scapy.all import Ether, IP, TCP
    dt, out = 1.0 / rate, []
    for i in range(n):
        p = Ether() / IP(src=src, dst=VICTIM) / TCP(
            sport=random.randint(1024, 65535), dport=80, flags="S")
        p.time = base + i * dt
        out.append(p)
    return out


def _udp_flood(src, base, n=1500, rate=4000.0):
    from scapy.all import Ether, IP, UDP, Raw
    dt, out = 1.0 / rate, []
    for i in range(n):
        p = Ether() / IP(src=src, dst=VICTIM) / UDP(
            sport=random.randint(1024, 65535), dport=53) / Raw(b"\x00" * 512)
        p.time = base + i * dt
        out.append(p)
    return out


def _slowloris(src, base, n=15, gap=8.0):
    """Low-and-slow: one SYN, then trickled partial requests, long gaps."""
    from scapy.all import Ether, IP, TCP, Raw
    out = []
    p0 = Ether() / IP(src=src, dst=VICTIM) / TCP(sport=44000, dport=80, flags="S")
    p0.time = base
    out.append(p0)
    for i in range(1, n):
        p = Ether() / IP(src=src, dst=VICTIM) / TCP(
            sport=44000, dport=80, flags="PA") / Raw(b"X-a: b\r\n")
        p.time = base + i * gap
        out.append(p)
    return out


def _benign(src, base, n=120, rate=40.0):
    """Mixed, moderate-rate normal traffic across a few services."""
    from scapy.all import Ether, IP, TCP, UDP, Raw
    dt, out = 1.0 / rate, []
    ports = [80, 443, 22, 53]
    for i in range(n):
        base_pkt = Ether() / IP(src=src, dst=VICTIM)
        if random.random() < 0.3:
            p = base_pkt / UDP(sport=random.randint(1024, 65535), dport=53) / Raw(b"\x00" * 64)
        else:
            p = base_pkt / TCP(sport=random.randint(1024, 65535),
                               dport=random.choice(ports), flags="PA") / Raw(b"\x00" * random.randint(200, 800))
        p.time = base + i * dt + random.uniform(0, dt)
        out.append(p)
    return out


def build(seed: int = 7):
    from scapy.all import wrpcap  # noqa: F401  (import check only)
    random.seed(seed)
    base = 1_700_000_000.0
    pkts = []
    pkts += _syn_flood("10.0.0.5", base)
    pkts += _udp_flood("10.0.0.6", base)
    pkts += _slowloris("10.0.0.7", base)
    pkts += _benign("10.0.0.8", base)
    pkts.sort(key=lambda p: p.time)
    return pkts


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default="/tmp/bastion_synth.pcap")
    ap.add_argument("--seed", type=int, default=7)
    args = ap.parse_args()
    from scapy.all import wrpcap
    pkts = build(args.seed)
    wrpcap(args.out, pkts)
    print(f"wrote {len(pkts)} packets -> {args.out}")
    print("sources: 10.0.0.5 syn_flood, 10.0.0.6 udp_flood, "
          "10.0.0.7 slowloris, 10.0.0.8 benign")


if __name__ == "__main__":
    main()
