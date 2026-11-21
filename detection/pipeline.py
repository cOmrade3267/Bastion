"""
Bastion — detection pipeline (Week 2 skeleton)
==============================================
Ties the detection track together end to end:

    features -> classify -> build DetectionEvent -> (emit to dashboard | print)

Runs today with synthetic flows (no VM lab needed). Swap `--source pcap
<path>` once real captures exist (#1/#4) — the rest of the pipeline is
unchanged because everything downstream works off FEATURE_COLUMNS.

Usage:
    python pipeline.py --dry-run            # print events, no network
    python pipeline.py --url http://127.0.0.1:5000   # POST to the dashboard
    python pipeline.py --source pcap capture.pcap --url http://127.0.0.1:5000
"""

from __future__ import annotations

import argparse
import pathlib
import sys

HERE = pathlib.Path(__file__).resolve().parent
REPO_ROOT = HERE.parent
sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(HERE))

from features.extract import synthetic_flows, extract_from_pcap, FEATURE_COLUMNS  # noqa: E402
from models.classify import classify_row  # noqa: E402
from emit.emitter import build_event, post_event  # noqa: E402


def load_flows(source: str, path: str | None, n: int, seed: int | None):
    if source == "synthetic":
        return synthetic_flows(n=n, seed=seed)
    if source == "pcap":
        if not path:
            raise SystemExit("--source pcap requires a pcap file path")
        return extract_from_pcap(path)
    raise SystemExit(f"unknown source: {source}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--source", choices=["synthetic", "pcap"], default="synthetic")
    ap.add_argument("--path", help="pcap path (with --source pcap)")
    ap.add_argument("--n", type=int, default=8, help="synthetic flow count")
    ap.add_argument("--seed", type=int, default=None)
    ap.add_argument("--url", default=None, help="dashboard base URL to POST to")
    ap.add_argument("--dry-run", action="store_true", help="print events, do not POST")
    args = ap.parse_args()

    if not args.dry_run and not args.url:
        ap.error("pass --url <dashboard> to emit, or --dry-run to just print")

    flows = load_flows(args.source, args.path, args.n, args.seed)
    sent = 0
    for _, row in flows.iterrows():
        at, conf = classify_row({c: row[c] for c in FEATURE_COLUMNS})
        event = build_event(src_ip=str(row["src_ip"]), attack_type=at, confidence=conf)
        if args.dry_run:
            truth = f"  (truth={row['label']})" if "label" in row else ""
            print(event.to_json() + truth)
        else:
            r = post_event(event, args.url)
            print(f"POST {event.src_ip} {at.value} -> {r.status_code}")
            if r.status_code != 202:
                print("  rejected:", r.text)
        sent += 1
    print(f"\n{sent} events {'printed' if args.dry_run else 'emitted'}.")


if __name__ == "__main__":
    main()
