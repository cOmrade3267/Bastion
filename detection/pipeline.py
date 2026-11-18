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
from mitigate.blocker import Blocker  # noqa: E402
from shared.schema import ActionTaken  # noqa: E402


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
    # --- mitigation (#16) ---
    ap.add_argument("--mitigate", action="store_true",
                    help="enable auto-block mitigation (plan mode unless --enforce)")
    ap.add_argument("--enforce", action="store_true",
                    help="actually run firewall commands (needs root); default is plan mode")
    ap.add_argument("--threshold", type=float, default=0.8,
                    help="min confidence to auto-block (else LOGGED)")
    ap.add_argument("--block-seconds", type=int, default=300,
                    help="auto-unblock timeout per IP")
    ap.add_argument("--allow", action="append", default=[],
                    help="IP never to block (repeatable); loopback is always allowed")
    ap.add_argument("--backend", default="auto",
                    choices=["auto", "nftables", "iptables", "log-only"],
                    help="firewall backend for mitigation")
    args = ap.parse_args()

    if not args.dry_run and not args.url:
        ap.error("pass --url <dashboard> to emit, or --dry-run to just print")

    import logging
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

    blocker = None
    if args.mitigate:
        blocker = Blocker(enabled=True, enforce=args.enforce, threshold=args.threshold,
                          block_seconds=args.block_seconds, allow=args.allow,
                          backend=args.backend, sweep=True)
        mode = "ENFORCE (firewall will be modified)" if args.enforce else "PLAN (firewall untouched)"
        print(f"[mitigate] on — backend={blocker.backend.name}, {mode}, "
              f"threshold={args.threshold}, block_seconds={args.block_seconds}\n")

    flows = load_flows(args.source, args.path, args.n, args.seed)
    sent = blocked = 0
    try:
        for _, row in flows.iterrows():
            at, conf = classify_row({c: row[c] for c in FEATURE_COLUMNS})
            src_ip = str(row["src_ip"])
            action = blocker.consider(at, conf, src_ip) if blocker else None
            if action is not None and action == ActionTaken.BLOCKED:
                blocked += 1
            event = build_event(src_ip=src_ip, attack_type=at, confidence=conf,
                                action_taken=action)
            if args.dry_run:
                truth = f"  (truth={row['label']})" if "label" in row else ""
                print(event.to_json() + truth)
            else:
                r = post_event(event, args.url)
                print(f"POST {event.src_ip} {at.value} {event.action_taken.value} -> {r.status_code}")
                if r.status_code != 202:
                    print("  rejected:", r.text)
            sent += 1
    finally:
        if blocker:
            print(f"\n[mitigate] active blocks: {blocker.active()}")
            blocker.close()
    tail = f", {blocked} blocked" if blocker else ""
    print(f"\n{sent} events {'printed' if args.dry_run else 'emitted'}{tail}.")


if __name__ == "__main__":
    main()
