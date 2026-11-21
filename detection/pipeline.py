"""
Bastion — detection pipeline
============================
Ties the detection track together end to end:

    features -> classify -> build DetectionEvent -> (emit to dashboard | print)

Two modes:
  * one-shot (default): process one batch of flows and exit.
  * real-time (--window N): a sliding-window loop that re-captures, classifies
    and emits every N seconds until Ctrl-C (Week-5 wiring). Works today against
    synthetic traffic; point it at a live interface once the lab is up.

Sources: synthetic (no lab needed), pcap <path>, or live <iface> (needs root).
Everything downstream works off FEATURE_COLUMNS, so the source is swappable.

Usage:
    # one-shot
    python pipeline.py --dry-run                      # print events, no network
    python pipeline.py --url http://127.0.0.1:5000    # POST to the dashboard
    python pipeline.py --source pcap --path cap.pcap --url http://127.0.0.1:5000

    # real-time loop (every 5s), synthetic traffic, just print
    python pipeline.py --window 5 --dry-run

    # real-time loop off a live interface, emitting + auto-blocking
    sudo python pipeline.py --source live --interface eth0 --window 5 \
        --url http://127.0.0.1:5000 --mitigate --enforce
"""

from __future__ import annotations

import argparse
import pathlib
import sys
import time

HERE = pathlib.Path(__file__).resolve().parent
REPO_ROOT = HERE.parent
sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(HERE))

from features.extract import (synthetic_flows, extract_from_pcap,  # noqa: E402
                              extract_from_live, FEATURE_COLUMNS)
from models.classify import classify_row  # noqa: E402
from emit.emitter import build_event, post_event  # noqa: E402
from mitigate.blocker import Blocker  # noqa: E402
from shared.schema import ActionTaken  # noqa: E402


def load_flows(args, window_seed):
    """Produce one batch of flows for the current window from the chosen source."""
    if args.source == "synthetic":
        return synthetic_flows(n=args.n, seed=window_seed)
    if args.source == "pcap":
        if not args.path:
            raise SystemExit("--source pcap requires --path <pcap file>")
        return extract_from_pcap(args.path)
    if args.source == "live":
        if not args.interface:
            raise SystemExit("--source live requires --interface <iface>")
        # Sniff for the window length (slightly less than --window to leave room
        # for classify/emit), so captures don't overlap the next window.
        secs = max(1.0, (args.window or 5) * 0.9)
        return extract_from_live(args.interface, seconds=secs)
    raise SystemExit(f"unknown source: {args.source}")


def process_batch(flows, args, blocker, window_idx):
    """Classify one batch, emit/print each event, return (sent, blocked)."""
    sent = blocked = 0
    for _, row in flows.iterrows():
        at, conf = classify_row({c: row[c] for c in FEATURE_COLUMNS})
        src_ip = str(row["src_ip"])
        action = blocker.consider(at, conf, src_ip) if blocker else None
        if action == ActionTaken.BLOCKED:
            blocked += 1
        event = build_event(src_ip=src_ip, attack_type=at, confidence=conf,
                            action_taken=action)
        if args.dry_run:
            truth = f"  (truth={row['label']})" if "label" in row else ""
            prefix = f"[w{window_idx}] " if args.window else ""
            print(prefix + event.to_json() + truth)
        else:
            r = post_event(event, args.url)
            print(f"POST {event.src_ip} {at.value} {event.action_taken.value} "
                  f"-> {r.status_code}")
            if r.status_code != 202:
                print("  rejected:", r.text)
        sent += 1
    return sent, blocked


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--source", choices=["synthetic", "pcap", "live"],
                    default="synthetic")
    ap.add_argument("--path", help="pcap path (with --source pcap)")
    ap.add_argument("--interface", help="network interface (with --source live)")
    ap.add_argument("--n", type=int, default=8, help="synthetic flow count per batch")
    ap.add_argument("--seed", type=int, default=None)
    ap.add_argument("--url", default=None, help="dashboard base URL to POST to")
    ap.add_argument("--dry-run", action="store_true", help="print events, do not POST")
    # --- real-time loop (#W5) ---
    ap.add_argument("--window", type=float, default=None,
                    help="seconds per window; enables the continuous real-time loop")
    ap.add_argument("--max-windows", type=int, default=0,
                    help="stop after N windows (0 = run until Ctrl-C); for tests/CI")
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

    total_sent = total_blocked = 0
    try:
        if args.window:
            # --- real-time sliding-window loop ---
            print(f"[realtime] window={args.window}s source={args.source}"
                  f"{' iface='+args.interface if args.interface else ''}"
                  f"{' (synthetic)' if args.source == 'synthetic' else ''} — Ctrl-C to stop\n")
            w = 0
            while True:
                w += 1
                t0 = time.monotonic()
                # vary the synthetic seed per window so batches differ
                wseed = None if args.seed is None else args.seed + w
                flows = load_flows(args, wseed)
                s, b = process_batch(flows, args, blocker, w)
                total_sent += s
                total_blocked += b
                if blocker:
                    print(f"[w{w}] active blocks: {blocker.active()}")
                if args.max_windows and w >= args.max_windows:
                    break
                # sleep off the remainder of the window (live already spent most of it sniffing)
                if args.source != "live":
                    elapsed = time.monotonic() - t0
                    time.sleep(max(0.0, args.window - elapsed))
        else:
            # --- one-shot ---
            flows = load_flows(args, args.seed)
            total_sent, total_blocked = process_batch(flows, args, blocker, 0)
    except KeyboardInterrupt:
        print("\n[realtime] stopped by user.")
    finally:
        if blocker:
            print(f"\n[mitigate] active blocks: {blocker.active()}")
            blocker.close()

    tail = f", {total_blocked} blocked" if blocker else ""
    print(f"\n{total_sent} events {'printed' if args.dry_run else 'emitted'}{tail}.")


if __name__ == "__main__":
    main()
