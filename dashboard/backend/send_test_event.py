"""
Send a hand-crafted DetectionEvent to the dashboard backend.

This is the Week 2 sync test (issue #6): it stands in for the detection track
until the real emitter exists, and lets either person confirm the /event
endpoint accepts a contract-valid event.

Usage:
    python send_test_event.py                 # sends one valid sample event
    python send_test_event.py --bad           # sends an invalid event (expect 400)
    python send_test_event.py --url http://127.0.0.1:5000
"""

import argparse
import sys
import pathlib

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT))

import requests  # noqa: E402
from shared.schema import DetectionEvent, AttackType, ActionTaken  # noqa: E402


def sample_event() -> dict:
    ev = DetectionEvent(
        timestamp=DetectionEvent.now_iso(),
        src_ip="10.0.0.5",
        attack_type=AttackType.SYN_FLOOD,
        confidence=0.94,
        action_taken=ActionTaken.BLOCKED,
    )
    import json
    return json.loads(ev.to_json())


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--url", default="http://127.0.0.1:5000")
    ap.add_argument("--bad", action="store_true",
                    help="send a contract-violating event to check validation")
    args = ap.parse_args()

    if args.bad:
        payload = {
            "timestamp": DetectionEvent.now_iso(),
            "src_ip": "10.0.0.9",
            "attack_type": "teardrop",   # not in the contract
            "confidence": 1.7,            # out of [0,1]
            "action_taken": "blocked",
        }
    else:
        payload = sample_event()

    resp = requests.post(f"{args.url}/event", json=payload, timeout=5)
    print(f"POST /event -> {resp.status_code}")
    print(resp.json())
    # Non-zero exit on an unexpected result makes this usable in CI later.
    expected = 400 if args.bad else 202
    sys.exit(0 if resp.status_code == expected else 1)


if __name__ == "__main__":
    main()
