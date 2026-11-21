"""
Bastion — detection event emitter
==================================
Builds a contract-valid DetectionEvent from a classification result and sends
it to the dashboard's /event endpoint.

`action_taken` is LOGGED for a detected attack and NONE for benign — real
auto-blocking (BLOCKED) arrives with mitigation in Week 6 (#16).
"""

from __future__ import annotations

import sys
import pathlib

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT))

from shared.schema import DetectionEvent, AttackType, ActionTaken  # noqa: E402


def build_event(src_ip: str, attack_type: AttackType, confidence: float) -> DetectionEvent:
    action = ActionTaken.NONE if attack_type == AttackType.BENIGN else ActionTaken.LOGGED
    return DetectionEvent(
        timestamp=DetectionEvent.now_iso(),
        src_ip=src_ip,
        attack_type=attack_type,
        confidence=confidence,
        action_taken=action,
    )


def post_event(event: DetectionEvent, url: str, timeout: float = 5.0):
    """POST one event to <url>/event. Returns the requests.Response."""
    import requests  # lazy so --dry-run needs no network stack
    return requests.post(f"{url.rstrip('/')}/event", data=event.to_json(),
                         headers={"Content-Type": "application/json"}, timeout=timeout)
