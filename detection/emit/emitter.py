"""
Bastion — detection event emitter
==================================
Builds a contract-valid DetectionEvent from a classification result and sends
it to the dashboard's /event endpoint.

By default `action_taken` is LOGGED for a detected attack and NONE for benign.
When the mitigation layer (Week 6, #16) is active, the pipeline passes the
`action_taken` it decided — BLOCKED when an auto-block rule is in place — so the
event always reflects what actually happened.
"""

from __future__ import annotations

import sys
import pathlib

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT))

from shared.schema import DetectionEvent, AttackType, ActionTaken  # noqa: E402


def build_event(src_ip: str, attack_type: AttackType, confidence: float,
                action_taken: "ActionTaken | None" = None) -> DetectionEvent:
    """Build a contract-valid event.

    `action_taken` defaults to the detect-only policy (LOGGED for an attack,
    NONE for benign). Pass an explicit ActionTaken (e.g. from the Blocker) to
    record a real mitigation decision such as BLOCKED.
    """
    if action_taken is None:
        action_taken = ActionTaken.NONE if attack_type == AttackType.BENIGN else ActionTaken.LOGGED
    return DetectionEvent(
        timestamp=DetectionEvent.now_iso(),
        src_ip=src_ip,
        attack_type=attack_type,
        confidence=confidence,
        action_taken=action_taken,
    )


def post_event(event: DetectionEvent, url: str, timeout: float = 5.0):
    """POST one event to <url>/event. Returns the requests.Response."""
    import requests  # lazy so --dry-run needs no network stack
    return requests.post(f"{url.rstrip('/')}/event", data=event.to_json(),
                         headers={"Content-Type": "application/json"}, timeout=timeout)
