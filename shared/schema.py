"""
Bastion — shared event schema
==============================
This is the CONTRACT between the detection track and the dashboard track.

Detection emits events in this exact shape.
Dashboard consumes events in this exact shape.

Any change to this file must be a joint PR reviewed by both people.
Do not extend this schema unilaterally mid-sprint (see Week 7 note in
docs/PROJECT_PLAN.md re: adding SHAP explanation fields).
"""

from dataclasses import dataclass, asdict
from enum import Enum
from datetime import datetime, timezone
import json


class AttackType(str, Enum):
    SYN_FLOOD = "syn_flood"
    UDP_FLOOD = "udp_flood"
    SLOWLORIS = "slowloris"
    BENIGN = "benign"


class ActionTaken(str, Enum):
    BLOCKED = "blocked"
    LOGGED = "logged"
    NONE = "none"


@dataclass
class DetectionEvent:
    timestamp: str          # ISO8601, e.g. 2026-08-19T10:15:30.123Z
    src_ip: str
    attack_type: AttackType
    confidence: float        # 0.0 - 1.0
    action_taken: ActionTaken

    def __post_init__(self):
        if not (0.0 <= self.confidence <= 1.0):
            raise ValueError(f"confidence must be in [0,1], got {self.confidence}")

    def to_json(self) -> str:
        d = asdict(self)
        d["attack_type"] = self.attack_type.value
        d["action_taken"] = self.action_taken.value
        return json.dumps(d)

    @staticmethod
    def now_iso() -> str:
        return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


# --- Example usage (both sides should be able to run this file standalone) ---
if __name__ == "__main__":
    ev = DetectionEvent(
        timestamp=DetectionEvent.now_iso(),
        src_ip="10.0.0.5",
        attack_type=AttackType.SYN_FLOOD,
        confidence=0.94,
        action_taken=ActionTaken.BLOCKED,
    )
    print(ev.to_json())
