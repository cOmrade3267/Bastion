"""
Bastion — Dashboard backend (Week 2 skeleton)
=============================================
A minimal Flask app that receives DetectionEvents from the detection track
and keeps them in memory so the UI (later weeks) has something to read.

It validates every incoming event against the shared contract
(`shared/schema.py`) — nothing that violates the contract is stored.

Endpoints
---------
  GET  /health   -> {"status": "ok", "events_stored": N}
  POST /event    -> accept one DetectionEvent (JSON), validate, store, print
  GET  /events   -> list stored events (in-memory, newest last)

Scope note: in-memory storage only. A real datastore + live UI feed come in
Weeks 4-5 (see docs/PROJECT_PLAN.md). Do not add a database here yet.

Run:
    pip install -r requirements.txt
    python app.py
"""

import sys
import pathlib

# Make the shared contract importable regardless of where this is launched from.
REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT))

from flask import Flask, request, jsonify, send_from_directory  # noqa: E402
from shared.schema import DetectionEvent, AttackType, ActionTaken  # noqa: E402

FRONTEND_DIR = REPO_ROOT / "dashboard" / "frontend"

app = Flask(__name__)

# In-memory store for Week 2. Replaced by a real feed in Weeks 4-5.
EVENTS: list[dict] = []

REQUIRED_FIELDS = {"timestamp", "src_ip", "attack_type", "confidence", "action_taken"}


def parse_event(payload: dict) -> DetectionEvent:
    """Validate a raw dict against the shared contract.

    Raises ValueError on anything the contract rejects: unknown attack_type /
    action_taken, confidence out of [0,1], missing fields, bad types.
    """
    if not isinstance(payload, dict):
        raise ValueError("body must be a JSON object")
    missing = REQUIRED_FIELDS - payload.keys()
    if missing:
        raise ValueError(f"missing required fields: {sorted(missing)}")
    return DetectionEvent(
        timestamp=str(payload["timestamp"]),
        src_ip=str(payload["src_ip"]),
        attack_type=AttackType(payload["attack_type"]),   # raises on unknown value
        confidence=float(payload["confidence"]),           # raises on non-number
        action_taken=ActionTaken(payload["action_taken"]),  # raises on unknown value
    )


@app.get("/")
def index():
    """Serve the live dashboard UI."""
    return send_from_directory(FRONTEND_DIR, "index.html")


@app.get("/health")
def health():
    return jsonify(status="ok", events_stored=len(EVENTS))


@app.post("/event")
def receive_event():
    try:
        payload = request.get_json(force=True, silent=False)
    except Exception:
        return jsonify(error="body is not valid JSON"), 400

    try:
        event = parse_event(payload)
    except ValueError as e:
        return jsonify(error=str(e)), 400

    stored = {
        "timestamp": event.timestamp,
        "src_ip": event.src_ip,
        "attack_type": event.attack_type.value,
        "confidence": event.confidence,
        "action_taken": event.action_taken.value,
    }
    EVENTS.append(stored)
    print(f"[event] {event.src_ip} {event.attack_type.value} "
          f"conf={event.confidence:.2f} action={event.action_taken.value}")
    return jsonify(status="accepted", stored=stored), 202


@app.get("/events")
def list_events():
    return jsonify(count=len(EVENTS), events=EVENTS)


if __name__ == "__main__":
    # host=127.0.0.1 keeps it local; detection posts over the lab network later.
    app.run(host="127.0.0.1", port=5000, debug=True)
