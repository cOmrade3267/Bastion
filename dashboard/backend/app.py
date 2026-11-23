"""
Bastion — Dashboard backend
===========================
A small Flask app that receives DetectionEvents from the detection track,
validates them against the shared contract (`shared/schema.py`), and stores
them in SQLite so the UI (later weeks) has something durable to read.

Nothing that violates the contract is stored.

Endpoints
---------
  GET  /         -> serve the live dashboard UI (dashboard/frontend/index.html)
  GET  /health   -> {"status": "ok", "events_stored": N}
  POST /event    -> accept one DetectionEvent (JSON), validate, store
  GET  /events   -> list stored events, newest last. Optional query params:
                      limit        max events returned (default 100, max 1000)
                      attack_type  benign | dos | ddos | probe
                      action_taken blocked | logged | none
                      src_ip       exact source IP
                      since        ISO8601 timestamp, e.g. 2026-11-18T10:00:00Z
                    Response: {"count": returned, "total": matching, "events": [...]}

Storage: SQLite file at dashboard/data/bastion.db (override with the
BASTION_DB environment variable). See storage.py.

Run:
    pip install -r requirements.txt
    python app.py
"""

import ipaddress
import os
import pathlib
import sys

# Make the shared contract importable regardless of where this is launched from.
REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

FRONTEND_DIR = REPO_ROOT / "dashboard" / "frontend"

from flask import Flask, request, jsonify, send_from_directory  # noqa: E402
from shared.schema import DetectionEvent, AttackType, ActionTaken  # noqa: E402
from storage import EventStore, parse_timestamp  # noqa: E402

REQUIRED_FIELDS = {"timestamp", "src_ip", "attack_type", "confidence", "action_taken"}
DEFAULT_LIMIT = 100
MAX_LIMIT = 1000


def parse_event(payload: dict) -> DetectionEvent:
    """Validate a raw dict against the shared contract.

    Raises ValueError on anything the contract rejects: unknown attack_type /
    action_taken, confidence out of [0,1], missing fields, bad types, an
    unparseable timestamp or a src_ip that is not a valid IPv4/IPv6 address.
    """
    if not isinstance(payload, dict):
        raise ValueError("body must be a JSON object")
    missing = REQUIRED_FIELDS - payload.keys()
    if missing:
        raise ValueError(f"missing required fields: {sorted(missing)}")

    timestamp = str(payload["timestamp"])
    parse_timestamp(timestamp)  # raises ValueError if not ISO8601

    # Raises ValueError if not an IP. Stored in canonical form so that filtering
    # by src_ip matches regardless of how an emitter wrote an IPv6 address.
    src_ip = str(ipaddress.ip_address(str(payload["src_ip"]).strip()))

    return DetectionEvent(
        timestamp=timestamp,
        src_ip=src_ip,
        attack_type=AttackType(payload["attack_type"]),   # raises on unknown value
        confidence=float(payload["confidence"]),           # raises on non-number
        action_taken=ActionTaken(payload["action_taken"]),  # raises on unknown value
    )


def create_app(db_path=None) -> Flask:
    app = Flask(__name__)
    store = EventStore(db_path or os.environ.get("BASTION_DB"))
    app.config["STORE"] = store

    @app.get("/")
    def index():
        """Serve the live dashboard UI, which polls /events."""
        return send_from_directory(FRONTEND_DIR, "index.html")

    @app.get("/health")
    def health():
        return jsonify(status="ok", events_stored=store.count())

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
        store.add(stored)
        print(f"[event] {event.src_ip} {event.attack_type.value} "
              f"conf={event.confidence:.2f} action={event.action_taken.value}")
        return jsonify(status="accepted", stored=stored), 202

    @app.get("/events")
    def list_events():
        args = request.args

        try:
            limit = int(args.get("limit", DEFAULT_LIMIT))
        except ValueError:
            return jsonify(error="limit must be an integer"), 400
        if not 1 <= limit <= MAX_LIMIT:
            return jsonify(error=f"limit must be between 1 and {MAX_LIMIT}"), 400

        filters = {}
        if "attack_type" in args:
            try:
                filters["attack_type"] = AttackType(args["attack_type"]).value
            except ValueError:
                return jsonify(error=f"unknown attack_type: {args['attack_type']!r}"), 400
        if "action_taken" in args:
            try:
                filters["action_taken"] = ActionTaken(args["action_taken"]).value
            except ValueError:
                return jsonify(error=f"unknown action_taken: {args['action_taken']!r}"), 400
        if "src_ip" in args:
            try:
                filters["src_ip"] = str(ipaddress.ip_address(args["src_ip"].strip()))
            except ValueError:
                return jsonify(error=f"invalid src_ip: {args['src_ip']!r}"), 400
        if "since" in args:
            try:
                filters["since"] = parse_timestamp(args["since"])
            except ValueError as e:
                return jsonify(error=str(e)), 400

        events = store.list(limit=limit, **filters)
        return jsonify(count=len(events), total=store.count(**filters), events=events)

    return app


if __name__ == "__main__":
    # host=127.0.0.1 keeps it local; detection posts over the lab network later.
    create_app().run(host="127.0.0.1", port=5000, debug=True)
