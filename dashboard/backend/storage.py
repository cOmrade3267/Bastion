"""
Bastion — Dashboard event storage (SQLite)
==========================================
Persists validated DetectionEvents so they survive a server restart.

Uses only the standard library (`sqlite3`) — no new dependency.

Design notes
------------
* One short-lived connection per call. Flask can serve requests from several
  threads, and SQLite connections must not be shared across threads by default.
* `ts_epoch` is the event timestamp parsed to UTC epoch seconds. Sorting and
  `since` filtering use it, so they stay correct even if two emitters format
  the ISO8601 string slightly differently (with/without milliseconds, "Z" vs
  "+00:00"). The original `timestamp` string is stored untouched.
* All SQL is parameterised. Filter values from the query string are never
  formatted into SQL text.
"""

import pathlib
import sqlite3
from contextlib import closing
from datetime import datetime, timezone

DEFAULT_DB_PATH = pathlib.Path(__file__).resolve().parents[1] / "data" / "bastion.db"

SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp    TEXT    NOT NULL,
    ts_epoch     REAL    NOT NULL,
    src_ip       TEXT    NOT NULL,
    attack_type  TEXT    NOT NULL,
    confidence   REAL    NOT NULL,
    action_taken TEXT    NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_events_ts      ON events (ts_epoch);
CREATE INDEX IF NOT EXISTS idx_events_attack  ON events (attack_type);
CREATE INDEX IF NOT EXISTS idx_events_src_ip  ON events (src_ip);
"""

FIELDS = ("timestamp", "src_ip", "attack_type", "confidence", "action_taken")


def parse_timestamp(value: str) -> datetime:
    """Parse an ISO8601 string into an aware UTC datetime.

    Accepts a trailing "Z". A timestamp with no timezone is treated as UTC.
    Raises ValueError if it cannot be parsed.
    """
    if not isinstance(value, str):
        raise ValueError("timestamp must be a string")
    text = value.strip()
    if text.endswith(("Z", "z")):
        text = text[:-1] + "+00:00"
    try:
        dt = datetime.fromisoformat(text)
    except ValueError:
        raise ValueError(f"timestamp is not valid ISO8601: {value!r}") from None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


class EventStore:
    def __init__(self, db_path=None):
        self.db_path = pathlib.Path(db_path) if db_path else DEFAULT_DB_PATH
        # Note: ":memory:" would NOT work here, because each call opens a new
        # connection and every connection would get its own empty database.
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.db_path), timeout=5)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self) -> None:
        with closing(self._connect()) as conn, conn:
            conn.executescript(SCHEMA)

    def add(self, event: dict) -> int:
        """Store one already-validated event dict. Returns its row id."""
        epoch = parse_timestamp(event["timestamp"]).timestamp()
        with closing(self._connect()) as conn, conn:
            cur = conn.execute(
                "INSERT INTO events "
                "(timestamp, ts_epoch, src_ip, attack_type, confidence, action_taken) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (
                    event["timestamp"],
                    epoch,
                    event["src_ip"],
                    event["attack_type"],
                    event["confidence"],
                    event["action_taken"],
                ),
            )
            return cur.lastrowid

    @staticmethod
    def _where(attack_type=None, action_taken=None, src_ip=None, since=None):
        clauses, params = [], []
        if attack_type:
            clauses.append("attack_type = ?")
            params.append(attack_type)
        if action_taken:
            clauses.append("action_taken = ?")
            params.append(action_taken)
        if src_ip:
            clauses.append("src_ip = ?")
            params.append(src_ip)
        if since is not None:
            clauses.append("ts_epoch >= ?")
            params.append(since.timestamp())
        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        return where, params

    def count(self, **filters) -> int:
        where, params = self._where(**filters)
        with closing(self._connect()) as conn:
            return conn.execute(
                f"SELECT COUNT(*) FROM events {where}", params
            ).fetchone()[0]

    def list(self, limit: int = 100, **filters) -> list:
        """Return up to `limit` of the most recent matching events, newest last
        (the same ordering the in-memory skeleton used)."""
        where, params = self._where(**filters)
        with closing(self._connect()) as conn:
            rows = conn.execute(
                f"SELECT {', '.join(FIELDS)} FROM events {where} "
                "ORDER BY ts_epoch DESC, id DESC LIMIT ?",
                [*params, limit],
            ).fetchall()
        return [dict(r) for r in reversed(rows)]
