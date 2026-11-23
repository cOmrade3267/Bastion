# Dashboard backend

Minimal Flask service that receives `DetectionEvent`s from the detection
track and stores them in SQLite. Validates every event against the shared
contract (`shared/schema.py`).

## Run

```bash
cd dashboard/backend
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
python app.py            # serves on http://127.0.0.1:5000
```

Events are saved to `dashboard/data/bastion.db` (git-ignored) and survive a
restart. Set `BASTION_DB=/path/to/file.db` to use a different file.

## Tests

```bash
pip install -r requirements-dev.txt
pytest -q
```

## Endpoints

| Method | Path      | Purpose                                              |
|--------|-----------|------------------------------------------------------|
| GET    | `/`       | Serve the live dashboard UI (`dashboard/frontend`)   |
| GET    | `/health` | Liveness + how many events are stored                |
| POST   | `/event`  | Accept one `DetectionEvent` (JSON), validate, store  |
| GET    | `/events` | List stored events, newest last (filters below)      |

### `GET /events` query parameters

| Param          | Meaning                                                     |
|----------------|-------------------------------------------------------------|
| `limit`        | Max events returned, 1-1000 (default 100; keeps the newest) |
| `attack_type`  | `benign`, `dos`, `ddos` or `probe` (InSDN taxonomy)         |
| `action_taken` | `blocked`, `logged` or `none`                               |
| `src_ip`       | Exact source IP                                             |
| `since`        | ISO8601 timestamp, e.g. `2026-11-18T10:00:00Z`              |

Response: `{"count": <returned>, "total": <matching>, "events": [...]}`.
Invalid parameters return 400 with a reason.

## Test it (issue #6 sync)

With the server running, in another terminal:

```bash
python send_test_event.py          # valid event  -> 202 accepted
python send_test_event.py --bad    # invalid event -> 400 with reason
curl -s http://127.0.0.1:5000/events | python -m json.tool
```

Or by hand:

```bash
curl -s -X POST http://127.0.0.1:5000/event \
  -H 'Content-Type: application/json' \
  -d '{"timestamp":"2026-11-18T10:15:30.123Z","src_ip":"10.0.0.5",
       "attack_type":"ddos","confidence":0.94,"action_taken":"blocked"}'
```

## Scope

SQLite storage, `/events` filtering, and the live polling UI (served at `/`)
are in. The `shared/schema.py` contract carries the InSDN taxonomy
(`benign`/`dos`/`ddos`/`probe`); changing it is a joint PR.
