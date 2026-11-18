# Dashboard backend

Minimal Flask service that receives `DetectionEvent`s from the detection
track and holds them in memory. Validates every event against the shared
contract (`shared/schema.py`).

## Run

```bash
cd dashboard/backend
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
python app.py            # serves on http://127.0.0.1:5000
```

## Endpoints

| Method | Path      | Purpose                                              |
|--------|-----------|------------------------------------------------------|
| GET    | `/health` | Liveness + how many events are stored                |
| POST   | `/event`  | Accept one `DetectionEvent` (JSON), validate, store  |
| GET    | `/events` | List stored events (in-memory, newest last)          |

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
       "attack_type":"syn_flood","confidence":0.94,"action_taken":"blocked"}'
```

## Scope

Week 2 skeleton: **in-memory only, no database**. A real datastore and the
live UI feed arrive in Weeks 4–5 (see `docs/PROJECT_PLAN.md`). The
`shared/schema.py` contract is frozen — changing it is a joint PR.
