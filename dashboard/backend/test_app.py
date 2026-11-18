"""Tests for the dashboard backend. Run from dashboard/backend:  pytest -q"""

import pytest

from app import create_app


@pytest.fixture()
def client(tmp_path):
    app = create_app(tmp_path / "test.db")
    app.config["TESTING"] = True
    return app.test_client()


def make_event(**overrides):
    ev = {
        "timestamp": "2026-11-18T10:15:30.123Z",
        "src_ip": "10.0.0.5",
        "attack_type": "syn_flood",
        "confidence": 0.94,
        "action_taken": "blocked",
    }
    ev.update(overrides)
    return ev


def post(client, **overrides):
    return client.post("/event", json=make_event(**overrides))


def test_health_starts_empty(client):
    r = client.get("/health")
    assert r.status_code == 200
    assert r.get_json() == {"status": "ok", "events_stored": 0}


def test_valid_event_accepted_and_stored(client):
    r = post(client)
    assert r.status_code == 202
    assert r.get_json()["stored"]["attack_type"] == "syn_flood"
    body = client.get("/events").get_json()
    assert body["count"] == 1 and body["total"] == 1
    assert body["events"][0]["src_ip"] == "10.0.0.5"


def test_events_survive_restart(tmp_path):
    db = tmp_path / "persist.db"
    first = create_app(db).test_client()
    assert first.post("/event", json=make_event()).status_code == 202
    second = create_app(db).test_client()  # new app, same file
    assert second.get("/health").get_json()["events_stored"] == 1


@pytest.mark.parametrize(
    "overrides",
    [
        {"attack_type": "teardrop"},
        {"action_taken": "exploded"},
        {"confidence": 1.7},
        {"confidence": "high"},
        {"src_ip": "not-an-ip"},
        {"src_ip": "999.1.1.1"},
        {"timestamp": "yesterday"},
    ],
)
def test_invalid_events_rejected_and_not_stored(client, overrides):
    assert post(client, **overrides).status_code == 400
    assert client.get("/health").get_json()["events_stored"] == 0


def test_missing_field_and_bad_body_rejected(client):
    bad = make_event()
    del bad["confidence"]
    assert client.post("/event", json=bad).status_code == 400
    assert client.post("/event", data="{not json").status_code == 400
    assert client.post("/event", json=[1, 2]).status_code == 400


def test_ipv6_is_canonicalised_for_filtering(client):
    post(client, src_ip="0:0:0:0:0:0:0:1")
    r = client.get("/events?src_ip=::1")
    assert r.get_json()["count"] == 1


def test_list_is_newest_last_and_limit_keeps_most_recent(client):
    for i in range(5):
        post(client, timestamp=f"2026-11-18T10:00:0{i}Z", src_ip=f"10.0.0.{i + 1}")
    ips = [e["src_ip"] for e in client.get("/events").get_json()["events"]]
    assert ips == [f"10.0.0.{i}" for i in range(1, 6)]

    body = client.get("/events?limit=2").get_json()
    assert body["count"] == 2 and body["total"] == 5
    assert [e["src_ip"] for e in body["events"]] == ["10.0.0.4", "10.0.0.5"]


def test_ordering_uses_real_time_not_string_format(client):
    # Same instant-order, different string formats: "...:00Z" vs "...:00.500+00:00"
    post(client, timestamp="2026-11-18T10:00:00.500+00:00", src_ip="10.0.0.2")
    post(client, timestamp="2026-11-18T10:00:00Z", src_ip="10.0.0.1")
    ips = [e["src_ip"] for e in client.get("/events").get_json()["events"]]
    assert ips == ["10.0.0.1", "10.0.0.2"]


def test_filters(client):
    post(client, attack_type="syn_flood", action_taken="blocked", src_ip="10.0.0.1")
    post(client, attack_type="udp_flood", action_taken="logged", src_ip="10.0.0.2")
    post(client, attack_type="benign", action_taken="none", src_ip="10.0.0.3")

    def ips(query):
        return [e["src_ip"] for e in client.get(f"/events?{query}").get_json()["events"]]

    assert ips("attack_type=udp_flood") == ["10.0.0.2"]
    assert ips("action_taken=blocked") == ["10.0.0.1"]
    assert ips("src_ip=10.0.0.3") == ["10.0.0.3"]
    assert ips("attack_type=syn_flood&action_taken=logged") == []


def test_since_filter(client):
    post(client, timestamp="2026-11-18T09:00:00Z", src_ip="10.0.0.1")
    post(client, timestamp="2026-11-18T11:00:00Z", src_ip="10.0.0.2")
    r = client.get("/events?since=2026-11-18T10:00:00Z").get_json()
    assert [e["src_ip"] for e in r["events"]] == ["10.0.0.2"]


@pytest.mark.parametrize(
    "query",
    [
        "limit=abc",
        "limit=0",
        "limit=5000",
        "attack_type=teardrop",
        "action_taken=exploded",
        "src_ip=nope",
        "since=yesterday",
    ],
)
def test_bad_query_params_rejected(client, query):
    assert client.get(f"/events?{query}").status_code == 400


def test_sql_injection_attempt_is_inert(client):
    post(client)
    r = client.get("/events?src_ip=10.0.0.5' OR '1'='1")
    assert r.status_code == 400
    assert client.get("/health").get_json()["events_stored"] == 1
