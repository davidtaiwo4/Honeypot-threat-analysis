"""
Tests the hash ledger builder, specifically the bytes_is_unreliable flag
(the real data-quality finding from the actual replay -- same hash,
inconsistent declared byte size across occurrences) and locator
preservation (every row must carry event_id/source_line back to raw
evidence).
"""

from hash import build_hash_ledger_rows, summarize_hashes
from sessionize import sessionize_group


def _ev(event_id, action, seq, source_ip, payload_sha256=None, bytes_val=None,
        source_line=1, source_file="test.jsonl", sensor_time="2026-07-01T00:00:00Z",
        protocol="ssh", destination_port=22, schema_version="2"):
    return {
        "event_id": event_id, "session_seq": seq, "source_ip": source_ip,
        "action": action, "payload_sha256": payload_sha256, "bytes": bytes_val,
        "source_line": source_line, "source_file": source_file,
        "sensor_time": sensor_time, "protocol": protocol, "destination_port": destination_port,
        "schema_version": schema_version,
    }


def test_consistent_bytes_across_same_hash_is_not_flagged():
    h = "dddd" * 16
    events = [
        _ev("G-1-1", "connect", 1, "203.0.113.1", source_line=1),
        _ev("G-1-2", "payload_download", 2, "203.0.113.1", payload_sha256=h, bytes_val=500, source_line=2),
        _ev("G-1-3", "disconnect", 3, "203.0.113.1", source_line=3),
    ]
    sessions = sessionize_group("G-1", events)
    rows = build_hash_ledger_rows(events, sessions)
    assert len(rows) == 1
    assert rows[0]["bytes_is_unreliable"] is False
    assert rows[0]["note"] == ""


def test_inconsistent_bytes_across_same_hash_is_flagged():
    """Mirrors the real finding: same payload_sha256, different bytes
    values across occurrences -- must be flagged, not silently trusted."""
    h = "eeee" * 16
    group1 = [
        _ev("G-1-1", "connect", 1, "203.0.113.1", source_line=1),
        _ev("G-1-2", "payload_download", 2, "203.0.113.1", payload_sha256=h, bytes_val=500, source_line=2),
        _ev("G-1-3", "disconnect", 3, "203.0.113.1", source_line=3),
    ]
    group2 = [
        _ev("G-2-1", "connect", 1, "203.0.113.2", source_line=4),
        _ev("G-2-2", "payload_download", 2, "203.0.113.2", payload_sha256=h, bytes_val=9999, source_line=5),
        _ev("G-2-3", "disconnect", 3, "203.0.113.2", source_line=6),
    ]
    events = group1 + group2
    sessions = sessionize_group("G-1", group1) + sessionize_group("G-2", group2)
    rows = build_hash_ledger_rows(events, sessions)

    assert len(rows) == 2
    assert all(r["bytes_is_unreliable"] is True for r in rows)
    assert all("do not treat bytes_declared as authoritative" in r["note"] for r in rows)


def test_every_row_preserves_exact_locator():
    h = "ffff" * 16
    events = [
        _ev("G-1-1", "connect", 1, "203.0.113.1", source_line=1),
        _ev("G-1-2", "payload_download", 2, "203.0.113.1", payload_sha256=h,
            bytes_val=500, source_line=42, source_file="honeypot-replay.jsonl"),
        _ev("G-1-3", "disconnect", 3, "203.0.113.1", source_line=3),
    ]
    sessions = sessionize_group("G-1", events)
    rows = build_hash_ledger_rows(events, sessions)

    assert rows[0]["source_line"] == 42
    assert rows[0]["source_file"] == "honeypot-replay.jsonl"
    assert rows[0]["event_id"] == "G-1-2"
    assert rows[0]["session_id"] == sessions[0].session_id
    assert rows[0]["quarantine_status"] == "metadata_only_never_executed"


def test_no_payload_events_produces_empty_ledger():
    events = [
        _ev("G-1-1", "connect", 1, "203.0.113.1", source_line=1),
        _ev("G-1-2", "disconnect", 2, "203.0.113.1", source_line=2),
    ]
    sessions = sessionize_group("G-1", events)
    rows = build_hash_ledger_rows(events, sessions)
    assert rows == []


def test_summarize_hashes_aggregates_correctly():
    h = "1234" * 16
    events = [
        _ev("G-1-1", "connect", 1, "203.0.113.1", source_line=1, sensor_time="2026-07-01T00:00:00Z"),
        _ev("G-1-2", "payload_download", 2, "203.0.113.1", payload_sha256=h, bytes_val=500,
            source_line=2, sensor_time="2026-07-01T00:00:01Z"),
        _ev("G-1-3", "disconnect", 3, "203.0.113.1", source_line=3, sensor_time="2026-07-01T00:00:02Z"),
    ]
    sessions = sessionize_group("G-1", events)
    rows = build_hash_ledger_rows(events, sessions)
    summary = summarize_hashes(rows)

    assert len(summary) == 1
    assert summary[0]["occurrence_count"] == 1
    assert summary[0]["distinct_source_ips"] == 1
    assert summary[0]["bytes_field_reliable"] is True
