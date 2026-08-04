"""
Malformed-input tests, for "unattended positive, negative, malformed-input, and 
clean-state tests."

Every quarantine path in normalize.py gets an explicit test here, every one of 
these malformed inputs must come back as a labeled quarantine record, never a 
crash and never a silent skip.
"""

from normalize import normalize_event, derive_canonical_session_id


VALID_EVENT = {
    "schema_version": "2",
    "event_id": "S-test01-0000001-1",
    "sensor_time": "2026-07-01T00:00:00Z",
    "protocol": "ssh",
    "source_ip": "198.51.100.10",
    "source_port": 12345,
    "destination_port": 22,
    "connection_id": "S-test01-0000001",
    "action": "connect",
    "username": None,
    "credential_fingerprint": None,
    "command": None,
    "payload_sha256": None,
    "bytes": None,
    "marker": None,
}


def test_valid_event_normalizes_cleanly():
    result = normalize_event(VALID_EVENT.copy(), source_file="test.jsonl", source_line=1)
    assert "quarantine_reason" not in result
    assert result["canonical_session_id"] == "S-test01-0000001"
    assert result["session_seq"] == 1
    assert result["raw_connection_id"] == "S-test01-0000001"


def test_missing_required_field_is_quarantined_not_dropped():
    broken = VALID_EVENT.copy()
    del broken["source_ip"]
    result = normalize_event(broken, source_file="test.jsonl", source_line=2)
    assert "quarantine_reason" in result
    assert "missing_fields" in result["quarantine_reason"]
    assert "source_ip" in result["quarantine_reason"]
    assert result["source_line"] == 2


def test_unknown_schema_version_is_quarantined():
    broken = VALID_EVENT.copy()
    broken["schema_version"] = "99"
    result = normalize_event(broken, source_file="test.jsonl", source_line=3)
    assert "quarantine_reason" in result
    assert "unknown_schema_version" in result["quarantine_reason"]


def test_unknown_action_is_quarantined():
    broken = VALID_EVENT.copy()
    broken["action"] = "teleport"
    result = normalize_event(broken, source_file="test.jsonl", source_line=4)
    assert "quarantine_reason" in result
    assert "unknown_action" in result["quarantine_reason"]


def test_malformed_event_id_is_quarantined():
    broken = VALID_EVENT.copy()
    broken["event_id"] = "not-a-valid-format"  # no numeric suffix
    result = normalize_event(broken, source_file="test.jsonl", source_line=5)
    assert "quarantine_reason" in result
    assert "bad_event_id" in result["quarantine_reason"]


def test_non_numeric_port_is_quarantined_not_crashed():
    broken = VALID_EVENT.copy()
    broken["source_port"] = "not-a-number"
    result = normalize_event(broken, source_file="test.jsonl", source_line=6)
    assert "quarantine_reason" in result
    assert "type_coercion_failed" in result["quarantine_reason"]


def test_already_quarantined_record_from_ingest_passes_through():
    # simulates what ingest.py's parse_json_line returns for invalid JSON
    already_broken = {"quarantine_reason": "invalid_json"}
    result = normalize_event(already_broken, source_file="test.jsonl", source_line=7)
    assert result["quarantine_reason"] == "invalid_json"
    assert result["source_line"] == 7


def test_derive_canonical_session_id_splits_correctly():
    prefix, seq = derive_canonical_session_id("S-ed7d82-0000844-6")
    assert prefix == "S-ed7d82-0000844"
    assert seq == 6


def test_derive_canonical_session_id_rejects_bad_format():
    import pytest
    with pytest.raises(ValueError):
        derive_canonical_session_id("no-numeric-suffix-here")


def test_v1_and_v2_events_in_same_session_get_same_canonical_id():
    """This is the central bug fix (see decision-log D-001): schema v1 and
    v2 events of the same logical session must resolve to the same
    canonical_session_id even though their raw connection_id fields
    differ completely."""
    v1_event = VALID_EVENT.copy()
    v1_event.update({
        "schema_version": "1",
        "event_id": "S-samesession-0000005-2",
        "connection_id": "conn-totally-different-random-string",
        "action": "client_banner",
    })
    v2_event = VALID_EVENT.copy()
    v2_event.update({
        "schema_version": "2",
        "event_id": "S-samesession-0000005-1",
        "connection_id": "S-samesession-0000005",
        "action": "connect",
    })
    r1 = normalize_event(v1_event, source_file="test.jsonl", source_line=8)
    r2 = normalize_event(v2_event, source_file="test.jsonl", source_line=9)
    assert r1["canonical_session_id"] == r2["canonical_session_id"] == "S-samesession-0000005"
    # raw_connection_id must still be PRESERVED, just not used for grouping
    assert r1["raw_connection_id"] == "conn-totally-different-random-string"
    assert r2["raw_connection_id"] == "S-samesession-0000005"
