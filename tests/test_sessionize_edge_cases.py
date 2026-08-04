"""
Covers sessionize.py behaviors not exercised by public-fixtures.json:
incomplete sessions (no trailing disconnect), a group that doesn't open
with "connect", and empty input. These are real patterns confirmed to
exist in honeypot-replay.jsonl (see decision-log).
"""

from sessionize import sessionize_group


def _ev(event_id, action, seq, schema_version="2", protocol="ssh",
        source_ip="198.51.100.10", destination_port=22, sensor_time="2026-07-01T00:00:00Z"):
    return {
        "event_id": event_id,
        "session_seq": seq,
        "schema_version": schema_version,
        "protocol": protocol,
        "source_ip": source_ip,
        "destination_port": destination_port,
        "sensor_time": sensor_time,
        "action": action,
    }


def test_incomplete_session_no_trailing_disconnect_is_flagged_not_dropped():
    """Confirmed real pattern: S-ed7d82-0062515 in honeypot-replay.jsonl
    ends with connect + client_banner and no disconnect (replay window
    ended mid-session). Must be preserved with incomplete=True, not
    silently discarded and not crashed on."""
    events = [
        _ev("G-0000001-1", "connect", 1),
        _ev("G-0000001-2", "client_banner", 2),
    ]
    sessions = sessionize_group("G-0000001", events)
    assert len(sessions) == 1
    assert sessions[0].incomplete is True
    assert sessions[0].anomaly == "no_disconnect_before_end_of_replay"
    assert sessions[0].event_ids == ["G-0000001-1", "G-0000001-2"]


def test_reconnect_within_one_group_produces_two_sessions():
    """Confirmed by public fixture P-SESSION-01: one canonical group,
    two full connect->...->disconnect cycles = session_count 2."""
    events = [
        _ev("G-0000002-1", "connect", 1),
        _ev("G-0000002-2", "auth_fail", 2),
        _ev("G-0000002-3", "disconnect", 3),
        _ev("G-0000002-4", "connect", 4),
        _ev("G-0000002-5", "auth_fail", 5),
        _ev("G-0000002-6", "disconnect", 6),
    ]
    sessions = sessionize_group("G-0000002", events)
    assert len(sessions) == 2
    assert all(not s.incomplete for s in sessions)
    assert sessions[0].reconnect_index == 0
    assert sessions[1].reconnect_index == 1
    assert sessions[0].event_ids == ["G-0000002-1", "G-0000002-2", "G-0000002-3"]
    assert sessions[1].event_ids == ["G-0000002-4", "G-0000002-5", "G-0000002-6"]


def test_events_out_of_order_get_sorted_by_session_seq_not_input_order():
    """replay-interface.json states events are deliberately unordered
    within 5,000-row blocks -- sessionize_group must not depend on input
    order, only on session_seq."""
    events = [
        _ev("G-0000003-3", "disconnect", 3),
        _ev("G-0000003-1", "connect", 1),
        _ev("G-0000003-2", "client_banner", 2),
    ]
    sessions = sessionize_group("G-0000003", events)
    assert len(sessions) == 1
    assert sessions[0].event_ids == ["G-0000003-1", "G-0000003-2", "G-0000003-3"]


def test_group_not_opening_with_connect_is_flagged_anomaly():
    events = [
        _ev("G-0000004-1", "client_banner", 1),
        _ev("G-0000004-2", "disconnect", 2),
    ]
    sessions = sessionize_group("G-0000004", events)
    assert len(sessions) == 1
    assert sessions[0].anomaly == "session_did_not_open_with_connect"


def test_empty_group_returns_no_sessions():
    sessions = sessionize_group("G-0000005", [])
    assert sessions == []


def test_session_preserves_protocol_and_source_ip_from_first_event():
    events = [
        _ev("G-0000006-1", "connect", 1, protocol="mqtt", source_ip="198.51.100.99", destination_port=1883),
        _ev("G-0000006-2", "disconnect", 2, protocol="mqtt", source_ip="198.51.100.99", destination_port=1883),
    ]
    sessions = sessionize_group("G-0000006", events)
    assert sessions[0].protocol == "mqtt"
    assert sessions[0].source_ip == "198.51.100.99"
    assert sessions[0].destination_port == 1883
