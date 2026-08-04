"""
Tests each of the three cluster categories cluster.py can produce, using
small synthetic inputs (not the full replay) so these run fast and make
the expected behavior explicit and auditable.
"""

from sessionize import sessionize_group
from cluster import cluster_sessions


def _ev(event_id, action, seq, source_ip, protocol="ssh", destination_port=22,
        payload_sha256=None, credential_fingerprint=None, sensor_time="2026-07-01T00:00:00Z"):
    return {
        "event_id": event_id,
        "session_seq": seq,
        "schema_version": "2",
        "protocol": protocol,
        "source_ip": source_ip,
        "destination_port": destination_port,
        "sensor_time": sensor_time,
        "action": action,
        "payload_sha256": payload_sha256,
        "credential_fingerprint": credential_fingerprint,
    }


def _sessions_for(events_by_group):
    sessions = []
    for group_id, events in events_by_group.items():
        sessions.extend(sessionize_group(group_id, events))
    return sessions


def test_two_ips_sharing_payload_hash_form_one_high_confidence_cluster():
    shared_hash = "aaaa" * 16
    events_by_group = {
        "G-1": [
            _ev("G-1-1", "connect", 1, "203.0.113.1"),
            _ev("G-1-2", "payload_download", 2, "203.0.113.1", payload_sha256=shared_hash),
            _ev("G-1-3", "disconnect", 3, "203.0.113.1"),
        ],
        "G-2": [
            _ev("G-2-1", "connect", 1, "203.0.113.2"),
            _ev("G-2-2", "payload_download", 2, "203.0.113.2", payload_sha256=shared_hash),
            _ev("G-2-3", "disconnect", 3, "203.0.113.2"),
        ],
    }
    normalized = [e for evs in events_by_group.values() for e in evs]
    sessions = _sessions_for(events_by_group)

    clusters = cluster_sessions(normalized, sessions)
    payload_clusters = [c for c in clusters if c.evidence_type == "shared_payload_hash"]
    assert len(payload_clusters) == 1
    assert set(payload_clusters[0].member_source_ips) == {"203.0.113.1", "203.0.113.2"}
    assert payload_clusters[0].confidence == "high"
    assert payload_clusters[0].shared_payload_hashes == [shared_hash]


def test_ip_with_no_auth_and_no_payload_is_reconnaissance_only():
    events_by_group = {
        "G-3": [
            _ev("G-3-1", "connect", 1, "203.0.113.99"),
            _ev("G-3-2", "client_banner", 2, "203.0.113.99"),
            _ev("G-3-3", "disconnect", 3, "203.0.113.99"),
        ],
    }
    normalized = events_by_group["G-3"]
    sessions = _sessions_for(events_by_group)

    clusters = cluster_sessions(normalized, sessions)
    recon = [c for c in clusters if c.evidence_type == "reconnaissance_only"]
    assert len(recon) == 1
    assert recon[0].member_source_ips == ["203.0.113.99"]
    assert recon[0].confidence == "low"


def test_ip_with_auth_attempt_but_no_payload_is_background_unclustered():
    events_by_group = {
        "G-4": [
            _ev("G-4-1", "connect", 1, "203.0.113.50"),
            _ev("G-4-2", "auth_fail", 2, "203.0.113.50", credential_fingerprint="widelyusedcred"),
            _ev("G-4-3", "disconnect", 3, "203.0.113.50"),
        ],
    }
    normalized = events_by_group["G-4"]
    sessions = _sessions_for(events_by_group)

    clusters = cluster_sessions(normalized, sessions)
    background = [c for c in clusters if c.evidence_type == "unclustered"]
    assert len(background) == 1
    assert background[0].member_source_ips == ["203.0.113.50"]
    assert background[0].confidence == "low"


def test_every_session_is_accounted_for_exactly_once():
    """No session should be lost or double-counted across cluster
    categories -- this mirrors the real-data sanity check (293 + 644 +
    61578 = 62515) at small scale."""
    shared_hash = "bbbb" * 16
    events_by_group = {
        "G-5": [_ev("G-5-1", "connect", 1, "203.0.113.1"),
                _ev("G-5-2", "payload_download", 2, "203.0.113.1", payload_sha256=shared_hash),
                _ev("G-5-3", "disconnect", 3, "203.0.113.1")],
        "G-6": [_ev("G-6-1", "connect", 1, "203.0.113.2"),
                _ev("G-6-2", "payload_download", 2, "203.0.113.2", payload_sha256=shared_hash),
                _ev("G-6-3", "disconnect", 3, "203.0.113.2")],
        "G-7": [_ev("G-7-1", "connect", 1, "192.0.2.1"),
                _ev("G-7-2", "client_banner", 2, "192.0.2.1"),
                _ev("G-7-3", "disconnect", 3, "192.0.2.1")],
        "G-8": [_ev("G-8-1", "connect", 1, "203.0.113.77"),
                _ev("G-8-2", "auth_fail", 2, "203.0.113.77", credential_fingerprint="x"),
                _ev("G-8-3", "disconnect", 3, "203.0.113.77")],
    }
    normalized = [e for evs in events_by_group.values() for e in evs]
    sessions = _sessions_for(events_by_group)
    total_sessions = len(sessions)

    clusters = cluster_sessions(normalized, sessions)
    all_session_ids = [sid for c in clusters for sid in c.session_ids]
    assert len(all_session_ids) == total_sessions
    assert len(set(all_session_ids)) == total_sessions  # no duplicates


def test_clustering_is_deterministic_across_reruns():
    shared_hash = "cccc" * 16
    events_by_group = {
        "G-9": [_ev("G-9-1", "connect", 1, "203.0.113.5"),
                _ev("G-9-2", "payload_download", 2, "203.0.113.5", payload_sha256=shared_hash),
                _ev("G-9-3", "disconnect", 3, "203.0.113.5")],
    }
    normalized = events_by_group["G-9"]
    sessions = _sessions_for(events_by_group)

    result1 = cluster_sessions(normalized, sessions)
    result2 = cluster_sessions(normalized, sessions)
    assert [c.cluster_id for c in result1] == [c.cluster_id for c in result2]
    assert [c.member_source_ips for c in result1] == [c.member_source_ips for c in result2]
