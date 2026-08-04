"""
Groups normalized events (from normalize.py) into sessions.

Two-level grouping, because a single canonical_session_id group can contain
MORE THAN ONE logical session (a reconnect: connect -> ... -> disconnect ->
connect -> ... -> disconnect, all sharing one event_id prefix). Confirmed by
public-fixtures.json case P-SESSION-01: 6 events, 1 canonical group,
session_count=2.
"""

from dataclasses import dataclass, field
from typing import Optional


@dataclass
class Session:
    session_id: str                 # canonical_session_id, suffixed with -N if split by reconnect
    canonical_group_id: str
    reconnect_index: int            # 0 for the first sub-session in the group, 1 for the second, etc.
    protocol: str
    source_ip: str
    destination_port: int
    first_event_id: str
    last_event_id: str
    first_sensor_time: str
    last_sensor_time: str
    event_ids: list = field(default_factory=list)
    actions: list = field(default_factory=list)
    schema_versions_seen: set = field(default_factory=set)
    incomplete: bool = False
    anomaly: Optional[str] = None


def _close_session(events_in_subsession, canonical_group_id, reconnect_index, incomplete, anomaly=None):
    first = events_in_subsession[0]
    last = events_in_subsession[-1]
    return Session(
        session_id=f"{canonical_group_id}-r{reconnect_index}",
        canonical_group_id=canonical_group_id,
        reconnect_index=reconnect_index,
        protocol=first["protocol"],
        source_ip=first["source_ip"],
        destination_port=first["destination_port"],
        first_event_id=first["event_id"],
        last_event_id=last["event_id"],
        first_sensor_time=first["sensor_time"],
        last_sensor_time=last["sensor_time"],
        event_ids=[e["event_id"] for e in events_in_subsession],
        actions=[e["action"] for e in events_in_subsession],
        schema_versions_seen=set(e["schema_version"] for e in events_in_subsession),
        incomplete=incomplete,
        anomaly=anomaly,
    )


def sessionize_group(canonical_group_id: str, events: list) -> list:
    """events: normalized event dicts sharing one canonical_session_id.
    Returns a list of Session objects (usually 1, sometimes more for
    reconnects, and the caller should expect incomplete=True sessions to
    appear too - those are real evidence, not bugs)."""
    ordered = sorted(events, key=lambda e: e["session_seq"])

    sessions = []
    current = []
    reconnect_index = 0
    leading_anomaly = None

    for i, ev in enumerate(ordered):
        if ev["action"] == "connect":
            if current:
                # a connect arrived without a prior disconnect - close the
                # open sub-session as incomplete rather than merging
                sessions.append(_close_session(
                    current, canonical_group_id, reconnect_index,
                    incomplete=True, anomaly="connect_without_prior_disconnect",
                ))
                reconnect_index += 1
                current = []
            current.append(ev)
        else:
            if not current:
                # group doesn't open with "connect" - keep the event, flag it
                leading_anomaly = "session_did_not_open_with_connect"
                current.append(ev)
            else:
                current.append(ev)

        if ev["action"] == "disconnect" and current:
            sessions.append(_close_session(
                current, canonical_group_id, reconnect_index,
                incomplete=False, anomaly=leading_anomaly,
            ))
            leading_anomaly = None
            reconnect_index += 1
            current = []

    if current:
        # ran out of events with a sub-session still open: real pattern,
        # observed in honeypot-replay.jsonl (e.g. S-ed7d82-0062515)
        sessions.append(_close_session(
            current, canonical_group_id, reconnect_index,
            incomplete=True, anomaly=leading_anomaly or "no_disconnect_before_end_of_replay",
        ))

    return sessions


def sessionize_stream(normalized_events):
    """normalized_events: iterable of normalize.py output dicts (already
    filtered to exclude quarantine records by the caller).
    Groups by canonical_session_id in memory, then sessionizes each group.
    For 250k events this comfortably fits in memory; if you outgrow that,
    swap the dict for a DuckDB GROUP BY on canonical_session_id instead -
    the sessionize_group() logic itself is unchanged either way."""
    groups: dict[str, list] = {}
    for ev in normalized_events:
        groups.setdefault(ev["canonical_session_id"], []).append(ev)

    all_sessions = []
    for canonical_group_id, events in groups.items():
        all_sessions.extend(sessionize_group(canonical_group_id, events))
    return all_sessions
