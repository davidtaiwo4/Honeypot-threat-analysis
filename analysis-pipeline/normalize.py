"""
Converts raw parsed events (from ingest.read_source_file) into the canonical
normalized event schema used by every downstream stage (sessionize, cluster,
hash, STIX, detections).
This does not decide session boundaries (connect/disconnect
splitting, reconnects) -- that's sessionize.py. This project only cleans
and standardizes individual events, one at a time, and quarantines
anything malformed.
"""

from dataclasses import dataclass, asdict
from typing import Optional


REQUIRED_FIELDS = (
    "schema_version", "event_id", "sensor_time", "protocol",
    "source_ip", "source_port", "destination_port", "connection_id",
    "action",
)

KNOWN_SCHEMA_VERSIONS = {"1", "2"}
KNOWN_ACTIONS = {
    "connect", "client_banner", "auth_fail", "auth_success",
    "command", "payload_download", "disconnect",
}


@dataclass
class NormalizedEvent:
    canonical_session_id: str
    session_seq: int              # numeric suffix from event_id, for ordering
    schema_version: str
    event_id: str
    sensor_time: str
    protocol: str
    source_ip: str
    source_port: int
    destination_port: int
    raw_connection_id: str        # preserved, NOT used for grouping
    action: str
    username: Optional[str]
    credential_fingerprint: Optional[str]
    command: Optional[str]
    payload_sha256: Optional[str]
    bytes: Optional[int]
    marker: Optional[str]
    source_line: int              # locator back into the raw file
    source_file: str


def derive_canonical_session_id(event_id: str) -> tuple[str, int]:
    """Split 'S-ed7d82-0000844-6' into ('S-ed7d82-0000844', 6).
    Raises ValueError if event_id doesn't match the expected pattern -
    caller must quarantine such records rather than guess."""
    prefix, _, suffix = event_id.rpartition("-")
    if not prefix or not suffix.isdigit():
        raise ValueError(f"event_id does not match <prefix>-<seq> pattern: {event_id!r}")
    return prefix, int(suffix)


def normalize_event(raw: dict, source_file: str, source_line: int) -> dict:
    """Returns either a normalized event dict (asdict of NormalizedEvent)
    or a quarantine dict: {"quarantine_reason": ..., "source_line": ..., "source_file": ..., "raw": raw}
    Never raises - every malformed input becomes a quarantine record so
    nothing is silently dropped (matches ingest.py's stated contract)."""

    if "quarantine_reason" in raw:
        # already flagged by ingest.py (empty line / invalid json)
        raw["source_line"] = source_line
        raw["source_file"] = source_file
        return raw

    missing = [f for f in REQUIRED_FIELDS if f not in raw]
    if missing:
        return {
            "quarantine_reason": f"missing_fields:{','.join(missing)}",
            "source_line": source_line,
            "source_file": source_file,
            "raw": raw,
        }

    if raw["schema_version"] not in KNOWN_SCHEMA_VERSIONS:
        return {
            "quarantine_reason": f"unknown_schema_version:{raw['schema_version']}",
            "source_line": source_line,
            "source_file": source_file,
            "raw": raw,
        }

    if raw["action"] not in KNOWN_ACTIONS:
        return {
            "quarantine_reason": f"unknown_action:{raw['action']}",
            "source_line": source_line,
            "source_file": source_file,
            "raw": raw,
        }

    try:
        canonical_session_id, session_seq = derive_canonical_session_id(raw["event_id"])
    except ValueError as e:
        return {
            "quarantine_reason": f"bad_event_id:{e}",
            "source_line": source_line,
            "source_file": source_file,
            "raw": raw,
        }

    try:
        event = NormalizedEvent(
            canonical_session_id=canonical_session_id,
            session_seq=session_seq,
            schema_version=raw["schema_version"],
            event_id=raw["event_id"],
            sensor_time=raw["sensor_time"],
            protocol=raw["protocol"],
            source_ip=raw["source_ip"],
            source_port=int(raw["source_port"]),
            destination_port=int(raw["destination_port"]),
            raw_connection_id=raw["connection_id"],
            action=raw["action"],
            username=raw.get("username"),
            credential_fingerprint=raw.get("credential_fingerprint"),
            command=raw.get("command"),
            payload_sha256=raw.get("payload_sha256"),
            bytes=raw.get("bytes"),
            marker=raw.get("marker"),
            source_line=source_line,
            source_file=source_file,
        )
    except (TypeError, ValueError) as e:
        return {
            "quarantine_reason": f"type_coercion_failed:{e}",
            "source_line": source_line,
            "source_file": source_file,
            "raw": raw,
        }

    return asdict(event)


def normalize_file(path: str):
    """Generator yielding normalized-or-quarantined dicts for an entire
    JSONL source file. Import read_source_file from your ingest.py."""
    from ingest import read_source_file  # your existing, unmodified file

    for line_number, parsed in read_source_file(path):
        yield normalize_event(parsed, source_file=path, source_line=line_number)
