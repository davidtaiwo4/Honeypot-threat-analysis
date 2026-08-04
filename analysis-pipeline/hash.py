import csv
from collections import defaultdict


LEDGER_FIELDS = [
    "payload_sha256", "source_ip", "session_id", "event_id",
    "sensor_time", "protocol", "destination_port",
    "source_file", "source_line", "bytes_declared", "bytes_is_unreliable",
    "quarantine_status", "note",
]


def build_hash_ledger_rows(normalized_events: list, sessions: list) -> list:
    """Returns a list of dicts, one per payload_download event, ready to
    write to hash-ledger.csv. Never touches payload content -- only
    hash/size/locator metadata, matching the brief's quarantine-by-metadata
    requirement."""

    # need session_id for each event -> build event_id -> session_id lookup
    event_to_session = {}
    for s in sessions:
        for eid in s.event_ids:
            event_to_session[eid] = s.session_id

    # first pass: collect all bytes values seen per hash, to flag inconsistency
    bytes_by_hash = defaultdict(set)
    for ev in normalized_events:
        if ev.get("payload_sha256"):
            bytes_by_hash[ev["payload_sha256"]].add(ev.get("bytes"))

    rows = []
    for ev in normalized_events:
        if not ev.get("payload_sha256"):
            continue
        h = ev["payload_sha256"]
        inconsistent = len(bytes_by_hash[h]) > 1
        rows.append({
            "payload_sha256": h,
            "source_ip": ev["source_ip"],
            "session_id": event_to_session.get(ev["event_id"], "UNKNOWN"),
            "event_id": ev["event_id"],
            "sensor_time": ev["sensor_time"],
            "protocol": ev["protocol"],
            "destination_port": ev["destination_port"],
            "source_file": ev["source_file"],
            "source_line": ev["source_line"],
            "bytes_declared": ev.get("bytes"),
            "bytes_is_unreliable": inconsistent,
            "quarantine_status": "metadata_only_never_executed",
            "note": (
                "bytes varies across occurrences of this identical hash; "
                "do not treat bytes_declared as authoritative payload size"
                if inconsistent else ""
            ),
        })

    rows.sort(key=lambda r: (r["payload_sha256"], r["event_id"]))
    return rows


def write_hash_ledger_csv(rows: list, path: str) -> None:
    with open(path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=LEDGER_FIELDS)
        writer.writeheader()
        writer.writerows(rows)


def summarize_hashes(rows: list) -> list:
    """Derived 4-row (in this dataset) per-hash summary for readability in
    a report -- NOT a replacement for the per-event ledger."""
    by_hash = defaultdict(list)
    for r in rows:
        by_hash[r["payload_sha256"]].append(r)

    summary = []
    for h, hrows in by_hash.items():
        ips = sorted(set(r["source_ip"] for r in hrows))
        byte_values = sorted(set(r["bytes_declared"] for r in hrows))
        summary.append({
            "payload_sha256": h,
            "occurrence_count": len(hrows),
            "distinct_source_ips": len(ips),
            "source_ips": ";".join(ips),
            "distinct_bytes_values_seen": len(byte_values),
            "bytes_field_reliable": len(byte_values) == 1,
            "first_sensor_time": min(r["sensor_time"] for r in hrows),
            "last_sensor_time": max(r["sensor_time"] for r in hrows),
        })
    summary.sort(key=lambda s: s["payload_sha256"])
    return summary
