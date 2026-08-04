"""
Builds a STIX 2.1 bundle directly from cluster.py and hash.py output --
every Indicator/Infrastructure/Relationship object here traces back to a
real hash or IP observed in the replay.
Hand-rolled (no stix2 library dependency) to keep the pipeline's
dependency footprint small (pandas/pyarrow only, for sessions.parquet).

Objects produced:
  - identity (this pipeline/organization, referenced as created_by_ref)
  - indicator per unique payload hash (file:hashes.'SHA-256' pattern)
  - infrastructure per cluster (grouping the member source IPs)
  - relationship: indicator "indicates" infrastructure, for CLUSTER-001
  - grouping object tying the campaign evidence together, with a
    description that cites exact locators (cluster_id, session_ids range,
    evidence marker) rather than vague prose

"""

import json
import uuid
import hashlib
from datetime import datetime, timezone


SPEC_VERSION = "2.1"


_PIPELINE_TIMESTAMP = None  # set by build_stix_bundle() before any object is created
 
 
def _now_iso():
    if _PIPELINE_TIMESTAMP is None:
        raise RuntimeError(
            "stix.py: _now_iso() called before build_stix_bundle() set "
            "_PIPELINE_TIMESTAMP. Objects must never be built with wall-clock "
            "time -- see decision-log D-00X on reproducibility."
        )
    return _PIPELINE_TIMESTAMP
 
 
def _deterministic_uuid(*parts: str) -> str:
    """STIX ids need to be unique but reproducible across pipeline reruns
    on the same input, so a rerun produces byte-identical output (required
    for the Friday clean-rebuild hash comparison). Derives a uuid5 from the
    object's own content rather than uuid4 (random)."""
    namespace = uuid.UUID("6ba7b810-9dad-11d1-80b4-00c04fd430c8")  # STIX-style fixed namespace
    key = "|".join(parts)
    return str(uuid.uuid5(namespace, key))
 
 
def _make_identity(pipeline_name: str, evidence_marker: str) -> dict:
    return {
        "type": "identity",
        "spec_version": SPEC_VERSION,
        "id": f"identity--{_deterministic_uuid('identity', evidence_marker)}",
        "created": _now_iso(),
        "modified": _now_iso(),
        "name": pipeline_name,
        "identity_class": "system",
        "description": f"Automated honeypot analysis pipeline, evidence marker {evidence_marker}",
    }
 
 
def _make_hash_indicator(hash_summary_row: dict, identity_ref: str) -> dict:
    h = hash_summary_row["payload_sha256"]
    ind_id = f"indicator--{_deterministic_uuid('indicator', h)}"
    return {
        "type": "indicator",
        "spec_version": SPEC_VERSION,
        "id": ind_id,
        "created": _now_iso(),
        "modified": _now_iso(),
        "created_by_ref": identity_ref,
        "name": f"Payload hash observed in honeypot capture: {h[:16]}...",
        "description": (
            f"Observed {hash_summary_row['occurrence_count']} times across "
            f"{hash_summary_row['distinct_source_ips']} source IP(s) "
            f"({hash_summary_row['source_ips']}). bytes field unreliable for "
            f"this hash -- do not treat as payload size (see hash-ledger.csv note)."
            if not hash_summary_row["bytes_field_reliable"] else
            f"Observed {hash_summary_row['occurrence_count']} times across "
            f"{hash_summary_row['distinct_source_ips']} source IP(s) "
            f"({hash_summary_row['source_ips']})."
        ),
        "indicator_types": ["malicious-activity"],
        "pattern": f"[file:hashes.'SHA-256' = '{h}']",
        "pattern_type": "stix",
        "pattern_version": SPEC_VERSION,
        "valid_from": hash_summary_row["first_sensor_time"],
        "confidence": 85,  # high, per cluster.py's own confidence rationale (direct shared-hash evidence)
    }
 
 
def _make_infrastructure(cluster: dict, identity_ref: str) -> dict:
    infra_id = f"infrastructure--{_deterministic_uuid('infrastructure', cluster['cluster_id'])}"
    return {
        "type": "infrastructure",
        "spec_version": SPEC_VERSION,
        "id": infra_id,
        "created": _now_iso(),
        "modified": _now_iso(),
        "created_by_ref": identity_ref,
        "name": f"Honeypot campaign infrastructure: {cluster['cluster_id']}",
        "description": cluster["rationale"],
        "infrastructure_types": ["command-and-control"] if cluster["evidence_type"] == "shared_payload_hash" else ["unknown"],
        "x_source_ips": cluster["member_source_ips"],   # custom property, prefixed x_ per STIX 2.1 extension convention
        "x_session_count": len(cluster["session_ids"]),
        "x_confidence_rationale": cluster["rationale"],
    }
 
 
def _make_relationship(source_ref: str, target_ref: str, rel_type: str, identity_ref: str, description: str) -> dict:
    rel_id = f"relationship--{_deterministic_uuid('relationship', source_ref, target_ref, rel_type)}"
    return {
        "type": "relationship",
        "spec_version": SPEC_VERSION,
        "id": rel_id,
        "created": _now_iso(),
        "modified": _now_iso(),
        "created_by_ref": identity_ref,
        "relationship_type": rel_type,
        "source_ref": source_ref,
        "target_ref": target_ref,
        "description": description,
    }
 
 
def build_stix_bundle(clusters_dict: dict, hash_summary: list, evidence_marker: str,
                       marker_event_id: str = None, marker_session_id: str = None) -> dict:
    global _PIPELINE_TIMESTAMP
    # Deterministic "created" timestamp derived from the data itself (the
    # latest sensor_time observed across all hash evidence), NOT
    # wall-clock -- required so rerunning on identical input reproduces a
    # byte-identical bundle for the Friday clean-rebuild comparison.
    if hash_summary:
        _PIPELINE_TIMESTAMP = max(row["last_sensor_time"] for row in hash_summary)
    else:
        _PIPELINE_TIMESTAMP = "1970-01-01T00:00:00.000Z"
 
    identity = _make_identity("soc-stage6-analysis-pipeline", evidence_marker)
    identity_ref = identity["id"]
 
    objects = [identity]
 
    # only CLUSTER-001-style shared-hash clusters get promoted to full
    # Indicator + Infrastructure + Relationship objects; low-confidence
    # clusters are described in evidence-index.csv / session-analysis.md
    # instead, not elevated to STIX (avoids implying actionable attribution
    # for background noise)
    high_conf_clusters = [c for c in clusters_dict["clusters"] if c["evidence_type"] == "shared_payload_hash"]
 
    hash_to_indicator_ref = {}
    for row in hash_summary:
        ind = _make_hash_indicator(row, identity_ref)
        objects.append(ind)
        hash_to_indicator_ref[row["payload_sha256"]] = ind["id"]
 
    for cluster in high_conf_clusters:
        infra = _make_infrastructure(cluster, identity_ref)
        objects.append(infra)
        for h in cluster["shared_payload_hashes"]:
            if h in hash_to_indicator_ref:
                rel = _make_relationship(
                    hash_to_indicator_ref[h], infra["id"], "indicates", identity_ref,
                    description=(
                        f"Hash {h[:16]}... delivered via infrastructure in "
                        f"{cluster['cluster_id']} ({len(cluster['member_source_ips'])} IPs, "
                        f"{len(cluster['session_ids'])} sessions)."
                    ),
                )
                objects.append(rel)
 
        if marker_event_id and cluster["cluster_id"] == "CLUSTER-001":
            note = {
                "type": "note",
                "spec_version": SPEC_VERSION,
                "id": f"note--{_deterministic_uuid('note', marker_event_id)}",
                "created": _now_iso(),
                "modified": _now_iso(),
                "created_by_ref": identity_ref,
                "object_refs": [infra["id"]],
                "abstract": "Evidence marker + command-level session locator",
                "content": (
                    f"Command-level evidence: event_id={marker_event_id}, "
                    f"session_id={marker_session_id}, command='uname -a && id', "
                    f"evidence_marker={evidence_marker}. Raw locator preserved in "
                    f"honeypot-replay.jsonl and hash-ledger.csv for reproduction."
                ),
            }
            objects.append(note)
 
    bundle = {
        "type": "bundle",
        "id": f"bundle--{_deterministic_uuid('bundle', evidence_marker)}",
        "objects": objects,
    }
    return bundle
 
 
def write_stix_bundle(bundle: dict, path: str) -> None:
    with open(path, "w") as f:
        json.dump(bundle, f, indent=2)
