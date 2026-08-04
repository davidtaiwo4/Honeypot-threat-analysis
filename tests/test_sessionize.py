import json
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "analysis-pipeline"))

from sessionize import sessionize_group  # noqa: E402


def _fixture_event_to_normalized(fx_event: dict) -> dict:
    """public-fixtures.json uses a slimmer shape (src/time, no schema_version,
    no destination_port) than the real replay. This adapter maps it onto the
    fields sessionize_group() actually needs, so the same sessionization
    logic is exercised by both the fixtures and the real replay file."""
    event_id = fx_event["event_id"]
    _, _, seq = event_id.rpartition("-")
    return {
        "event_id": event_id,
        "session_seq": int(seq),
        "schema_version": "fixture",
        "protocol": fx_event["protocol"],
        "source_ip": fx_event["src"],
        "destination_port": None,
        "sensor_time": fx_event["time"],
        "action": fx_event["action"],
    }


def run_public_fixtures(fixtures_path: str) -> None:
    with open(fixtures_path) as f:
        data = json.load(f)

    failures = []
    for case in data["fixtures"]:
        case_id = case["case_id"]
        normalized = [_fixture_event_to_normalized(e) for e in case["input"]]
        # canonical_session_id for a fixture group = shared event_id prefix
        prefix = normalized[0]["event_id"].rsplit("-", 1)[0]
        sessions = sessionize_group(prefix, normalized)

        expected_count = case["expected"]["session_count"]
        expected_order = case["expected"]["ordered_event_ids"]

        actual_count = len(sessions)
        actual_order = [eid for s in sessions for eid in s.event_ids]

        ok = (actual_count == expected_count) and (actual_order == expected_order)
        status = "PASS" if ok else "FAIL"
        print(f"{status}  {case_id}  expected_sessions={expected_count} actual={actual_count}")
        if not ok:
            failures.append(case_id)
            print(f"       expected_order={expected_order}")
            print(f"       actual_order  ={actual_order}")

    print()
    if failures:
        print(f"{len(failures)} fixture(s) FAILED: {failures}")
        sys.exit(1)
    else:
        print(f"All {len(data['fixtures'])} public fixtures PASSED.")


if __name__ == "__main__":
    fixtures_path = sys.argv[1] if len(sys.argv) > 1 else "public-fixtures.json"
    run_public_fixtures(fixtures_path)
