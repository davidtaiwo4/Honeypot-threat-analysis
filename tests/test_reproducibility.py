"""
This test runs the FULL real pipeline
(ingest -> normalize -> sessionize -> cluster -> hash ledger -> STIX ->
detections) TWICE against the actual replay file, in two separate
directories, and asserts every output file is byte-identical.

This is the test that would have caught it if e.g. STIX object IDs were
built with uuid4() (random) instead of uuid5() (deterministic from
content) -- a subtle bug that wouldn't show up in any single-run test,
only in a rerun comparison.
Usage:
    python3 tests/test_reproducibility.py /path/to/honeypot-replay.jsonl
"""

import sys
import os
import subprocess
import hashlib
import shutil


def _file_hash(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        h.update(f.read())
    return h.hexdigest()


def run_reproducibility_check(replay_path: str) -> bool:
    pipeline_dir = os.path.join(os.path.dirname(__file__), "..", "analysis-pipeline")
    run_a = "/tmp/repro-check-run-a"
    run_b = "/tmp/repro-check-run-b"
    for d in (run_a, run_b):
        if os.path.exists(d):
            shutil.rmtree(d)
        os.makedirs(d)

    for run_dir in (run_a, run_b):
        result = subprocess.run(
            [sys.executable, os.path.join(pipeline_dir, "run_pipeline.py"), replay_path],
            cwd=run_dir, capture_output=True, text=True,
        )
        if result.returncode != 0:
            print(f"Pipeline run failed in {run_dir}:")
            print(result.stdout)
            print(result.stderr)
            return False

    # sessions.parquet has a non-deterministic internal write timestamp in
    # some pyarrow versions even with identical data -- compare row content
    # via pandas instead of raw bytes for that one file; everything else
    # must be raw-byte identical.
    exact_match_files = [
        "clusters.json", "hash-ledger.csv", "hash-summary.json",
        "stix-bundle.json",
        "detections/sigma-recon-command.yml",
        "detections/suricata-known-payload-hashes.rules",
        "detections/suricata-cluster-001-watchlist.rules",
    ]

    all_ok = True
    for rel_path in exact_match_files:
        path_a = os.path.join(run_a, rel_path)
        path_b = os.path.join(run_b, rel_path)
        if not (os.path.exists(path_a) and os.path.exists(path_b)):
            print(f"MISSING: {rel_path} not produced by both runs")
            all_ok = False
            continue
        hash_a, hash_b = _file_hash(path_a), _file_hash(path_b)
        status = "IDENTICAL" if hash_a == hash_b else "DIFFERS"
        print(f"{status}  {rel_path}")
        if hash_a != hash_b:
            all_ok = False

    try:
        import pandas as pd
        df_a = pd.read_parquet(os.path.join(run_a, "sessions.parquet"))
        df_b = pd.read_parquet(os.path.join(run_b, "sessions.parquet"))
        sessions_match = df_a.equals(df_b)
        print(f"{'IDENTICAL' if sessions_match else 'DIFFERS'}  sessions.parquet (content comparison)")
        all_ok = all_ok and sessions_match
    except ImportError:
        print("SKIPPED  sessions.parquet (pandas not installed)")

    return all_ok


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 test_reproducibility.py /path/to/honeypot-replay.jsonl")
        sys.exit(2)
    ok = run_reproducibility_check(sys.argv[1])
    if ok:
        print("\nAll outputs reproducible across two clean runs.")
        sys.exit(0)
    else:
        print("\nREPRODUCIBILITY FAILURE - see above.")
        sys.exit(1)
