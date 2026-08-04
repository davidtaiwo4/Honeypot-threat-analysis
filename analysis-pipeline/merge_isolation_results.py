"""
merge_isolation_results.py
 
Merges isolation-results.json files produced from separate viewpoints
(WSL, Kali, sensor/VM) into one canonical file at the submission root. 
Dedupes by test_id -- if the same test_id appears in more
than one file, the LAST file passed on the command line wins for that
test_id. Order your arguments accordingly (least authoritative first).
 
Usage:
    python3 merge_isolation_results.py isolation-results.json \
        isolation-results-kali.json isolation-results-sensor.json \
        --out isolation-results.json
"""
 
import argparse
import json
 
 
def merge(paths: list) -> dict:
    by_id = {}
    for path in paths:
        with open(path) as f:
            data = json.load(f)
        for r in data.get("results", []):
            by_id[r["test_id"]] = r  # later files overwrite earlier ones for same test_id
    merged = sorted(by_id.values(), key=lambda r: r["test_id"])
    return {"results": merged}
 
 
if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("inputs", nargs="+", help="isolation-results.json files to merge, in order")
    parser.add_argument("--out", default="isolation-results.json")
    args = parser.parse_args()
 
    merged = merge(args.inputs)
    with open(args.out, "w") as f:
        json.dump(merged, f, indent=2)
 
    print(f"Merged {len(args.inputs)} files -> {len(merged['results'])} unique test_ids -> {args.out}")
    for r in merged["results"]:
        print(f"  {r['result']:14s} {r['test_id']:10s} {r['source']} -> {r['destination']}")
