# Stage 6 — Engineer a Deception Sensor and Analysis Pipeline

## Candidate / variant
Intern: UBI-2026-0210
Track: SOC_ANALYSIS
Variant: D5
Evidence marker: UBI-A6-FDB93D88BC5B

## Environment
- OS: Ubuntu 24.04 LTS (WSL2)
- Python: Python 3.12.3
- Key tool versions: pandas 3.0.5, pyarrow 25.0.0, pytest 9.1.1, ansible [core 2.16.3], nftables v1.0.9 (Old Doc Yak #3), T-Pot 24.04.1

## Reproduction order

1. `make provision` — provisions the sensor boundary (requires sudo password prompt on the VM)
2. `make analyze` — runs the full analysis pipeline against `raw-export/honeypot-replay.jsonl`, producing `sessions.parquet`, `clusters.json`, `stix-bundle.json`, `hash-ledger.csv`, and `detections/`
3. `make test` — runs the unit test suite, the 16 public session fixtures and the two-run reproducibility check
4. Isolation tests — run `isolation_runner.py` separately from three viewpoints (WSL/management, Kali/external, sensor VM), then merge with `analysis-pipeline/merge_isolation_results.py` into `isolation-results.json`
5. `make clean` — removes all regenerable pipeline outputs.

## Notes on scope

- The live public T-Pot sensor was deprioritized in favor of completing the mandatory sealed-replay path first, to prove isolation and deterministic analysis before considering live exposure.
- ISO-07 (internet → honeypot ports) is recorded `NOT_ATTEMPTED` in `isolation-results.json` — it requires genuine public exposure and is out of scope for the mandatory local-boundary path.
- `isolation-results.json` is generated from three separate machine runs and manually merged; it is preserved across `make clean` since no single local command can regenerate it.
