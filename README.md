# Honeypot Sensor Boundary and Analysis Pipeline

A decoy system designed to attract attackers, plus a reproducible pipeline that turns its raw telemetry into sessions, infrastructure clusters, threat intelligence and detection rules. The sensor was built so it could not be used to reach anything it shouldn't.


## What this project does

1. **Sensor boundary (`sensor-infrastructure/`)**: an Ubuntu Server VM locked down with Ansible and nftables. One trusted management host is allowed in, everything else is denied by default. T-Pot (24.04.1) then exposes realistic SSH, Telnet, HTTP and MQTT services as bait.
2. **Analysis pipeline (`analysis-pipeline/`)**: reads a sealed replay of 250,000 honeypot events and produces sessions, clusters, a payload hash ledger, a STIX 2.1 bundle and Sigma/Suricata detections.
3. **Isolation testing**: the boundary was tested from three vantage points: a management host (WSL Ubuntu), an external attacker (Kali Linux) and the sensor itself checking its own outbound reach.

## Results

| Output | Result |
|---|---|
| Events ingested | 250,000 accounted for, none silently dropped |
| Sessions reconstructed | 62,515 |
| High-confidence cluster | 3 source IPs, 293 sessions, same 4 payload hashes |
| Reconnaissance-only cluster | 1 source IP, 644 sessions, no login attempts |
| Background cluster | 248 source IPs, 61,578 sessions, shared weak credentials |
| Isolation tests | 7 of 8 pass, 1 not attempted (needs public exposure, see below) |
| Reproducibility | Two clean runs produce identical outputs |

## Pipeline stages

```
honeypot-replay.jsonl
  -> ingest.py        read every line, quarantine malformed input
  -> normalize.py     map both schema versions to one event structure
  -> sessionize.py    rebuild sessions, handle reconnects and truncated sessions
  -> cluster.py       group source IPs by shared infrastructure evidence
  -> hash.py          payload hash ledger (metadata only, nothing is executed)
  -> stix.py          STIX 2.1 bundle
  -> detections.py    Sigma and Suricata rules
```

`run_pipeline.py` runs all of it with one command. Every output keeps a locator (file and line number) back to the raw event it came from.

## Design decisions

**Session identity comes from the event ID, not the connection field.** The two schema versions label the same session with different connection values, so grouping on that field splits each mixed-schema session in half. That produces 125,030 fake sessions instead of 62,515 real ones. Sessions are built from the event ID prefix and ordered by sequence number, because the replay is deliberately shuffled within 5,000-row blocks. Reconnects and sessions still open at the end of the replay are handled explicitly.

**Clustering uses payload hashes only.** Credential reuse and protocol targeting were tested first and rejected. Each is shared by almost every source IP, so using either would merge the whole dataset into one meaningless cluster. Shared payload hashes were the only signal that separated real shared infrastructure from background noise. Volume alone is not treated as coordination.

**Malware is never executed.** Payloads are handled as hash, size and source locator only.

**Outputs are deterministic.** Identifiers and STIX timestamps are derived from the data, never from the wall clock, so repeated runs are byte-identical. `tests/test_reproducibility.py` runs the whole pipeline twice from clean directories and compares every output.

**The Sigma rule is behavioral.** It matches a successful login followed by a reconnaissance command pattern, so it would also catch a different attacker repeating the behavior. The Suricata rules are IOC-based and cover the confirmed payload hashes and the cluster's source IPs.

**Reputation is context, not attribution.** The pipeline makes no actor-attribution claims.

## Repository layout

```
analysis-pipeline/     ingest, normalize, sessionize, cluster, hash, stix, detections,
                       run_pipeline.py, isolation_runner.py, merge_isolation_results.py
sensor-infrastructure/ Ansible playbook, nftables template, evidence capture script,
                       inventory.example.ini
tests/                 unit tests, session fixture runner, reproducibility test
detections/            generated Sigma and Suricata rules (example output)
Makefile               provision, ingest, analyze, test, clean
session-analysis.md    command-level write-up of one reconstructed attack session
```

## Requirements

- Python 3.11+
- `pip install pandas pyarrow pytest`
- For the sensor only: Ansible, a fresh Ubuntu Server VM, and an isolated lab network

## Data

The replay and the test fixtures are supplied by the programme and are not included in this repository.

- Place the replay at `raw-export/honeypot-replay.jsonl`.
- Place the public session fixtures at `public-fixtures.json` in the repo root.
- Place the isolation test template at `isolation-tests.csv` in the repo root.

The replay uses RFC 5737 documentation-range addresses (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`), so no addresses in it belong to real hosts.

## Usage

```bash
make analyze    # run the full pipeline on the replay
make test       # unit tests, 16 session fixtures, two-run reproducibility check
make clean      # remove regenerable outputs
```

Outputs written to the repo root: `sessions.parquet`, `clusters.json`, `hash-ledger.csv`, `hash-summary.json`, `stix-bundle.json`, and `detections/`.

### Sensor boundary

```bash
cp sensor-infrastructure/inventory.example.ini sensor-infrastructure/inventory.ini
# edit inventory.ini: sensor IP, your management IP, evidence sink IP, T-Pot ref
make provision
```

Then run the official T-Pot installer on the VM as a non-root user and reboot. Management SSH moves to port 64297.

**Do this only on a VM you own, on an isolated lab network.** The sensor must have no route to private or home LAN ranges, and the management port must be reachable only from your own host.

### Isolation tests

Run `analysis-pipeline/isolation_runner.py` once from each vantage point, then merge:

```bash
# management host
python3 analysis-pipeline/isolation_runner.py --viewpoint management --sensor-ip <sensor-ip> --sensor-port 64297 --out isolation-results.json
# external host (Kali)
python3 isolation_runner.py --viewpoint external --sensor-ip <sensor-ip> --sensor-port 64297 --out isolation-results.json
# on the sensor VM
python3 isolation_runner.py --viewpoint sensor --management-cidr <management-ip>/32 --out isolation-results.json

python3 analysis-pipeline/merge_isolation_results.py <the three files> --out isolation-results.json
```

| Test | Check | Result |
|---|---|---|
| ISO-01 | Management host can reach the management port | Pass |
| ISO-02 | Untrusted host cannot reach the management port | Pass |
| ISO-03 to 05 | Sensor cannot reach RFC1918 ranges | Pass |
| ISO-06 | Sensor cannot reach the cloud metadata address | Pass |
| ISO-07 | Internet can reach the honeypot ports | Not attempted |
| ISO-08 | Sensor can resolve DNS | Pass |

## Limitations

- ISO-07 needs the sensor exposed to the public internet. I did not run it, because a result from a private lab network would not test real internet reachability.
- The `bytes` field on payload events is unreliable. The same hash appears with dozens of different sizes, so it is flagged in the ledger and never used as payload size.
- The command-level analysis covers one session. The "automated, not human" conclusion is stronger across all 293 sessions in the cluster than from that single session.
- Live evidence from the sensor is a point-in-time capture, not a sustained collection run.
- Reproducibility was verified on one environment (Ubuntu 24.04 on WSL2).

## Tech

Python, pandas, pyarrow, pytest, Ansible, nftables, Docker, T-Pot, STIX 2.1, Sigma, Suricata, MITRE ATT&CK.
