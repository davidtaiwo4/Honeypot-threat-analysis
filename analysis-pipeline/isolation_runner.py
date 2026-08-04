"""
Runs the tests in isolation-tests.csv and appends results to
isolation-results.json. Run this separately from each required viewpoint:

    On WSL (the declared "management workstation"):
        python3 isolation_runner.py --viewpoint management --sensor-ip <ip> --sensor-port 64297

    On Kali (the "untrusted test host"):
        python3 isolation_runner.py --viewpoint external --sensor-ip <ip> --sensor-port 64297

    On the sensor VM itself (SSH'd in, for egress tests):
        python3 isolation_runner.py --viewpoint sensor --management-cidr <your-mgmt-ip>

Each run appends to isolation-results.json, so results from all three 
viewpoints accumulate into one file. ISO-07 (internet -> honeypot ports) 
is deliberately not run by this script from any local viewpoint -- it 
requires genuine public exposure.
"""

import argparse
import csv
import json
import os
import socket
import subprocess
import sys
from datetime import datetime, timezone

CSV_FIELDS = [
    "test_id", "source", "destination", "port_or_protocol", "expected",
    "actual", "utc_time", "artifact", "locator", "result", "notes",
]
 
 
def _now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
 
 
def load_test_template(csv_path: str) -> dict:
    """Reads isolation-tests.csv, returns {test_id: row_dict} using the
    template's own source/destination/port_or_protocol/expected columns as
    the source of truth. This runner only ever fills in the remaining
    columns (actual/utc_time/artifact/locator/result/notes) - it never
    invents its own description of what a test checks."""
    template = {}
    with open(csv_path, newline="") as f:
        for row in csv.DictReader(f):
            template[row["test_id"]] = row
    return template
 
 
def _fill(template_row: dict, actual: str, result: str, artifact: str, locator: str, notes: str) -> dict:
    row = dict(template_row)  # copy test_id/source/destination/port_or_protocol/expected as-is
    row["actual"] = actual
    row["utc_time"] = _now()
    row["artifact"] = artifact
    row["locator"] = locator
    row["result"] = result
    row["notes"] = notes
    return row
 
 
def _tcp_connect_test(host, port, timeout=4):
    """Returns (connected: bool, detail: str)."""
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True, f"TCP connect to {host}:{port} succeeded"
    except (socket.timeout, TimeoutError):
        return False, f"TCP connect to {host}:{port} timed out (likely dropped by firewall)"
    except ConnectionRefusedError:
        return False, f"TCP connect to {host}:{port} refused (port closed, not firewall-dropped)"
    except OSError as e:
        return False, f"TCP connect to {host}:{port} failed: {e}"
 
 
def _http_probe(url, timeout=4):
    try:
        result = subprocess.run(
            ["curl", "-s", "-o", "/dev/null", "-w", "%{http_code}",
             "--connect-timeout", str(timeout), "--max-time", str(timeout + 1), url],
            capture_output=True, text=True, timeout=timeout + 2,
        )
        code = result.stdout.strip()
        if code and code != "000":
            return True, f"HTTP probe to {url} got status {code}"
        return False, f"HTTP probe to {url} got no response (timeout/blocked)"
    except subprocess.TimeoutExpired:
        return False, f"HTTP probe to {url} timed out"
    except FileNotFoundError:
        return None, "curl not installed - cannot run this probe"
 
 
def _dns_probe(hostname="archive.ubuntu.com", timeout=4):
    try:
        result = subprocess.run(
            ["nslookup", hostname], capture_output=True, text=True, timeout=timeout,
        )
        ok = result.returncode == 0 and "can't find" not in result.stdout.lower()
        return ok, result.stdout.strip().replace("\n", " | ")
    except FileNotFoundError:
        return None, "nslookup not installed - cannot run this probe"
 
 
def run_management_viewpoint(template: dict, sensor_ip: str, sensor_port: int) -> list:
    """ISO-01: management workstation -> sensor management port, expect allow."""
    connected, detail = _tcp_connect_test(sensor_ip, sensor_port)
    row = _fill(
        template["ISO-01"],
        actual="allow" if connected else "deny",
        result="PASS" if connected else "FAIL",
        artifact="isolation_runner.py tcp_connect_test",
        locator=f"{sensor_ip}:{sensor_port} from management workstation",
        notes=detail,
    )
    return [row]
 
 
def run_external_viewpoint(template: dict, sensor_ip: str, sensor_port: int) -> list:
    """ISO-02: untrusted test host -> sensor management port, expect deny."""
    connected, detail = _tcp_connect_test(sensor_ip, sensor_port)
    row = _fill(
        template["ISO-02"],
        actual="allow" if connected else "deny",
        result="PASS" if not connected else "FAIL",
        artifact="isolation_runner.py tcp_connect_test",
        locator=f"{sensor_ip}:{sensor_port} from untrusted external host",
        notes=detail,
    )
    return [row]
 
 
def run_sensor_viewpoint(template: dict, management_cidr: str) -> list:
    """ISO-03/04/05/06/08: egress tests run FROM the sensor itself.
    For RFC1918 tests, deliberately probes an address OUTSIDE
    management_cidr/artifact_sink_ip (which are legitimately allowed
    exceptions) - otherwise the test would be invalid, since your own
    management path IS a private address."""
    results = []
 
    rfc1918_test_targets = [
        ("ISO-03", "10.255.255.1"),
        ("ISO-04", "172.31.255.1"),
        ("ISO-05", "192.168.255.1"),
    ]
    mgmt_prefix = management_cidr.split("/")[0].split(".")[0:3]
    for test_id, probe_ip in rfc1918_test_targets:
        if probe_ip.split(".")[0:3] == mgmt_prefix:
            row = _fill(
                template[test_id], actual="skipped", result="SKIP",
                artifact="isolation_runner.py",
                locator=f"sensor -> {probe_ip}",
                notes=f"SKIPPED: probe target {probe_ip} overlaps declared management_cidr, would invalidate test",
            )
            results.append(row)
            continue
        connected, detail = _tcp_connect_test(probe_ip, 80, timeout=3)
        row = _fill(
            template[test_id],
            actual="allow" if connected else "deny",
            result="PASS" if not connected else "FAIL",
            artifact="isolation_runner.py tcp_connect_test",
            locator=f"sensor -> {probe_ip}:80",
            notes=detail,
        )
        results.append(row)
 
    # ISO-06: metadata endpoint
    allowed, detail = _http_probe("http://169.254.169.254/latest/meta-data/")
    results.append(_fill(
        template["ISO-06"],
        actual="allow" if allowed else "deny",
        result="PASS" if not allowed else "FAIL",
        artifact="isolation_runner.py http_probe / capture-state.sh metadata-probe.txt",
        locator="sensor -> 169.254.169.254 (HTTP)",
        notes=detail,
    ))
 
    # ISO-08: DNS egress
    ok, detail = _dns_probe()
    results.append(_fill(
        template["ISO-08"],
        actual="allow" if ok else "deny",
        result="PASS" if ok else "FAIL",
        artifact="isolation_runner.py dns_probe",
        locator="sensor -> DNS resolvers (udp/53)",
        notes=detail,
    ))
 
    return results
 
 
def add_iso07_placeholder(template: dict) -> dict:
    return _fill(
        template["ISO-07"],
        actual="not_attempted", result="NOT_ATTEMPTED",
        artifact="", locator="internet -> sensor honeypot ports",
        notes=("Requires genuine public internet exposure of the sensor - belongs to the "
               "optional live-sensor task, not the mandatory local-boundary path. Not run "
               "against a private/lab network, since that would not actually test internet "
               "reachability and would produce a misleading result."),
    )
 
 
def append_results(new_results: list, out_path: str):
    existing = []
    if os.path.exists(out_path):
        with open(out_path) as f:
            existing = json.load(f).get("results", [])
    by_id = {r["test_id"]: r for r in existing}
    for r in new_results:
        by_id[r["test_id"]] = r
    merged = sorted(by_id.values(), key=lambda r: r["test_id"])
    with open(out_path, "w") as f:
        json.dump({"results": merged, "last_updated": _now()}, f, indent=2)
 
 
def write_results_csv(out_json_path: str, out_csv_path: str):
    """Also emit the completed CSV form, in case the deliverable expects
    isolation-tests.csv filled in directly rather than only JSON."""
    with open(out_json_path) as f:
        results = json.load(f)["results"]
    with open(out_csv_path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=CSV_FIELDS)
        writer.writeheader()
        writer.writerows(results)
 
 
if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--viewpoint", required=True, choices=["management", "external", "sensor"])
    parser.add_argument("--template", default="isolation-tests.csv", help="Path to isolation-tests.csv")
    parser.add_argument("--sensor-ip", help="Required for management/external viewpoints")
    parser.add_argument("--sensor-port", type=int, default=64297)
    parser.add_argument("--management-cidr", help="Required for sensor viewpoint, e.g. 192.168.112.1/32")
    parser.add_argument("--out", default="isolation-results.json")
    parser.add_argument("--out-csv", default=None, help="Optional: also write completed CSV form")
    args = parser.parse_args()
 
    template = load_test_template(args.template)
 
    if args.viewpoint == "management":
        if not args.sensor_ip:
            sys.exit("--sensor-ip required for management viewpoint")
        results = run_management_viewpoint(template, args.sensor_ip, args.sensor_port)
    elif args.viewpoint == "external":
        if not args.sensor_ip:
            sys.exit("--sensor-ip required for external viewpoint")
        results = run_external_viewpoint(template, args.sensor_ip, args.sensor_port)
    else:
        if not args.management_cidr:
            sys.exit("--management-cidr required for sensor viewpoint")
        results = run_sensor_viewpoint(template, args.management_cidr)
 
    append_results(results, args.out)
    append_results([add_iso07_placeholder(template)], args.out)
 
    if args.out_csv:
        write_results_csv(args.out, args.out_csv)
 
    for r in results:
        print(f"{r['result']:8s} {r['test_id']}  {r['source']} -> {r['destination']}  | {r['notes']}")
    print(f"\nWritten to {args.out}" + (f" and {args.out_csv}" if args.out_csv else ""))

