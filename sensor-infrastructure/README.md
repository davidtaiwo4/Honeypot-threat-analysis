# SOC-A2 T-Pot Lab Source

This bundle provisions the host boundary around an official T-Pot installation.
It does not vendor T-Pot or pretend that a generated replay is a live sensor.

Required operator inputs:

- a fresh supported minimal Linux host with a dedicated public address;
- `management_cidr` set to the operator's own fixed management address;
- `artifact_sink_ip` set to an evidence collector in the operator's lab;
- the official T-Pot installer checkout pinned by `tpot_ref`;
- an operator-confirmed maintenance window before public exposure.

Run `make provision`, complete the official non-root installer when prompted,
then run `make capture`. The capture command records firewall configuration,
listening sockets, routes, egress probes, and T-Pot container state. It does not
declare a pass/fail result.

Never execute captured payloads. Export metadata, hashes, and quarantined bytes
only to the candidate-controlled evidence sink.
