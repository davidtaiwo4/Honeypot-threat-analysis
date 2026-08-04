# Continuity Record — Stage 6

## 1. Previous-stage commit and component reused

Previous stage: Stage 5, `hunt-engine/` repository.
Stage 5 Commit: `30036cc9ab3a7e580d6a5c80f0605f7d192f5bbb`
Component reused: the normalized event schema and evidence-locator conventions established in `hunt-engine/normalize.py` (the COALESCE-based approach for unifying divergent source schemas — originally built for hunt-engine's v1/v2/v3 field-renaming problem across auth/web/dns/firewall/endpoint sources).

## 2. Interface consumed and backward-compatible extension

Interface consumed: hunt-engine's normalized-event contract — one canonical schema per event, with every field traceable to a raw source file, line number, and original field name, regardless of which source schema version produced it.

Backward-compatible extension: Stage 6's `analysis-pipeline/normalize.py` extends this same contract to honeypot replay data (`schema_version` "1"/"2" instead of hunt-engine's v1/v2/v3), adding new fields specific to honeypot data (`canonical_session_id`, `payload_sha256`, `credential_fingerprint`) without removing or renaming any field hunt-engine's model relied on. Any Stage 7 component built against hunt-engine's schema should be able to consume Stage 6's output unmodified for the fields both share.

## 3. Evidence that prior raw-to-result provenance remains intact

Every normalized event in Stage 6 carries `source_file` and `source_line`, the same locator pattern hunt-engine used — confirmed by `session-analysis.md`'s evidence chain, where every claim cites an exact line number in `honeypot-replay.jsonl`. `evidence-index.csv` follows the identical claim/locator/confidence/alternative structure used since Stage 4's deliverables, unchanged in Stage 6.

## 4. Migration record for every incompatible change

**Change:** session-grouping strategy. Hunt-engine's Stage 5 model did not need a "session" concept in this form; Stage 6 introduces `canonical_session_id`, derived from the `event_id` prefix rather than any literal source field.
**Why incompatible:** the replay's own documented interface (`replay-interface.json`) states `connection_id` as the session key; this pipeline found and rejected that approach after it produced 125,030 sessions instead of the true 62,515 (see decision-log.md D-001) — an honeypot-specific problem hunt-engine's sources never had.
**Migration:** this is additive, not a breaking change to hunt-engine's schema — `canonical_session_id` is a new field on top of the existing normalized-event contract, not a replacement of any hunt-engine field.

## 5. Component, schema, evidence, and decision record handed to the next stage

- **Schema:** the extended normalized-event contract (`analysis-pipeline/normalize.py`), ready for a Stage 7 network-range adapter to consume the same way Stage 6 consumed hunt-engine's.
- **Evidence:** `clusters.json` (CLUSTER-001, evidence-backed), `hash-ledger.csv`, `stix-bundle.json` — all with locators back to raw replay data.
- **Decision record:** `decision-log.md`, in particular D-001 (session-key derivation) and the credential/protocol-signal rejection rationale in `cluster.py`, both directly relevant if Stage 7 encounters similar multi-schema or weak-signal problems.
- **Detections:** `detections/sigma-recon-command.yml` and the Suricata rules — behavioral and IOC-based content Stage 7 can consume or extend against network-range data.
