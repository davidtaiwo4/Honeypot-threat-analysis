# Honeypot Session Analysis

Session ID: S-ed7d82-0000211-r0
Sensor / honeypot: T-Pot / MQTT honeypot, destination port 1883
First / last UTC event: 2026-07-01T00:10:34Z / 2026-07-01T00:10:39Z
Assigned evidence marker: UBI-A6-FDB93D88BC5B

## Evidence chain

|Step|UTC|Raw artifact + locator|Observed action|Interpretation|Confidence|Alternative|
|-|-|-|-|-|-|-|
|1|00:10:34Z|honeypot-replay.jsonl line 1226, event\_id S-ed7d82-0000211-1|connect from 198.51.100.155, dest port 1883 (mqtt)|Attacker opens MQTT session against honeypot|High|Could be a benign scanner that connects and disconnects immediately, ruled out by steps 3-5|
|2|00:10:35Z|honeypot-replay.jsonl line 4601, event\_id S-ed7d82-0000211-2|client\_banner|Client identifies itself to the broker before continuing|Medium|Banner content is not distinguishing on its own|
|3|00:10:36Z|honeypot-replay.jsonl line 213, event\_id S-ed7d82-0000211-3|auth\_success, username svc30, credential\_fingerprint 1a5ace3ed07f1b60|Successful authentication using a service-style account name|High (outcome) / Low (why it worked)|This credential fingerprint is reused across \~251 of 252 source IPs in the replay, so it may be a widely shared weak credential rather than something specific to this actor|
|4|00:10:37Z|honeypot-replay.jsonl line 4942, event\_id S-ed7d82-0000211-4|command: uname -a \&\& id (evidence marker UBI-A6-SHARED-B1 present on this event)|Post-authentication reconnaissance of OS/kernel and user identity|High|Could be scripted/automated rather than a human operator; nothing in this session alone distinguishes the two|
|5|00:10:38Z|honeypot-replay.jsonl line 4648, event\_id S-ed7d82-0000211-5|payload\_download, sha256 e1c27bf70abbabeb9ee71bffa8f9737b70361802170cbe39c11bbdc42875263f|Binary payload fetched immediately after recon|High (download occurred) / metadata only, file never opened|Declared byte size for this event is unreliable (72+ different values seen for this identical hash across occurrences)|
|6|00:10:39Z|honeypot-replay.jsonl line 1426, event\_id S-ed7d82-0000211-6|disconnect|Session ends cleanly after the download|High|None|

## Intent assessment

Most likely objective: automated reconnaissance-and-payload-staging. The session authenticates, fingerprints the environment (uname -a \&\& id), then immediately fetches a payload, all within 5 seconds with no operator-paced delay. What supports it: the command-to-download gap is 1 second, consistent with scripted behavior; the source IP is one of exactly 3 IPs (CLUSTER-001) sharing an identical 4-hash payload set delivered across multiple honeypot protocols, indicating a consistent toolkit rather than a one-off manual action. What would disprove it: evidence of human-paced interaction, such as longer gaps between steps, exploratory or incorrect commands, or abandonment after recon without follow-through. None of that is present in this session, but one session alone is thin evidence for "automated" on its own; the conclusion is stronger when read across all 293 CLUSTER-001 sessions collectively rather than from this session in isolation.

## ATT\&CK mapping

1. T1082 - System Information Discovery: uname -a. Evidence: step 4 command event. Limitation: single command observed, no further discovery activity in this session to corroborate a broader discovery phase.
2. T1033 - System Owner/User Discovery: id, chained in the same command. Evidence: step 4 command event. Limitation: chained via \&\& in one event rather than a separate observed step, so this pipeline's per-event granularity cannot fully separate the two techniques' individual timing.
3. T1105 - Ingress Tool Transfer: payload\_download action. Evidence: step 5, hash captured in hash-ledger.csv and stix-bundle.json. Limitation: the payload was never executed or inspected beyond hash and metadata, so its actual capability or malware family is unconfirmed - the hash is an indicator, not a classification.
4. T1078 - Valid Accounts (weak candidate, lower confidence): auth\_success. Evidence: step 3. Limitation: this credential fingerprint is shared across \~251 other source IPs unrelated to this cluster, so it more likely reflects a weak/default honeypot-exposed credential than a compromised legitimate account.

## Indicator handling

Payload hash e1c27bf70abbabeb9ee71bffa8f9737b70361802170cbe39c11bbdc42875263f - shared, high confidence: observed across all 3 CLUSTER-001 source IPs, part of an identical 4-hash set, delivered via multiple protocols. Represented as a STIX Indicator in stix-bundle.json, linked to the CLUSTER-001 Infrastructure object via an "indicates" relationship.

Source IP 198.51.100.155 - member of CLUSTER-001 (clusters.json), a 3-IP shared-infrastructure group. This is an RFC 5737 documentation-range test address in this replay dataset, not a real-world IP; treated as cluster context, not attribution.

Credential fingerprint 1a5ace3ed07f1b60 - not treated as a distinguishing indicator. It is one of 31 fingerprints, each independently observed across roughly 251 of 252 total source IPs in the replay, so it carries no attribution or clustering value on its own. No actor attribution is claimed from this fingerprint or from any IP reputation result.

## Defensive action

Detection: detections/sigma-recon-command.yml, a behavioral Sigma rule matching an auth\_success immediately followed (within 5 seconds) by a command containing both "uname" and "id". Not tied to this session's specific IP or hash, so it also matches a different future attacker using the same recon pattern. Owner: SOC detection engineer. Acceptance test: replay this session (or the P-SESSION fixtures) through the rule and confirm it fires; replay a benign, longer, more varied admin session and confirm it does not fire.

Prevention: disable or rate-limit the weak/default credential set responsible for the 251-IP-wide auth\_success hits recorded in hash-ledger.csv's associated sessions. Owner: infrastructure/identity team. Acceptance test: attempt authentication with the top reused credential fingerprints against a hardened target and confirm all are rejected; confirm legitimate, distinct-credential service accounts still authenticate successfully.
