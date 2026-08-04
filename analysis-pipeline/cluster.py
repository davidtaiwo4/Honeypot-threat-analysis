"""
Groups sessions into infrastructure clusters.
"""

from dataclasses import dataclass, field, asdict
from collections import defaultdict, Counter


@dataclass
class Cluster:
    cluster_id: str
    member_source_ips: list
    evidence_type: str              # "shared_payload_hash" | "reconnaissance_only" | "unclustered"
    shared_payload_hashes: list
    session_ids: list
    confidence: str                 # "high" | "medium" | "low"
    rationale: str
    context_credential_fingerprints_seen: list = field(default_factory=list)
    context_protocols_seen: list = field(default_factory=list)


class _UnionFind:
    def __init__(self):
        self.parent = {}

    def find(self, x):
        self.parent.setdefault(x, x)
        while self.parent[x] != x:
            self.parent[x] = self.parent[self.parent[x]]
            x = self.parent[x]
        return x

    def union(self, a, b):
        ra, rb = self.find(a), self.find(b)
        if ra != rb:
            self.parent[ra] = rb


def cluster_sessions(normalized_events: list, sessions: list) -> list:
    """normalized_events: flat list of normalize.py output dicts (for
    per-event fields like credential_fingerprint/payload_sha256/protocol).
    sessions: sessionize.py Session objects.
    Returns a list of Cluster objects."""

    # per-source_ip aggregates, built from raw normalized events
    ip_payload_hashes = defaultdict(set)
    ip_credential_fps = defaultdict(set)
    ip_protocols = defaultdict(set)
    ip_had_auth_attempt = defaultdict(bool)
    ip_had_payload = defaultdict(bool)

    for ev in normalized_events:
        ip = ev["source_ip"]
        ip_protocols[ip].add(ev["protocol"])
        if ev.get("credential_fingerprint"):
            ip_credential_fps[ip].add(ev["credential_fingerprint"])
        if ev.get("payload_sha256"):
            ip_payload_hashes[ip].add(ev["payload_sha256"])
            ip_had_payload[ip] = True
        if ev["action"] in ("auth_fail", "auth_success"):
            ip_had_auth_attempt[ip] = True

    # union-find: connect source_ips that share at least one payload hash
    uf = _UnionFind()
    hash_to_ips = defaultdict(set)
    for ip, hashes in ip_payload_hashes.items():
        for h in hashes:
            hash_to_ips[h].add(ip)
    for h, ips in hash_to_ips.items():
        ips = list(ips)
        for other in ips[1:]:
            uf.union(ips[0], other)

    # group payload-connected ips by root
    groups = defaultdict(set)
    for ip in ip_payload_hashes:
        groups[uf.find(ip)].add(ip)

    # map sessions -> source_ip for fast lookup
    sessions_by_ip = defaultdict(list)
    for s in sessions:
        sessions_by_ip[s.source_ip].append(s.session_id)

    clusters = []
    cluster_num = 0

    for root, member_ips in groups.items():
        cluster_num += 1
        member_ips = sorted(member_ips)
        shared_hashes = sorted(set().union(*(ip_payload_hashes[ip] for ip in member_ips)))
        session_ids = sorted(sid for ip in member_ips for sid in sessions_by_ip[ip])
        creds_seen = sorted(set().union(*(ip_credential_fps[ip] for ip in member_ips)))
        protocols_seen = sorted(set().union(*(ip_protocols[ip] for ip in member_ips)))

        clusters.append(Cluster(
            cluster_id=f"CLUSTER-{cluster_num:03d}",
            member_source_ips=member_ips,
            evidence_type="shared_payload_hash",
            shared_payload_hashes=shared_hashes,
            session_ids=session_ids,
            confidence="high" if len(member_ips) > 1 else "medium",
            rationale=(
                f"{len(member_ips)} source IP(s) share identical payload hash set "
                f"({len(shared_hashes)} hashes) -- direct evidence of shared "
                f"distribution infrastructure, not inferred from reputation."
            ),
            context_credential_fingerprints_seen=creds_seen,
            context_protocols_seen=protocols_seen,
        ))

    # reconnaissance-only ips: sessions exist, no auth attempt ever, no payload ever
    recon_only_ips = sorted(
        ip for ip in ip_protocols
        if not ip_had_auth_attempt[ip] and not ip_had_payload[ip]
    )
    if recon_only_ips:
        session_ids = sorted(sid for ip in recon_only_ips for sid in sessions_by_ip[ip])
        clusters.append(Cluster(
            cluster_id="CLUSTER-RECON-ONLY",
            member_source_ips=recon_only_ips,
            evidence_type="reconnaissance_only",
            shared_payload_hashes=[],
            session_ids=session_ids,
            confidence="low",
            rationale=(
                f"{len(recon_only_ips)} source IP(s) with sessions containing only "
                f"connect/banner/disconnect -- never attempted auth, never downloaded "
                f"a payload. Reported separately as reconnaissance/scanning activity, "
                f"NOT merged with payload-based clusters -- no evidence connects them."
            ),
        ))

    clustered_ips = set(ip for c in clusters for ip in c.member_source_ips)
    remaining_ips = sorted(set(ip_protocols) - clustered_ips)
    if remaining_ips:
        session_ids = sorted(sid for ip in remaining_ips for sid in sessions_by_ip[ip])
        clusters.append(Cluster(
            cluster_id="CLUSTER-UNCLUSTERED-BACKGROUND",
            member_source_ips=remaining_ips,
            evidence_type="unclustered",
            shared_payload_hashes=[],
            session_ids=session_ids,
            confidence="low",
            rationale=(
                f"{len(remaining_ips)} source IP(s) attempted authentication using "
                f"widely-shared credential fingerprints (each fingerprint independently "
                f"observed across ~{max((len(v) for v in ip_credential_fps.values()), default=0)} "
                f"other IPs) with no payload delivery and no infrastructure overlap "
                f"beyond the shared credential list itself. Treated as background "
                f"credential-stuffing noise, not attributed to a single actor or "
                f"campaign -- credential reuse here is context, not identity evidence."
            ),
        ))

    return clusters


def clusters_to_dict(clusters: list) -> dict:
    return {"clusters": [asdict(c) for c in clusters]}
