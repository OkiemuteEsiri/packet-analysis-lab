"""Deterministic, offline detection logic over synthetic network flow evidence."""
import hashlib
from collections import Counter
from typing import Iterable

from .models import Finding, FlowRecord

SEVERITY_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1}


def _id(kind: str, flow: FlowRecord) -> str:
    material = f"{kind}|{flow.timestamp}|{flow.src_ip}|{flow.dst_ip}|{flow.dst_port}|{flow.protocol}"
    return hashlib.sha256(material.encode()).hexdigest()[:12]


def _finding(flow: FlowRecord, kind: str, title: str, base: int, evidence: str,
             remediation: str, techniques: tuple[str, ...]) -> Finding:
    score = min(100, max(0, base + (10 if flow.direction == "outbound" else 0)
                         + (10 if not flow.authenticated else 0)
                         + (10 if not flow.approved_service else 0)))
    severity = "critical" if score >= 85 else "high" if score >= 70 else "medium" if score >= 45 else "low"
    return Finding(_id(kind, flow), title, severity, score, flow.src_ip, flow.dst_ip,
                   evidence, remediation, techniques)


def analyze_flow(flow: FlowRecord) -> list[Finding]:
    findings: list[Finding] = []

    if flow.protocol == "DNS" and len(flow.dns_query) >= 55:
        findings.append(_finding(
            flow, "long-dns", "Unusually long DNS query", 65,
            f"DNS query length={len(flow.dns_query)} characters",
            "Validate the source workload and resolver logs; block unauthorized tunneling patterns and tune detections after validation.",
            ("T1048.003", "T1071.004"),
        ))

    if flow.direction == "outbound" and flow.bytes_sent >= 5_000_000:
        findings.append(_finding(
            flow, "large-egress", "Large outbound data transfer", 70,
            f"Observed {flow.bytes_sent} outbound bytes in the synthetic flow record",
            "Confirm business purpose, destination ownership, DLP coverage and egress policy; investigate unexplained transfers.",
            ("T1048",),
        ))

    if flow.direction == "inbound" and flow.dst_port in {22, 3389, 445} and not flow.approved_service:
        findings.append(_finding(
            flow, "admin-exposure", "Unapproved inbound administrative service", 78,
            f"Inbound {flow.protocol}/{flow.dst_port} marked unapproved",
            "Restrict administrative services to approved management paths, require strong authentication and validate firewall policy.",
            ("T1133", "T1021"),
        ))

    if flow.connection_count >= 80 and flow.dst_port in {22, 3389, 445, 443}:
        findings.append(_finding(
            flow, "connection-spike", "High connection-attempt concentration", 62,
            f"connection_count={flow.connection_count} for destination port {flow.dst_port}",
            "Correlate authentication and firewall telemetry, validate expected automation, and tune rate-based detection thresholds.",
            ("T1110", "T1046"),
        ))

    if flow.protocol == "HTTP" and flow.direction == "outbound":
        findings.append(_finding(
            flow, "cleartext-egress", "Cleartext outbound HTTP", 48,
            f"Outbound HTTP host={flow.http_host or 'unspecified'}",
            "Migrate the service to authenticated TLS, validate certificate handling and restrict cleartext egress where feasible.",
            ("T1040",),
        ))

    if flow.direction == "east-west" and flow.protocol == "SMB" and not flow.authenticated:
        findings.append(_finding(
            flow, "unauth-smb", "Unauthenticated east-west SMB activity", 82,
            "Synthetic flow indicates east-west SMB without authenticated context",
            "Require authenticated SMB, disable guest/anonymous access, enforce segmentation and review endpoint telemetry.",
            ("T1021.002",),
        ))

    return findings


def analyze(records: Iterable[FlowRecord]) -> list[Finding]:
    findings = [finding for record in records for finding in analyze_flow(record)]
    return sorted(findings, key=lambda f: (-f.score, f.finding_id))


def metrics(findings: Iterable[Finding]) -> dict[str, object]:
    items = list(findings)
    severities = Counter(f.severity for f in items)
    techniques = Counter(t for f in items for t in f.attack_techniques)
    return {
        "total_findings": len(items),
        "severity_counts": dict(severities),
        "highest_score": max((f.score for f in items), default=0),
        "attack_technique_counts": dict(techniques),
    }
