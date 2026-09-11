"""Domain models for offline, defensive packet-telemetry analysis."""
from dataclasses import dataclass
from ipaddress import ip_address
from typing import Any

ALLOWED_PROTOCOLS = {"TCP", "UDP", "ICMP", "DNS", "HTTP", "HTTPS", "SMB", "RDP", "SSH"}
ALLOWED_DIRECTIONS = {"inbound", "outbound", "east-west"}


@dataclass(frozen=True)
class FlowRecord:
    timestamp: str
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str
    direction: str
    bytes_sent: int
    packets: int
    connection_count: int = 1
    dns_query: str = ""
    http_host: str = ""
    tls_sni: str = ""
    authenticated: bool = True
    approved_service: bool = True

    @staticmethod
    def from_dict(raw: dict[str, Any]) -> "FlowRecord":
        required = {
            "timestamp", "src_ip", "dst_ip", "src_port", "dst_port", "protocol",
            "direction", "bytes_sent", "packets"
        }
        missing = required - raw.keys()
        if missing:
            raise ValueError(f"missing required fields: {sorted(missing)}")

        for key in ("src_ip", "dst_ip"):
            try:
                ip_address(str(raw[key]))
            except ValueError as exc:
                raise ValueError(f"invalid {key}: {raw[key]}") from exc

        for key in ("src_port", "dst_port"):
            value = int(raw[key])
            if not 0 <= value <= 65535:
                raise ValueError(f"{key} outside 0-65535")

        protocol = str(raw["protocol"]).upper()
        if protocol not in ALLOWED_PROTOCOLS:
            raise ValueError(f"unsupported protocol: {protocol}")
        direction = str(raw["direction"]).lower()
        if direction not in ALLOWED_DIRECTIONS:
            raise ValueError(f"unsupported direction: {direction}")

        for key in ("bytes_sent", "packets", "connection_count"):
            value = int(raw.get(key, 1 if key == "connection_count" else 0))
            if value < 0:
                raise ValueError(f"{key} cannot be negative")

        return FlowRecord(
            timestamp=str(raw["timestamp"]),
            src_ip=str(raw["src_ip"]), dst_ip=str(raw["dst_ip"]),
            src_port=int(raw["src_port"]), dst_port=int(raw["dst_port"]),
            protocol=protocol, direction=direction,
            bytes_sent=int(raw["bytes_sent"]), packets=int(raw["packets"]),
            connection_count=int(raw.get("connection_count", 1)),
            dns_query=str(raw.get("dns_query", "")),
            http_host=str(raw.get("http_host", "")),
            tls_sni=str(raw.get("tls_sni", "")),
            authenticated=bool(raw.get("authenticated", True)),
            approved_service=bool(raw.get("approved_service", True)),
        )


@dataclass(frozen=True)
class Finding:
    finding_id: str
    title: str
    severity: str
    score: int
    src_ip: str
    dst_ip: str
    evidence: str
    remediation: str
    attack_techniques: tuple[str, ...]
