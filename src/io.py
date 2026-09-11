"""Fail-closed JSON ingestion for synthetic packet/flow evidence."""
import json
from pathlib import Path

from .models import FlowRecord


def load_records(path: str | Path) -> list[FlowRecord]:
    payload = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(payload, list):
        raise ValueError("top-level JSON value must be a list")

    records: list[FlowRecord] = []
    seen: set[tuple[object, ...]] = set()
    for raw in payload:
        if not isinstance(raw, dict):
            raise ValueError("each flow record must be a JSON object")
        record = FlowRecord.from_dict(raw)
        key = (
            record.timestamp, record.src_ip, record.dst_ip,
            record.src_port, record.dst_port, record.protocol,
        )
        if key in seen:
            raise ValueError(f"duplicate flow record: {key}")
        seen.add(key)
        records.append(record)
    return records
