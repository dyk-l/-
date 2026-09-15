"""归因与日志导出：标准化 JSON 证据链。"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Literal
from uuid import uuid4

from src.config import AUDIT_LOG_PATH, OUTPUT_DIR

Status = Literal["BLOCKED", "ALLOWED", "SAFE", "PENDING_APPROVAL"]


def _utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


@dataclass
class AuditEvent:
    event_id: str
    timestamp: str
    sample_id: str
    file_name: str
    source_file: str
    split: str
    category: str
    source_label: str
    target_tool: str | None
    tool_args: dict[str, Any]
    status: Status
    reason: str
    policy_hits: list[dict[str, Any]]
    baseline_attack_success: bool
    protected_attack_success: bool
    false_positive: bool
    model: str
    llm_mode: str
    model_response_preview: str
    hitl_required: bool = False
    hitl_decision: str = ""
    hitl_note: str = ""
    hitl_decided_at: str = ""
    risk_dimensions: list[str] = field(default_factory=list)
    localization: dict[str, Any] = field(default_factory=dict)
    reproduction: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def create(cls, **kwargs: Any) -> "AuditEvent":
        kwargs.setdefault("event_id", uuid4().hex)
        kwargs.setdefault("timestamp", _utc_now())
        kwargs.setdefault("policy_hits", [])
        kwargs.setdefault("split", "NORMAL")
        kwargs.setdefault("source_label", "Untrusted_External")
        kwargs.setdefault("false_positive", False)
        kwargs.setdefault("baseline_attack_success", False)
        kwargs.setdefault("protected_attack_success", False)
        kwargs.setdefault("hitl_required", False)
        kwargs.setdefault("hitl_decision", "")
        kwargs.setdefault("hitl_note", "")
        kwargs.setdefault("hitl_decided_at", "")
        kwargs.setdefault("risk_dimensions", [])
        kwargs.setdefault("localization", {})
        kwargs.setdefault("reproduction", {})
        return cls(**kwargs)


@dataclass
class AuditBundle:
    meta: dict[str, Any] = field(default_factory=dict)
    events: list[AuditEvent] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "meta": self.meta,
            "events": [asdict(event) for event in self.events],
        }


class AuditEngine:
    def __init__(self, path: Path | None = None) -> None:
        self.path = path or AUDIT_LOG_PATH
        self.events: list[AuditEvent] = []

    def record(self, event: AuditEvent) -> AuditEvent:
        self.events.append(event)
        return event

    def export(self, meta: dict[str, Any] | None = None) -> Path:
        OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
        bundle = AuditBundle(meta=meta or {}, events=self.events)
        self.path.write_text(
            json.dumps(bundle.to_dict(), ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
        return self.path

    def save_bundle(self, bundle: dict[str, Any]) -> Path:
        OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
        self.path.write_text(
            json.dumps(bundle, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
        return self.path

    @staticmethod
    def load(path: Path | None = None) -> dict[str, Any]:
        target = path or AUDIT_LOG_PATH
        if not target.exists():
            return {"meta": {}, "events": []}
        payload = json.loads(target.read_text(encoding="utf-8"))
        if isinstance(payload, list):
            return {"meta": {}, "events": payload}
        payload.setdefault("meta", {})
        payload.setdefault("events", [])
        return payload
