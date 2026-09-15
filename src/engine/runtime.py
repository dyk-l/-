"""运行时策略决策点：挂到真实智能体工具调用之前。

兼容 OpenClaw 钩子、OpenAI function calling，以及通用 {tool, args}。
本服务不执行工具，只判定是否允许执行；调用方在收到 ALLOW 后再自行落地。
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Literal
from uuid import uuid4

from src.config import RUNTIME_AUDIT_PATH, RUNTIME_PENDING_PATH, SCENARIO_POLICY_PATH
from src.data.llm import ToolCall
from src.engine.execution_gate import AgentGate
from src.engine.ifc import IFCDecision, PolicyWhitelistGateway
from src.engine.supply_chain import SupplyChainScanner

DecisionStatus = Literal["BLOCKED", "ALLOWED", "SAFE", "PENDING_APPROVAL"]


def _utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _canon(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _clip(text: str, limit: int) -> str:
    compact = " ".join(str(text or "").split())
    if len(compact) <= limit:
        return compact
    return compact[: max(limit - 1, 0)] + "…"


@dataclass
class RuntimeDecision:
    status: DecisionStatus
    allowed: bool
    would_execute: bool
    requires_approval: bool
    tool: str
    canonical_tool: str
    scenario: str
    session_id: str
    source_label: str
    agent_id: str
    reason: str
    approval_id: str = ""
    policy_hits: list[dict[str, Any]] = field(default_factory=list)
    stages: dict[str, Any] = field(default_factory=dict)
    event_id: str = ""
    timestamp: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    def approval_prompt(self) -> dict[str, Any]:
        failed = [item for item in self.policy_hits if not item.get("passed")]
        rules = "、".join(str(item.get("rule_id") or "") for item in failed[:4] if item.get("rule_id"))
        description = _clip(
            "；".join(
                part
                for part in [
                    self.reason,
                    f"场景 {self.scenario} 会话 {self.session_id}",
                    f"失败规则 {rules}" if rules else "",
                    f"证据 /guard {self.event_id or self.session_id}",
                ]
                if part
            ),
            512,
        )
        title = _clip(f"政企审批：{self.canonical_tool or self.tool}", 80)
        if (self.canonical_tool or self.tool) == "install_plugin":
            title = _clip("政企审批：安装插件/Skill", 80)
        return {
            "title": title,
            "description": description,
            "severity": "warning",
            "timeoutMs": 120_000,
            "allowedDecisions": ["allow-once", "deny"],
        }

    def to_openclaw_hook(self) -> dict[str, Any] | None:
        """映射到 OpenClaw `before_tool_call` / `before_install` 钩子返回值。

        安装与工具调用统一：待审返回 requireApproval；硬拦截返回 block。
        """
        if self.requires_approval or self.status == "PENDING_APPROVAL":
            return {"requireApproval": self.approval_prompt()}
        if self.allowed:
            return None
        return {"block": True, "blockReason": self.reason}

    def openclaw_plugin_payload(self) -> dict[str, Any]:
        if self.requires_approval or self.status == "PENDING_APPROVAL":
            action = "approve"
        elif self.allowed:
            action = "allow"
        else:
            action = "block"
        return {
            "ok": True,
            "action": action,
            "approvalId": self.approval_id,
            "decision": self.to_dict(),
            "hook": self.to_openclaw_hook(),
        }


class RuntimePolicyBroker:
    def __init__(
        self,
        scenario_path: Path | None = None,
        pending_path: Path | None = None,
        audit_path: Path | None = None,
        audit_limit: int = 2000,
    ) -> None:
        self.scenario_path = scenario_path or SCENARIO_POLICY_PATH
        self.pending_path = pending_path or RUNTIME_PENDING_PATH
        self.audit_path = audit_path or RUNTIME_AUDIT_PATH
        self.audit_limit = max(int(audit_limit), 1)
        self.config = json.loads(self.scenario_path.read_text(encoding="utf-8"))
        self.ifc = PolicyWhitelistGateway()
        self.exec_gate = AgentGate()
        self.scanner = SupplyChainScanner()
        self.pending: dict[str, dict[str, Any]] = {}
        self.always: list[dict[str, Any]] = []
        self._load_pending()

    def scenarios(self) -> dict[str, Any]:
        return {
            "default": self.config.get("default_scenario") or "office",
            "aliases": dict(self.config.get("agent_aliases") or {}),
            "scenarios": {
                key: {
                    "id": key,
                    "name": spec.get("name"),
                    "allow": list(spec.get("allow") or []),
                    "agent_id": spec.get("agent_id"),
                    "source_label": spec.get("source_label"),
                }
                for key, spec in (self.config.get("scenarios") or {}).items()
            },
        }

    def check(
        self,
        *,
        tool: str,
        args: dict[str, Any] | None = None,
        scenario: str | None = None,
        session_id: str | None = None,
        source_label: str | None = None,
        agent_id: str | None = None,
        sibling_calls: list[dict[str, Any]] | None = None,
        approval_id: str = "",
        caller: str = "generic",
    ) -> RuntimeDecision:
        spec, scenario_id = self._scenario(scenario, agent_id)
        session = (session_id or "default").strip() or "default"
        canonical, normalized = self._canonicalize(tool, dict(args or {}))
        allow = {str(item) for item in (spec.get("allow") or [])}
        label = (source_label or spec.get("source_label") or "Trusted_Internal").strip()
        runtime_agent = str(spec.get("agent_id") or "agent_clerk").strip()
        fingerprint = self._fingerprint(session, canonical, normalized)

        if canonical not in allow:
            return self._finish(
                RuntimeDecision(
                    status="BLOCKED",
                    allowed=False,
                    would_execute=False,
                    requires_approval=False,
                    tool=tool,
                    canonical_tool=canonical or tool,
                    scenario=scenario_id,
                    session_id=session,
                    source_label=label,
                    agent_id=runtime_agent,
                    reason=f"场景「{spec.get('name') or scenario_id}」不允许工具 `{canonical or tool}`",
                    policy_hits=[{"rule_id": "runtime.scenario_allow", "passed": False, "detail": canonical or tool}],
                    stages={"perceive": {"caller": caller, "canonical": canonical}},
                )
            )

        if self._always_granted(session, canonical, fingerprint):
            return self._finish(
                RuntimeDecision(
                    status="ALLOWED",
                    allowed=True,
                    would_execute=True,
                    requires_approval=False,
                    tool=tool,
                    canonical_tool=canonical,
                    scenario=scenario_id,
                    session_id=session,
                    source_label=label,
                    agent_id=runtime_agent,
                    reason="会话已授权该工具（allow-always）。",
                    policy_hits=[{"rule_id": "runtime.allow_always", "passed": True, "detail": canonical}],
                    stages={"invoke": {"approval": "allow-always"}},
                )
            )

        if approval_id:
            granted = self.pending.get(approval_id) or {}
            if granted.get("decision") == "approved" and granted.get("fingerprint") == fingerprint:
                return self._finish(
                    RuntimeDecision(
                        status="ALLOWED",
                        allowed=True,
                        would_execute=True,
                        requires_approval=False,
                        tool=tool,
                        canonical_tool=canonical,
                        scenario=scenario_id,
                        session_id=session,
                        source_label=label,
                        agent_id=runtime_agent,
                        reason="人工审批已通过，允许执行。",
                        approval_id=approval_id,
                        policy_hits=[{"rule_id": "runtime.hitl_approved", "passed": True, "detail": approval_id}],
                        stages={"invoke": {"approval": "approved"}},
                    )
                )

        ifc_tools = set(self.config.get("ifc_tools") or [])
        exec_tools = set(self.config.get("exec_tools") or [])
        supply_tools = set(self.config.get("supply_tools") or [])

        if canonical in ifc_tools:
            siblings = [
                ToolCall(
                    id=str(item.get("id") or f"sib-{index}"),
                    name=self._canonicalize(str(item.get("tool") or item.get("name") or ""), dict(item.get("args") or item.get("arguments") or {}))[0],
                    arguments=self._canonicalize(str(item.get("tool") or item.get("name") or ""), dict(item.get("args") or item.get("arguments") or {}))[1],
                )
                for index, item in enumerate(sibling_calls or [])
            ]
            decision = self.ifc.inspect_call(
                canonical,
                normalized,
                source_label=label,
                session_id=session,
                sibling_calls=siblings or None,
            )
            return self._from_ifc(decision, tool, canonical, scenario_id, session, label, runtime_agent, caller, normalized)

        if canonical in exec_tools:
            report = self.exec_gate.inspect_live(runtime_agent, canonical, normalized, session)
            return self._from_exec(report, tool, canonical, scenario_id, session, label, runtime_agent, caller)

        if canonical in supply_tools:
            path = Path(str(normalized.get("path") or ""))
            if not path.exists():
                return self._finish(
                    RuntimeDecision(
                        status="BLOCKED",
                        allowed=False,
                        would_execute=False,
                        requires_approval=False,
                        tool=tool,
                        canonical_tool=canonical,
                        scenario=scenario_id,
                        session_id=session,
                        source_label=label,
                        agent_id=runtime_agent,
                        reason="安装组件缺少可扫描的本地解包目录。",
                        policy_hits=[{"rule_id": "runtime.package_path", "passed": False, "detail": str(path)}],
                    )
                )
            scanned = self.scanner.scan_package(path)
            blocked = scanned.action == "BLOCK"
            pending = scanned.action == "REVIEW"
            return self._finish(
                RuntimeDecision(
                    status="BLOCKED" if blocked else ("PENDING_APPROVAL" if pending else "ALLOWED"),
                    allowed=scanned.action == "ALLOW",
                    would_execute=scanned.action == "ALLOW",
                    requires_approval=pending,
                    tool=tool,
                    canonical_tool=canonical,
                    scenario=scenario_id,
                    session_id=session,
                    source_label=label,
                    agent_id=runtime_agent,
                    reason=scanned.localization().get("root_detail") or scanned.action,
                    approval_id=self._queue_approval(session, canonical, normalized) if pending else "",
                    policy_hits=[{"rule_id": item.rule_id, "passed": False, "detail": item.detail} for item in scanned.findings],
                    stages={"supply_chain": {"action": scanned.action, "score": scanned.score}},
                )
            )

        return self._finish(
            RuntimeDecision(
                status="BLOCKED",
                allowed=False,
                would_execute=False,
                requires_approval=False,
                tool=tool,
                canonical_tool=canonical,
                scenario=scenario_id,
                session_id=session,
                source_label=label,
                agent_id=runtime_agent,
                reason=f"未登记的工具 `{canonical}`，默认拒绝。",
                policy_hits=[{"rule_id": "runtime.unknown_tool", "passed": False, "detail": canonical}],
            )
        )

    def check_openai_tool_calls(
        self,
        tool_calls: list[dict[str, Any]],
        *,
        scenario: str | None = None,
        session_id: str | None = None,
        source_label: str | None = None,
        agent_id: str | None = None,
    ) -> dict[str, Any]:
        parsed: list[dict[str, Any]] = []
        for item in tool_calls:
            fn = item.get("function") if isinstance(item.get("function"), dict) else item
            name = str((fn or {}).get("name") or item.get("name") or "")
            raw_args = (fn or {}).get("arguments") if fn else item.get("arguments")
            if isinstance(raw_args, str):
                try:
                    arguments = json.loads(raw_args or "{}")
                except json.JSONDecodeError:
                    arguments = {"_raw": raw_args}
            else:
                arguments = dict(raw_args or item.get("args") or {})
            parsed.append({"id": item.get("id"), "tool": name, "args": arguments})
        decisions = [
            self.check(
                tool=str(item["tool"]),
                args=dict(item["args"]),
                scenario=scenario,
                session_id=session_id,
                source_label=source_label,
                agent_id=agent_id,
                sibling_calls=parsed,
                caller="openai",
            )
            for item in parsed
        ]
        allowed = all(item.allowed for item in decisions)
        return {
            "allowed": allowed,
            "decisions": [item.to_dict() for item in decisions],
        }

    def resolve_approval(self, approval_id: str, decision: Literal["approved", "rejected"], note: str = "") -> dict[str, Any]:
        item = self.pending.get(approval_id)
        if not item:
            raise ValueError(f"未找到审批单 {approval_id}")
        if decision not in {"approved", "rejected"}:
            raise ValueError("decision 必须是 approved 或 rejected")
        item["decision"] = decision
        item["note"] = note
        item["decided_at"] = _utc_now()
        if decision == "approved" and _is_allow_always(note):
            self._remember_always(item)
        self._save_pending()
        return dict(item)

    def _from_ifc(
        self,
        decision: IFCDecision,
        tool: str,
        canonical: str,
        scenario: str,
        session: str,
        label: str,
        agent_id: str,
        caller: str,
        args: dict[str, Any],
    ) -> RuntimeDecision:
        pending = decision.status == "PENDING_APPROVAL"
        approval_id = self._queue_approval(session, canonical, args) if pending else ""
        return self._finish(
            RuntimeDecision(
                status=decision.status,
                allowed=decision.status in {"ALLOWED", "SAFE"},
                would_execute=decision.would_execute,
                requires_approval=pending,
                tool=tool,
                canonical_tool=canonical,
                scenario=scenario,
                session_id=session,
                source_label=label,
                agent_id=agent_id,
                reason=decision.reason,
                approval_id=approval_id,
                policy_hits=[asdict(hit) for hit in decision.policy_hits],
                stages={"decide": {"caller": caller, "engine": "ifc"}},
            )
        )

    def _from_exec(
        self,
        report: Any,
        tool: str,
        canonical: str,
        scenario: str,
        session: str,
        label: str,
        agent_id: str,
        caller: str,
    ) -> RuntimeDecision:
        mapping = {"ALLOW": "ALLOWED", "BLOCK": "BLOCKED", "REVIEW": "PENDING_APPROVAL"}
        status = mapping.get(report.action, "BLOCKED")
        pending = status == "PENDING_APPROVAL"
        approval_id = self._queue_approval(session, canonical, report.args) if pending else ""
        return self._finish(
            RuntimeDecision(
                status=status,  # type: ignore[arg-type]
                allowed=status in {"ALLOWED", "SAFE"},
                would_execute=bool(report.would_execute),
                requires_approval=pending,
                tool=tool,
                canonical_tool=canonical,
                scenario=scenario,
                session_id=session,
                source_label=label,
                agent_id=agent_id,
                reason="；".join(f"[{hit.rule_id}] {hit.detail}" for hit in report.hits) or report.action,
                approval_id=approval_id,
                policy_hits=[asdict(hit) for hit in report.hits],
                stages=dict(report.stages or {}) | {"caller": caller},
            )
        )

    def _scenario(self, name: str | None, agent_id: str | None = None) -> tuple[dict[str, Any], str]:
        scenarios = self.config.get("scenarios") or {}
        aliases = {
            str(key).strip().lower(): str(value).strip()
            for key, value in (self.config.get("agent_aliases") or {}).items()
        }
        default = str(self.config.get("default_scenario") or "office")

        def resolve(raw: str | None) -> str:
            key = (raw or "").strip()
            if not key:
                return ""
            if key in scenarios:
                return key
            mapped = aliases.get(key.lower())
            if mapped in scenarios:
                return mapped
            return ""

        key = resolve(name) or resolve(agent_id) or default
        if key not in scenarios:
            key = default if default in scenarios else next(iter(scenarios), "office")
        return dict(scenarios[key]), key

    def _canonicalize(self, tool: str, args: dict[str, Any]) -> tuple[str, dict[str, Any]]:
        aliases = {str(key).lower(): str(value) for key, value in (self.config.get("aliases") or {}).items()}
        name = aliases.get((tool or "").strip().lower(), (tool or "").strip())
        normalized = dict(args)
        for target, sources in (self.config.get("arg_aliases") or {}).items():
            if target in normalized and normalized[target] not in (None, ""):
                continue
            for source in sources:
                if source in normalized and normalized[source] not in (None, ""):
                    normalized[target] = normalized[source]
                    break
        return name, normalized

    def _fingerprint(self, session: str, tool: str, args: dict[str, Any]) -> str:
        return hashlib.sha256(f"{session}|{tool}|{_canon(args)}".encode("utf-8")).hexdigest()

    def _queue_approval(self, session: str, tool: str, args: dict[str, Any]) -> str:
        approval_id = uuid4().hex
        self.pending[approval_id] = {
            "approval_id": approval_id,
            "session_id": session,
            "tool": tool,
            "args": args,
            "fingerprint": self._fingerprint(session, tool, args),
            "decision": "pending",
            "created_at": _utc_now(),
        }
        self._save_pending()
        return approval_id

    def pending_approvals(self) -> list[dict[str, Any]]:
        return [dict(item) for item in self.pending.values() if item.get("decision") == "pending"]

    def _always_granted(self, session: str, tool: str, fingerprint: str) -> bool:
        return any(
            item.get("session_id") == session
            and item.get("tool") == tool
            and item.get("fingerprint") == fingerprint
            for item in self.always
        )

    def _remember_always(self, item: dict[str, Any]) -> None:
        fingerprint = str(item.get("fingerprint") or "")
        session = str(item.get("session_id") or "")
        tool = str(item.get("tool") or "")
        if not fingerprint or self._always_granted(session, tool, fingerprint):
            return
        self.always.append(
            {
                "session_id": session,
                "tool": tool,
                "fingerprint": fingerprint,
                "approval_id": item.get("approval_id") or "",
                "created_at": _utc_now(),
            }
        )

    def _load_pending(self) -> None:
        if not self.pending_path.exists():
            return
        try:
            payload = json.loads(self.pending_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            return
        if not isinstance(payload, dict):
            return
        pending = payload.get("pending") or {}
        if isinstance(pending, dict):
            self.pending = {str(key): dict(value) for key, value in pending.items() if isinstance(value, dict)}
        always = payload.get("always") or []
        if isinstance(always, list):
            self.always = [dict(item) for item in always if isinstance(item, dict)]

    def _save_pending(self) -> None:
        self.pending_path.parent.mkdir(parents=True, exist_ok=True)
        payload = {"pending": self.pending, "always": self.always}
        tmp = self.pending_path.with_name(self.pending_path.name + ".tmp")
        tmp.write_text(_canon(payload), encoding="utf-8")
        tmp.replace(self.pending_path)

    def _append_audit(self, decision: RuntimeDecision) -> None:
        self.audit_path.parent.mkdir(parents=True, exist_ok=True)
        line = _canon(decision.to_dict()) + "\n"
        existing: list[str] = []
        if self.audit_path.exists():
            existing = self.audit_path.read_text(encoding="utf-8").splitlines(keepends=True)
        existing.append(line)
        if len(existing) > self.audit_limit:
            self.audit_path.write_text("".join(existing[-self.audit_limit :]), encoding="utf-8")
            return
        with self.audit_path.open("a", encoding="utf-8") as handle:
            handle.write(line)

    def _finish(self, decision: RuntimeDecision) -> RuntimeDecision:
        decision.event_id = decision.event_id or uuid4().hex
        decision.timestamp = decision.timestamp or _utc_now()
        self._append_audit(decision)
        return decision


def _is_allow_always(note: str) -> bool:
    text = (note or "").strip().lower()
    return text in {"allow-always", "openclaw:allow-always"} or text.endswith(":allow-always")


def load_runtime_audit(limit: int = 80, path: Path | None = None) -> list[dict[str, Any]]:
    target = path or RUNTIME_AUDIT_PATH
    if not target.exists():
        return []
    events: list[dict[str, Any]] = []
    for line in target.read_text(encoding="utf-8").splitlines()[-max(limit, 1) :]:
        text = line.strip()
        if not text:
            continue
        try:
            item = json.loads(text)
        except json.JSONDecodeError:
            continue
        if isinstance(item, dict):
            events.append(item)
    events.reverse()
    return events
