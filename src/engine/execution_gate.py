"""工具调用与任务执行门禁：感知—决策—调用—执行。

控制面逻辑对齐 AgentGate / PDO / TCA / puncture 概念：
属性策略树授权、限制策略 deny-overrides、对象头签名与版本登记、
派生对象继承 RP 并沿 childs 传播。
对象头由 `src.engine.tca.HmacTCA` 签发（独立密钥 HMAC-SHA256），Charm/ABE 未接入。
"""

from __future__ import annotations

import json
from collections import Counter
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Literal
from urllib.parse import urlparse

from src.config import (
    EXECUTION_AUDIT_PATH,
    EXECUTION_HISTORY_PATH,
    EXECUTION_MANIFEST_PATH,
    EXECUTION_POLICY_PATH,
    OUTPUT_DIR,
)
from src.engine.tca import HmacTCA, compute_eta

GateAction = Literal["BLOCK", "REVIEW", "ALLOW"]


def _utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _canon(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def match_tree(node: Any, attrs: set[str]) -> bool:
    if node is None:
        return False
    if isinstance(node, str):
        return node in attrs
    if isinstance(node, dict):
        gate = str(node.get("gate") or "AND").upper()
        children = node.get("children") or node.get("tags") or []
        return _match_gate(gate, [match_tree(child, attrs) if not isinstance(child, str) else child in attrs for child in children])
    if isinstance(node, (list, tuple)) and node:
        gate = str(node[0]).upper()
        if gate in {"AND", "OR"}:
            rest = list(node[1:])
            if len(rest) == 1 and isinstance(rest[0], list):
                rest = rest[0]
            return _match_gate(gate, [match_tree(child, attrs) for child in rest])
        return False
    return False


def _match_gate(gate: str, hits: list[bool]) -> bool:
    if not hits:
        return False
    return all(hits) if gate == "AND" else any(hits)


def rp_matches(rp: dict[str, Any], tags: set[str]) -> bool:
    if not rp:
        return False
    if "tags" in rp:
        gate = str(rp.get("gate") or "OR").upper()
        hits = [item in tags for item in rp.get("tags") or []]
        return _match_gate(gate, hits)
    children = rp.get("children") or []
    gate = str(rp.get("gate") or "OR").upper()
    hits = []
    for child in children:
        if isinstance(child, str):
            hits.append(child in tags)
        elif isinstance(child, dict) and "tag" in child:
            hits.append(str(child["tag"]) in tags)
        else:
            hits.append(rp_matches(child, tags) if isinstance(child, dict) else False)
    return _match_gate(gate, hits)


def _host_of(url: str) -> str:
    text = (url or "").strip()
    if not text:
        return ""
    parsed = urlparse(text if "://" in text else f"https://{text}")
    return (parsed.hostname or "").lower()


def _domain_allowed(host: str, allowed: list[str], denied: list[str]) -> tuple[bool, str]:
    if not host:
        return False, "缺少主机"
    if any(host == item or host.endswith("." + item) for item in denied):
        return False, f"命中拒绝域 {host}"
    if any(host == item or host.endswith("." + item) for item in allowed):
        return True, host
    return False, f"主机不在白名单：{host}"


@dataclass
class PolicyHit:
    rule_id: str
    passed: bool
    detail: str
    stage: str


@dataclass
class TaskObject:
    id: str
    attrs: list[str]
    rp: list[dict[str, Any]]
    meta: dict[str, Any]
    payload: bytes = b""
    head_v: dict[str, Any] | None = None

    def eta(self) -> list[str]:
        return compute_eta(self.payload, self.attrs, self.rp, self.meta)


@dataclass
class Agent:
    id: str
    tree: Any
    tags: list[str]
    sk_bound: bool = False

    def bind_sk(self, tree: Any, tags: list[str]) -> None:
        self.tree = tree
        self.tags = list(tags)
        self.sk_bound = True


class CS:
    def __init__(self) -> None:
        self.objects: dict[str, TaskObject] = {}

    def upload(self, obj: TaskObject) -> None:
        if obj.id in self.objects:
            raise ValueError(f"{obj.id} has exists")
        self.objects[obj.id] = obj

    def get(self, pdo_id: str) -> TaskObject:
        if pdo_id not in self.objects:
            raise ValueError("PDO ID is illegal")
        return self.objects[pdo_id]

    def exists(self, pdo_id: str) -> bool:
        return pdo_id in self.objects

    def try_puncture(self, pdo_id: str, delta_rp: dict[str, Any]) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
        obj = self.get(pdo_id)
        before = list(obj.rp)
        after = before + [delta_rp]
        return before, after

    def puncture(self, pdo_id: str, delta_rp: dict[str, Any], head_v: dict[str, Any]) -> None:
        obj = self.get(pdo_id)
        obj.rp = list(obj.rp) + [delta_rp]
        obj.head_v = head_v


@dataclass
class StepReport:
    tool: str
    kind: str
    args: dict[str, Any]
    action: GateAction
    would_execute: bool
    hits: list[PolicyHit]
    stages: dict[str, Any]
    object_id: str = ""
    attrs: list[str] = field(default_factory=list)


@dataclass
class TaskReport:
    task_id: str
    agent_id: str
    title: str
    action: GateAction
    expected_label: str = "unknown"
    expected_action: str = ""
    correct: bool | None = None
    steps: list[StepReport] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["localization"] = self.localization()
        payload["reproduction"] = {
            "task_id": self.task_id,
            "replay_api": f"/api/execution/reproduce/{self.task_id}",
        }
        return payload

    def localization(self) -> dict[str, Any]:
        blocked = next((item for item in self.steps if item.action == "BLOCK"), None)
        focus = blocked or (self.steps[-1] if self.steps else None)
        failed = [hit.rule_id for step in self.steps for hit in step.hits if not hit.passed]
        return {
            "root_cause": (failed[0] if failed else ""),
            "failed_rules": failed,
            "blocked_tool": focus.tool if focus and focus.action == "BLOCK" else "",
            "stages": focus.stages if focus else {},
            "action": self.action,
        }


class AgentGate:
    """对齐 copy.entity.AgentGate 的访问 / 签发 / 穿刺 / 派生协议。"""

    def __init__(self, policy_path: Path | None = None) -> None:
        self.policy_path = policy_path or EXECUTION_POLICY_PATH
        self.policy = json.loads(self.policy_path.read_text(encoding="utf-8"))
        self.tca = HmacTCA(str(self.policy.get("tca_id") or "TCA0"))
        self.cs = CS()
        self.agents: dict[str, Agent] = {}
        self._seq = 0
        self.live_sessions: dict[str, StepReport] = {}
        self._bootstrap_agents()

    def _object_bind(self, obj: TaskObject) -> dict[str, Any]:
        meta = obj.meta or {}
        return {
            "agent_id": str(meta.get("agent_id") or ""),
            "session_id": str(meta.get("session_id") or ""),
            "tool": str(meta.get("tool") or ""),
            "kind": str(meta.get("kind") or ""),
            "g": str(meta.get("g") or "governed"),
        }

    def _sign_object(self, obj: TaskObject, version: int) -> dict[str, Any]:
        return self.tca.sign_head(obj.id, version, obj.eta(), bind=self._object_bind(obj))

    def _bootstrap_agents(self) -> None:
        for agent_id, spec in (self.policy.get("agents") or {}).items():
            agent = Agent(id=agent_id, tree=spec.get("tree"), tags=list(spec.get("tags") or []))
            self.create_agent(agent)
            self.issue_credentials(agent, spec.get("tree"), list(spec.get("tags") or []))

    def create_agent(self, agent: Agent) -> None:
        if agent.id in self.agents:
            raise ValueError(f"Agent {agent.id} already exists")
        self.agents[agent.id] = agent

    def issue_credentials(self, agent: Agent, tree: Any, tags: list[str]) -> None:
        agent.bind_sk(tree, tags)

    def get_agent(self, agent_id: str) -> Agent:
        if agent_id not in self.agents:
            raise ValueError("Agent ID is illegal")
        return self.agents[agent_id]

    def upload_pdo(self, obj: TaskObject) -> TaskObject:
        obj.attrs = sorted(set(obj.attrs))
        obj.meta.setdefault("childs", [])
        obj.meta.setdefault("g", "governed")
        head = self._sign_object(obj, 0)
        obj.head_v = head
        self.cs.upload(obj)
        self.tca.register_version(obj.id, 0)
        return obj

    def perceive(self, tool: str, args: dict[str, Any]) -> dict[str, Any]:
        spec = (self.policy.get("tools") or {}).get(tool)
        if not spec:
            return {"kind": "unknown", "tool": tool, "attrs": [], "approval": False, "args": args}
        kind = str(spec["kind"])
        attrs: list[str] = []
        if kind == "file":
            path = str(args.get("path") or "")
            class_map = (self.policy.get("file") or {}).get("class_by_prefix") or {}
            for prefix, extra in class_map.items():
                if path == prefix or path.startswith(str(prefix).rstrip("/") + "/"):
                    attrs.extend(extra)
                    break
            if tool == "write_file" and "file.write" not in attrs:
                attrs.append("file.write")
            if tool == "delete_file" and "file.delete" not in attrs:
                attrs.append("file.delete")
            if tool == "read_file" and "file.read" not in attrs:
                attrs.append("file.read")
        elif kind == "cmd":
            binary = str(args.get("cmd") or "").strip().split(" ", 1)[0]
            allowed = set((self.policy.get("cmd") or {}).get("allowed_binaries") or [])
            attrs.extend(["dept.ops", "cmd.shell"] if binary in allowed else ["cmd.shell", "class.external"])
        elif kind == "browser":
            host = _host_of(str(args.get("url") or ""))
            allowed = list((self.policy.get("browser") or {}).get("allowed_domains") or [])
            ok, _ = _domain_allowed(host, allowed, [])
            attrs.extend(["dept.office", "class.public", "browser.access"] if ok else ["class.external", "browser.access"])
        elif kind == "api":
            host = _host_of(str(args.get("url") or ""))
            allowed = list((self.policy.get("api") or {}).get("allowed_hosts") or [])
            ok, _ = _domain_allowed(host, allowed, [])
            attrs.extend(["dept.office", "class.internal", "api.internal"] if ok else ["class.external", "api.call"])
        return {
            "kind": kind,
            "tool": tool,
            "attrs": sorted(set(attrs)),
            "approval": bool(spec.get("approval")),
            "args": args,
        }

    def _param_hits(self, kind: str, tool: str, args: dict[str, Any]) -> list[PolicyHit]:
        hits: list[PolicyHit] = []
        if kind == "file":
            path = str(args.get("path") or "")
            denied = list((self.policy.get("file") or {}).get("denied_prefixes") or [])
            allowed = list((self.policy.get("file") or {}).get("allowed_prefixes") or [])
            if any(path == item or path.startswith(item.rstrip("/") + "/") for item in denied):
                hits.append(PolicyHit("exec.file_denied_path", False, path, "decide"))
            elif any(path == item or path.startswith(item.rstrip("/") + "/") for item in allowed):
                hits.append(PolicyHit("exec.file_allowed_path", True, path, "decide"))
            else:
                hits.append(PolicyHit("exec.file_unlisted_path", False, path or "(empty)", "decide"))
        elif kind == "cmd":
            binary = str(args.get("cmd") or "").strip().split(" ", 1)[0]
            denied = set((self.policy.get("cmd") or {}).get("denied_binaries") or [])
            allowed = set((self.policy.get("cmd") or {}).get("allowed_binaries") or [])
            if binary in denied:
                hits.append(PolicyHit("exec.cmd_denied", False, binary, "decide"))
            elif binary in allowed:
                hits.append(PolicyHit("exec.cmd_allowed", True, binary, "decide"))
            else:
                hits.append(PolicyHit("exec.cmd_unlisted", False, binary or "(empty)", "decide"))
        elif kind == "browser":
            cfg = self.policy.get("browser") or {}
            ok, detail = _domain_allowed(_host_of(str(args.get("url") or "")), list(cfg.get("allowed_domains") or []), list(cfg.get("denied_domains") or []))
            hits.append(PolicyHit("exec.browser_domain", ok, detail, "decide"))
        elif kind == "api":
            cfg = self.policy.get("api") or {}
            ok, detail = _domain_allowed(_host_of(str(args.get("url") or "")), list(cfg.get("allowed_hosts") or []), list(cfg.get("denied_hosts") or []))
            hits.append(PolicyHit("exec.api_host", ok, detail, "decide"))
        else:
            hits.append(PolicyHit("exec.unknown_tool", False, tool, "perceive"))
        return hits

    def _need_chain_puncture(self, previous: StepReport | None, perceived: dict[str, Any]) -> bool:
        if previous is None or previous.action == "BLOCK":
            return False
        cfg = self.policy.get("chain_puncture") or {}
        if previous.kind not in set(cfg.get("from_kinds") or []):
            return False
        if perceived["kind"] not in set(cfg.get("to_kinds") or []):
            return False
        required = set(cfg.get("require_class") or [])
        return bool(required.intersection(previous.attrs))

    def puncture(self, delta_rp: dict[str, Any], pdo_id: str) -> None:
        obj = self.cs.get(pdo_id)
        if (obj.meta or {}).get("g") == "released":
            return
        before, after = self.cs.try_puncture(pdo_id, delta_rp)
        if not self.tca.verify_puncture(before, delta_rp, after):
            raise ValueError("TCA puncture verification failed")
        version = int((obj.head_v or {}).get("v") or 0) + 1
        obj.rp = after
        head = self._sign_object(obj, version)
        obj.rp = before
        self.cs.puncture(pdo_id, delta_rp, head)
        self.tca.register_version(pdo_id, version)
        for child_id in list((obj.meta or {}).get("childs") or []):
            if self.cs.exists(child_id):
                self.puncture(delta_rp, child_id)

    def drive_pdo(self, parent_id: str, child: TaskObject) -> TaskObject:
        parent = self.cs.get(parent_id)
        child.attrs = sorted(set(list(parent.attrs) + list(child.attrs)))
        child.rp = list(parent.rp) + list(child.rp)
        child.meta.setdefault("childs", [])
        child.meta.setdefault("g", "governed")
        self.upload_pdo(child)
        parent.meta["childs"] = list(parent.meta.get("childs") or []) + [child.id]
        version = int((parent.head_v or {}).get("v") or 0) + 1
        parent.head_v = self._sign_object(parent, version)
        self.tca.register_version(parent.id, version)
        return child

    def _access_object(self, agent: Agent, obj: TaskObject) -> list[PolicyHit]:
        hits: list[PolicyHit] = []
        if obj.head_v is None:
            hits.append(PolicyHit("tca.head_missing", False, obj.id, "execute"))
            return hits
        if obj.head_v.get("v") != self.tca.currentversion.get(obj.id):
            hits.append(PolicyHit("tca.version", False, f"{obj.head_v.get('v')} != {self.tca.currentversion.get(obj.id)}", "execute"))
            return hits
        if not self.tca.tca_verify(obj.head_v):
            hits.append(PolicyHit("tca.signature", False, obj.id, "execute"))
            return hits
        if obj.head_v.get("eta") != obj.eta():
            hits.append(PolicyHit("tca.eta", False, obj.id, "execute"))
            return hits
        expected_bind = self._object_bind(obj)
        if dict(obj.head_v.get("bind") or {}) != expected_bind:
            hits.append(PolicyHit("tca.bind", False, obj.id, "execute"))
            return hits
        hits.append(
            PolicyHit(
                "tca.object_head",
                True,
                f"v={obj.head_v.get('v')} kid={obj.head_v.get('kid')}",
                "execute",
            )
        )
        tree_ok = match_tree(agent.tree, set(obj.attrs))
        hits.append(PolicyHit("exec.access_tree", tree_ok, f"{agent.id} vs {obj.attrs}", "decide"))
        punctured = [item for item in obj.rp if rp_matches(item, set(agent.tags))]
        hits.append(
            PolicyHit(
                "exec.restriction_policy",
                not punctured,
                "deny-overrides" if punctured else "no matching RP",
                "decide",
            )
        )
        return hits

    def evaluate_step(
        self,
        agent: Agent,
        tool: str,
        args: dict[str, Any],
        *,
        parent_id: str | None = None,
        previous: StepReport | None = None,
        session_id: str = "",
    ) -> StepReport:
        perceived = self.perceive(tool, args)
        hits = [PolicyHit("exec.perceive", perceived["kind"] != "unknown", perceived["kind"], "perceive")]
        hits.extend(self._param_hits(perceived["kind"], tool, args))

        self._seq += 1
        obj = TaskObject(
            id=f"task-{agent.id}-{self._seq}",
            attrs=list(perceived["attrs"]),
            rp=[],
            meta={
                "g": "governed",
                "childs": [],
                "tool": tool,
                "kind": perceived["kind"],
                "agent_id": agent.id,
                "session_id": session_id or "",
            },
            payload=_canon({"tool": tool, "args": args, "session_id": session_id or ""}),
        )
        if parent_id:
            obj = self.drive_pdo(parent_id, obj)
        else:
            self.upload_pdo(obj)

        chain_applied = False
        if self._need_chain_puncture(previous, perceived):
            delta = dict((self.policy.get("chain_puncture") or {}).get("delta_rp") or {})
            self.puncture(delta, obj.id)
            chain_applied = True
            hits.append(PolicyHit("exec.chain_puncture", True, "已对派生对象追加限制策略", "invoke"))

        hits.extend(self._access_object(agent, obj))
        failed = [item for item in hits if not item.passed]
        approval = bool(perceived["approval"]) and not failed
        if approval:
            hits.append(PolicyHit("tca.approval_required", True, tool, "invoke"))

        if failed:
            action: GateAction = "BLOCK"
        elif approval:
            action = "REVIEW"
        else:
            action = "ALLOW"

        stages = {
            "perceive": {"kind": perceived["kind"], "attrs": perceived["attrs"]},
            "decide": {
                "tree": match_tree(agent.tree, set(obj.attrs)),
                "rp": [item for item in obj.rp],
                "param_failed": [item.rule_id for item in hits if item.stage == "decide" and not item.passed],
            },
            "invoke": {"approval": approval, "chain_puncture": chain_applied},
            "execute": {
                "would_execute": action == "ALLOW",
                "object_id": obj.id,
                "version": (obj.head_v or {}).get("v"),
                "kid": (obj.head_v or {}).get("kid"),
                "alg": (obj.head_v or {}).get("alg"),
            },
        }
        return StepReport(
            tool=tool,
            kind=perceived["kind"],
            args=dict(args),
            action=action,
            would_execute=action == "ALLOW",
            hits=hits,
            stages=stages,
            object_id=obj.id,
            attrs=list(obj.attrs),
        )

    def inspect_live(self, agent_id: str, tool: str, args: dict[str, Any], session_id: str) -> StepReport:
        previous = self.live_sessions.get(session_id)
        parent_id = previous.object_id if previous and previous.action != "BLOCK" else None
        report = self.evaluate_step(
            self.get_agent(agent_id),
            tool,
            args,
            parent_id=parent_id,
            previous=previous,
            session_id=session_id,
        )
        self.live_sessions[session_id] = report
        return report

    def evaluate_task(
        self,
        task_id: str,
        agent_id: str,
        steps: list[dict[str, Any]],
        *,
        title: str = "",
        expected_label: str = "unknown",
        expected_action: str = "",
    ) -> TaskReport:
        agent = self.get_agent(agent_id)
        reports: list[StepReport] = []
        parent_id: str | None = None
        previous: StepReport | None = None
        for step in steps:
            report = self.evaluate_step(
                agent,
                str(step.get("tool") or ""),
                dict(step.get("args") or {}),
                parent_id=parent_id,
                previous=previous,
            )
            reports.append(report)
            parent_id = report.object_id
            previous = report
            if report.action == "BLOCK":
                break
        if any(item.action == "BLOCK" for item in reports):
            action: GateAction = "BLOCK"
        elif any(item.action == "REVIEW" for item in reports):
            action = "REVIEW"
        else:
            action = "ALLOW"
        correct: bool | None = None
        if expected_action:
            correct = action == expected_action
        return TaskReport(
            task_id=task_id,
            agent_id=agent_id,
            title=title,
            action=action,
            expected_label=expected_label,
            expected_action=expected_action,
            correct=correct,
            steps=reports,
        )

    def evaluate_corpus(
        self,
        manifest_path: Path | None = None,
        output_path: Path | None = EXECUTION_AUDIT_PATH,
    ) -> dict[str, Any]:
        manifest = json.loads((manifest_path or EXECUTION_MANIFEST_PATH).read_text(encoding="utf-8"))
        reports = [
            self.evaluate_task(
                str(item["id"]),
                str(item["agent_id"]),
                list(item.get("steps") or []),
                title=str(item.get("title") or ""),
                expected_label=str(item.get("expected_label") or "unknown"),
                expected_action=str(item.get("expected_action") or ""),
            )
            for item in (manifest.get("tasks") or [])
        ]
        bundle = self._bundle(reports, str(manifest.get("dataset_name") or "execution-gate-bench"))
        if output_path is not None:
            output_path.parent.mkdir(parents=True, exist_ok=True)
            output_path.write_text(json.dumps(bundle, ensure_ascii=False, indent=2), encoding="utf-8")
            if output_path.resolve() == EXECUTION_AUDIT_PATH.resolve():
                append_execution_history(bundle.get("meta") or {})
        return bundle

    def reproduce_task(self, task_id: str) -> dict[str, Any]:
        manifest = json.loads(EXECUTION_MANIFEST_PATH.read_text(encoding="utf-8"))
        item = next((row for row in (manifest.get("tasks") or []) if str(row.get("id")) == task_id), None)
        if not item:
            raise ValueError(f"未找到执行样本 {task_id}")
        gate = AgentGate(self.policy_path)
        report = gate.evaluate_task(
            task_id,
            str(item["agent_id"]),
            list(item.get("steps") or []),
            title=str(item.get("title") or ""),
            expected_label=str(item.get("expected_label") or "unknown"),
            expected_action=str(item.get("expected_action") or ""),
        )
        prior = next(
            (row for row in (load_execution_audit().get("tasks") or []) if row.get("task_id") == task_id),
            None,
        )
        previous_action = str((prior or {}).get("action") or "")
        return {
            "replay_from": "policy-resimulate",
            "previous_action": previous_action,
            "status_changed": bool(previous_action) and previous_action != report.action,
            "report": report.to_dict(),
        }

    def _bundle(self, reports: list[TaskReport], dataset_name: str) -> dict[str, Any]:
        malicious = [item for item in reports if item.expected_label == "malicious"]
        benign = [item for item in reports if item.expected_label == "benign"]
        malicious_blocked = sum(item.action == "BLOCK" for item in malicious)
        malicious_detected = sum(item.action in {"BLOCK", "REVIEW"} for item in malicious)
        benign_blocked = sum(item.action == "BLOCK" for item in benign)
        labeled = sum(item.correct is not None for item in reports)
        correct = sum(item.correct is True for item in reports if item.correct is not None)
        status_counts = Counter(item.action for item in reports)
        metrics = {
            "malicious_block_rate": round(malicious_blocked / len(malicious), 4) if malicious else 0.0,
            "malicious_detection_rate": round(malicious_detected / len(malicious), 4) if malicious else 0.0,
            "benign_block_fpr": round(benign_blocked / len(benign), 4) if benign else 0.0,
            "expected_action_accuracy": round(correct / labeled, 4) if labeled else 0.0,
            "review_rate": round(status_counts["REVIEW"] / len(reports), 4) if reports else 0.0,
        }
        meta = {
            "generated_at": _utc_now(),
            "dataset_name": dataset_name,
            "analysis_mode": "perceive-decide-invoke-execute",
            "total_tasks": len(reports),
            "malicious_tasks": len(malicious),
            "benign_tasks": len(benign),
            "status_counts": dict(status_counts),
            "metrics": metrics,
            "method_sources": ["AgentGate/PDO/TCA puncture protocol"],
        }
        missed = [item.task_id for item in malicious if item.action == "ALLOW"]
        false_block = [item.task_id for item in benign if item.action == "BLOCK"]
        actions: list[str] = []
        if missed:
            actions.append(f"恶意任务被放行：{', '.join(missed)}。核对访问树、限制策略与任务链穿刺。")
        elif metrics["malicious_detection_rate"] >= 1:
            actions.append("恶意任务均已检出。下一轮补充未知工具或更长任务链。")
        if false_block:
            actions.append(f"正常任务被误拦：{', '.join(false_block)}。核对待信路径/域名与审批门槛。")
        meta["optimization"] = {
            "missed_malicious": missed,
            "false_blocked": false_block,
            "next_actions": actions,
        }
        return {"meta": meta, "tasks": [item.to_dict() for item in reports]}


def load_execution_audit(path: Path | None = None) -> dict[str, Any]:
    target = path or EXECUTION_AUDIT_PATH
    if not target.exists():
        return {"meta": {}, "tasks": []}
    payload = json.loads(target.read_text(encoding="utf-8"))
    payload.setdefault("meta", {})
    payload.setdefault("tasks", [])
    return payload


def load_execution_history() -> list[dict[str, Any]]:
    if not EXECUTION_HISTORY_PATH.exists():
        return []
    try:
        payload = json.loads(EXECUTION_HISTORY_PATH.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return []
    return payload if isinstance(payload, list) else []


def append_execution_history(meta: dict[str, Any]) -> None:
    snapshot = {
        "generated_at": meta.get("generated_at") or "",
        "metrics": dict(meta.get("metrics") or {}),
        "status_counts": dict(meta.get("status_counts") or {}),
        "malicious_tasks": meta.get("malicious_tasks"),
        "benign_tasks": meta.get("benign_tasks"),
    }
    history = load_execution_history()
    if history and history[-1].get("generated_at") == snapshot["generated_at"]:
        history[-1] = snapshot
    else:
        history.append(snapshot)
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    EXECUTION_HISTORY_PATH.write_text(
        json.dumps(history[-20:], ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
