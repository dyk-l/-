"""FastAPI：策略引擎与评测 API。界面在 OpenClaw 插件里，不提供独立看板。"""

from __future__ import annotations

import hmac
from typing import Any, Literal

from fastapi import Depends, FastAPI, Header, HTTPException, Query
from pydantic import BaseModel

from src import __version__
from src.config import (
    AUDIT_LOG_PATH,
    EXECUTION_AUDIT_PATH,
    RUNTIME_AUDIT_PATH,
    SUPPLY_CHAIN_AUDIT_PATH,
    policy_auth_disabled,
    policy_token,
    public_llm_settings,
)
from src.data.llm import LLMClient
from src.engine.benchmark import BenchmarkEngine
from src.engine.execution_gate import (
    AgentGate,
    load_execution_audit,
    load_execution_history,
)
from src.engine.runtime import RuntimePolicyBroker
from src.engine.supply_chain import (
    SupplyChainScanner,
    load_supply_chain_audit,
    load_supply_chain_history,
)
from src.engine.trace import export_evidence, query_evidence

app = FastAPI(title="政企智能体安全评测与运行时门禁", version=__version__)


class EvalRequest(BaseModel):
    mode: Literal["mock", "api"] | None = None
    api_key: str | None = None
    base_url: str | None = None
    model: str | None = None


class PolicyCheckIn(BaseModel):
    tool: str | None = None
    name: str | None = None
    action: str | None = None
    args: dict[str, Any] | None = None
    sessionKey: str | None = None
    session_id: str | None = None
    agentId: str | None = None
    agent_id: str | None = None
    scenario: str | None = None
    source_label: str | None = None
    approval_id: str | None = None
    idempotencyKey: str | None = None
    tool_calls: list[dict[str, Any]] | None = None


class RuntimeApprovalIn(BaseModel):
    decision: Literal["approved", "rejected"]
    note: str = ""


class OpenClawHookIn(BaseModel):
    toolName: str | None = None
    tool: str | None = None
    name: str | None = None
    params: dict[str, Any] | None = None
    args: dict[str, Any] | None = None
    sessionKey: str | None = None
    sessionId: str | None = None
    session_id: str | None = None
    agentId: str | None = None
    agent_id: str | None = None
    scenario: str | None = None
    source_label: str | None = None
    approval_id: str | None = None
    path: str | None = None
    stagedPath: str | None = None
    sourcePath: str | None = None


_runtime: RuntimePolicyBroker | None = None


def require_policy_token(authorization: str | None = Header(default=None)) -> None:
    if policy_auth_disabled():
        return
    expected = policy_token()
    if not expected:
        raise HTTPException(status_code=503, detail="策略令牌未就绪")
    scheme, _, token = (authorization or "").partition(" ")
    provided = token.strip() if scheme.lower() == "bearer" else ""
    if not provided or len(provided) != len(expected) or not hmac.compare_digest(provided, expected):
        raise HTTPException(status_code=401, detail="需要有效的 Bearer token")


_POLICY_AUTH = [Depends(require_policy_token)]


def runtime_broker() -> RuntimePolicyBroker:
    global _runtime
    if _runtime is None:
        _runtime = RuntimePolicyBroker()
    return _runtime


@app.get("/api/health")
def health() -> dict[str, Any]:
    return {
        "ok": True,
        "version": __version__,
        "audit_exists": AUDIT_LOG_PATH.exists(),
        "supply_chain_audit_exists": SUPPLY_CHAIN_AUDIT_PATH.exists(),
        "execution_audit_exists": EXECUTION_AUDIT_PATH.exists(),
        "runtime_audit_exists": RUNTIME_AUDIT_PATH.exists(),
        "runtime": True,
        "policy_token_required": not policy_auth_disabled(),
        "policy_auth_disabled": policy_auth_disabled(),
    }


@app.post("/api/eval")
def run_eval(payload: EvalRequest) -> dict[str, Any]:
    client = LLMClient(
        mode=payload.mode,
        api_key=payload.api_key if payload.api_key else None,
        base_url=payload.base_url or None,
        model=payload.model or None,
        strict=(payload.mode or public_llm_settings()["mode"]) == "api",
    )
    if client.mode == "api" and not client.api_key:
        raise HTTPException(status_code=400, detail="尚未配置 API Key，请在请求体或 .env 中设置 LLM_API_KEY")
    try:
        engine = BenchmarkEngine(llm=client)
        result = engine.run()
    except Exception as exc:  # noqa: BLE001
        if client.mode == "api":
            raise HTTPException(status_code=502, detail=f"真实 API 调用失败：{exc}") from exc
        raise
    return {"ok": True, "meta": result.meta, "audit_path": result.audit_path, "llm": public_llm_settings()}


@app.post("/api/eval/rescore")
def rescore_eval() -> dict[str, Any]:
    try:
        result = BenchmarkEngine().rescore_from_audit()
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return {"ok": True, "meta": result.meta, "audit_path": result.audit_path, "llm": public_llm_settings()}


@app.post("/api/reproduce/{sample_id}")
def reproduce(sample_id: str) -> dict[str, Any]:
    try:
        payload = BenchmarkEngine().reproduce_sample(sample_id)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    return {"ok": True, **payload}


@app.get("/api/supply-chain")
def supply_chain_overview() -> dict[str, Any]:
    bundle = load_supply_chain_audit()
    return {
        "meta": bundle.get("meta") or {},
        "packages": bundle.get("packages") or [],
        "history": load_supply_chain_history(),
        "has_audit": bool(bundle.get("packages")),
    }


@app.post("/api/supply-chain/eval")
def run_supply_chain_eval() -> dict[str, Any]:
    bundle = SupplyChainScanner().scan_corpus()
    return {
        "ok": True,
        "meta": bundle.get("meta") or {},
        "audit_path": str(SUPPLY_CHAIN_AUDIT_PATH),
        "package_count": len(bundle.get("packages") or []),
    }


@app.post("/api/supply-chain/reproduce/{package_id}")
def reproduce_supply_chain(package_id: str) -> dict[str, Any]:
    try:
        payload = SupplyChainScanner().reproduce_package(package_id)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    return {"ok": True, **payload}


@app.get("/api/execution")
def execution_overview() -> dict[str, Any]:
    bundle = load_execution_audit()
    return {
        "meta": bundle.get("meta") or {},
        "tasks": bundle.get("tasks") or [],
        "history": load_execution_history(),
        "has_audit": bool(bundle.get("tasks")),
    }


@app.post("/api/execution/eval")
def run_execution_eval() -> dict[str, Any]:
    bundle = AgentGate().evaluate_corpus()
    return {
        "ok": True,
        "meta": bundle.get("meta") or {},
        "audit_path": str(EXECUTION_AUDIT_PATH),
        "task_count": len(bundle.get("tasks") or []),
    }


@app.post("/api/execution/reproduce/{task_id}")
def reproduce_execution(task_id: str) -> dict[str, Any]:
    try:
        payload = AgentGate().reproduce_task(task_id)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    return {"ok": True, **payload}


def _run_policy_check(payload: PolicyCheckIn, caller: str):
    if payload.tool_calls:
        return runtime_broker().check_openai_tool_calls(
            payload.tool_calls,
            scenario=payload.scenario,
            session_id=payload.session_id or payload.sessionKey,
            source_label=payload.source_label,
            agent_id=payload.agent_id or payload.agentId,
        )
    tool = (payload.name or payload.tool or "").strip()
    if not tool:
        raise HTTPException(status_code=400, detail="缺少 tool / name")
    args = dict(payload.args or {})
    if payload.action and "action" not in args:
        args["action"] = payload.action
    return runtime_broker().check(
        tool=tool,
        args=args,
        scenario=payload.scenario,
        session_id=payload.session_id or payload.sessionKey or payload.idempotencyKey,
        source_label=payload.source_label,
        agent_id=payload.agent_id or payload.agentId,
        approval_id=payload.approval_id or "",
        caller=caller,
    )


@app.get("/v1/policy/scenarios", dependencies=_POLICY_AUTH)
def policy_scenarios() -> dict[str, Any]:
    return runtime_broker().scenarios()


@app.post("/v1/policy/check", dependencies=_POLICY_AUTH)
def policy_check(payload: PolicyCheckIn) -> dict[str, Any]:
    result = _run_policy_check(payload, "generic")
    if isinstance(result, dict):
        return {"ok": True, **result}
    return {"ok": True, **result.to_dict()}


def _openclaw_hook_check(payload: OpenClawHookIn, *, tool_override: str | None = None, for_install: bool = False):
    tool = (tool_override or payload.toolName or payload.name or payload.tool or "").strip()
    if not tool:
        raise HTTPException(status_code=400, detail="缺少 toolName")
    args = dict(payload.params or payload.args or {})
    if for_install:
        path = payload.stagedPath or payload.sourcePath or payload.path or args.get("path") or args.get("dir") or ""
        args = {"path": str(path)}
        tool = "install_plugin"
    result = runtime_broker().check(
        tool=tool,
        args=args,
        scenario=payload.scenario,
        session_id=payload.session_id or payload.sessionId or payload.sessionKey,
        source_label=payload.source_label,
        agent_id=payload.agent_id or payload.agentId,
        approval_id=payload.approval_id or "",
        caller="openclaw-plugin",
    )
    return result.openclaw_plugin_payload()


@app.post("/v1/policy/openclaw/before-tool-call", dependencies=_POLICY_AUTH)
def openclaw_before_tool_call(payload: OpenClawHookIn) -> dict[str, Any]:
    return _openclaw_hook_check(payload)


@app.post("/v1/policy/openclaw/before-install", dependencies=_POLICY_AUTH)
def openclaw_before_install(payload: OpenClawHookIn) -> dict[str, Any]:
    return _openclaw_hook_check(payload, tool_override="install_plugin", for_install=True)


@app.post("/v1/policy/approvals/{approval_id}", dependencies=_POLICY_AUTH)
def policy_approve(approval_id: str, payload: RuntimeApprovalIn) -> dict[str, Any]:
    try:
        saved = runtime_broker().resolve_approval(approval_id, payload.decision, payload.note)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    return {"ok": True, "approval": saved}


@app.get("/v1/policy/trace", dependencies=_POLICY_AUTH)
def policy_trace(
    q: str = Query("", description="事件 ID / 会话 / 工具 / 样本 / pending / export"),
    limit: int = Query(8, ge=1, le=20),
) -> dict[str, Any]:
    key = q.strip().lower()
    if key in {"pending", "待审", "审批"}:
        pending = runtime_broker().pending_approvals()
        if not pending:
            return {"ok": True, "query": q, "count": 0, "text": "当前没有待审批单。", "items": []}
        lines = ["## 待审批"]
        for item in pending:
            lines.append(
                f"- `{item.get('tool')}`　会话 `{item.get('session_id')}`　"
                f"审批单 `{item.get('approval_id')}`\n"
                f"  查询：`/guard {item.get('session_id')}`"
            )
        return {"ok": True, "query": q, "count": len(pending), "text": "\n".join(lines), "items": pending}
    if key == "export" or key.startswith("export ") or key.startswith("导出"):
        target = q.strip()
        for prefix in ("export", "导出"):
            if target.lower().startswith(prefix):
                target = target[len(prefix) :].strip()
                break
        return export_evidence(target, fmt="both")
    return query_evidence(q, limit=limit)


@app.get("/v1/policy/export", dependencies=_POLICY_AUTH)
def policy_export(
    q: str = Query("", description="事件 ID / 会话 / 工具 / 样本；空则导出最近运行时记录"),
    format: str = Query("both", description="json | md | both"),
) -> dict[str, Any]:
    fmt = (format or "both").strip().lower()
    if fmt in {"markdown", "md"}:
        fmt = "md"
    if fmt not in {"json", "md", "both"}:
        raise HTTPException(status_code=400, detail="format 必须是 json、md 或 both")
    return export_evidence(q, fmt=fmt)  # type: ignore[arg-type]


@app.get("/v1/policy/trace/{event_id}", dependencies=_POLICY_AUTH)
def policy_trace_one(event_id: str) -> dict[str, Any]:
    return query_evidence(event_id, limit=8)


@app.get("/")
def index() -> dict[str, Any]:
    return {
        "ok": True,
        "name": "政企智能体策略引擎",
        "version": __version__,
        "ui": "openclaw-plugin",
        "plugin": "gov-agent-guard",
        "commands": ["/guard", "/guard <id>", "/guard export", "/guard export <id>"],
        "hooks": ["/v1/policy/openclaw/before-tool-call", "/v1/policy/openclaw/before-install"],
        "trace": "/v1/policy/trace",
        "export": "/v1/policy/export",
    }
