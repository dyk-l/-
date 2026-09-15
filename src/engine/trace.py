"""审计溯源查询：给 OpenClaw `/guard` 命令拼证据链文本；支持导出 JSON / Markdown。"""

from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Literal
from uuid import uuid4

from src.config import (
    AUDIT_LOG_PATH,
    EVIDENCE_EXPORT_DIR,
    EXECUTION_AUDIT_PATH,
    SUPPLY_CHAIN_AUDIT_PATH,
)
from src.engine.runtime import load_runtime_audit

STATUS_LABELS = {
    "BLOCKED": "已拦截",
    "ALLOWED": "已放行",
    "SAFE": "安全",
    "PENDING_APPROVAL": "待审批",
    "BLOCK": "拦截",
    "REVIEW": "待审",
    "ALLOW": "放行",
}


def _clip(text: str, limit: int) -> str:
    compact = " ".join(str(text or "").split())
    if len(compact) <= limit:
        return compact
    return compact[: max(limit - 1, 0)] + "…"


def _label(value: Any) -> str:
    key = str(value or "")
    return STATUS_LABELS.get(key, key or "无")


def _match(query: str, *parts: Any) -> bool:
    needle = query.strip().lower()
    if not needle:
        return True
    hay = " ".join(str(part or "") for part in parts).lower()
    return needle in hay


def _hit_lines(hits: list[dict[str, Any]], *, limit: int = 8) -> list[str]:
    lines: list[str] = []
    for item in hits[:limit]:
        mark = "过" if item.get("passed") else "未过"
        rule = item.get("rule_id") or "rule"
        detail = _clip(str(item.get("detail") or ""), 80)
        lines.append(f"- [{mark}] {rule}: {detail}")
    return lines


def format_runtime_card(event: dict[str, Any]) -> str:
    hits = event.get("policy_hits") or []
    failed = [item for item in hits if not item.get("passed")]
    lines = [
        f"## 证据链 `{_clip(str(event.get('event_id') or ''), 12)}`",
        f"- 判定：{_label(event.get('status'))}",
        f"- 场景：{event.get('scenario') or '无'}　会话：{event.get('session_id') or '无'}",
        f"- 工具：{event.get('tool') or '无'} → `{event.get('canonical_tool') or event.get('tool') or '无'}`",
        f"- 来源：{event.get('source_label') or '无'}　智能体：{event.get('agent_id') or '无'}",
        f"- 原因：{_clip(str(event.get('reason') or ''), 240)}",
    ]
    if event.get("approval_id"):
        lines.append(f"- 审批单：`{event.get('approval_id')}`")
    if failed:
        lines.append("失败规则：")
        lines.extend(_hit_lines(failed))
    elif hits:
        lines.append("规则命中：")
        lines.extend(_hit_lines(hits, limit=5))
    return "\n".join(lines)


def format_eval_card(event: dict[str, Any]) -> str:
    loc = event.get("localization") or {}
    hits = event.get("policy_hits") or []
    lines = [
        f"## 评测样本 `{event.get('sample_id') or event.get('event_id')}`",
        f"- 判定：{_label(event.get('status'))}　类型：{event.get('split') or '无'}",
        f"- 工具：{event.get('target_tool') or '无'}　来源：{event.get('source_label') or '无'}",
        f"- 问题：{_clip(str(loc.get('root_cause') or event.get('reason') or ''), 200)}",
    ]
    failed = loc.get("failed_rules") or [item.get("rule_id") for item in hits if not item.get("passed")]
    if failed:
        lines.append(f"- 失败规则：{', '.join(str(item) for item in failed[:8])}")
    return "\n".join(lines)


def format_supply_card(row: dict[str, Any]) -> str:
    loc = row.get("localization") or {}
    findings = row.get("findings") or []
    lines = [
        f"## 供应链 `{row.get('package_id')}`",
        f"- 包：{row.get('name') or row.get('package_id')}　判定：{_label(row.get('action'))}",
        f"- 分数：{row.get('score') or 0}　风险：{row.get('risk_level') or '无'}",
        f"- 问题：{_clip(str(loc.get('root_detail') or loc.get('root_cause') or ''), 200)}",
    ]
    for item in findings[:5]:
        lines.append(f"- [{item.get('severity')}] {item.get('rule_id')}: {_clip(item.get('title') or item.get('detail') or '', 80)}")
    return "\n".join(lines)


def format_execution_card(row: dict[str, Any]) -> str:
    loc = row.get("localization") or {}
    steps = row.get("steps") or []
    lines = [
        f"## 执行任务 `{row.get('task_id')}`",
        f"- {row.get('title') or row.get('task_id')}　判定：{_label(row.get('action'))}",
        f"- 智能体：{row.get('agent_id') or '无'}",
        f"- 失败规则：{', '.join(str(item) for item in (loc.get('failed_rules') or [])[:8]) or '无'}",
    ]
    for step in steps[:6]:
        lines.append(
            f"- 步骤 `{step.get('tool')}` → {_label(step.get('action'))}"
            f"{'（会执行）' if step.get('would_execute') else '（不会执行）'}"
        )
    return "\n".join(lines)


def format_session_chain(session_id: str, events: list[dict[str, Any]]) -> str:
    scenario = next((item.get("scenario") for item in events if item.get("scenario")), "无")
    agent = next((item.get("agent_id") for item in events if item.get("agent_id")), "无")
    lines = [
        f"## 会话证据链 `{session_id}`",
        f"共 {len(events)} 步 · 场景 {scenario} · 智能体 {agent}",
        "",
    ]
    for index, event in enumerate(events, 1):
        tool = event.get("canonical_tool") or event.get("tool") or "无"
        raw = event.get("tool") or tool
        arrow = f"{raw} → `{tool}`" if str(raw) != str(tool) else f"`{tool}`"
        lines.append(f"{index}. {_label(event.get('status'))} {arrow}")
        reason = _clip(str(event.get("reason") or ""), 160)
        if reason:
            lines.append(f"   原因：{reason}")
        if event.get("approval_id"):
            lines.append(f"   审批单：`{event.get('approval_id')}`")
        failed = [hit for hit in (event.get("policy_hits") or []) if not hit.get("passed")]
        rules = "、".join(str(hit.get("rule_id") or "") for hit in failed[:4] if hit.get("rule_id"))
        if rules:
            lines.append(f"   失败规则：{rules}")
        if event.get("event_id"):
            lines.append(f"   事件：`{event.get('event_id')}`")
    return "\n".join(lines)


def _load_json(path) -> dict[str, Any]:
    if not path.exists():
        return {}
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return {}
    return payload if isinstance(payload, dict) else {}


def _search_evidence(query: str = "", *, audit_path=None, limit: int | None = None) -> dict[str, Any]:
    """统一检索：会话链优先；否则按 runtime / 评测 / 供应链 / 执行审计匹配。"""
    needle = (query or "").strip()
    runtime_events = load_runtime_audit(limit=2000, path=audit_path)
    items: list[dict[str, Any]] = []

    if needle:
        session_hits = [event for event in runtime_events if str(event.get("session_id") or "") == needle]
        if session_hits:
            chrono = list(reversed(session_hits))
            records = [{"kind": "runtime", "id": event.get("event_id"), "record": event, "card": format_runtime_card(event)} for event in chrono]
            return {
                "query": needle,
                "scope": "session",
                "count": len(records),
                "records": [{"kind": item["kind"], "id": item["id"], "record": item["record"]} for item in records],
                "items": records,
                "session_events": chrono,
                "markdown": format_session_chain(needle, chrono) + "\n\n" + "\n\n".join(item["card"] for item in records) + "\n",
                "text": format_session_chain(needle, chrono),
            }

    for event in runtime_events:
        if _match(
            needle,
            event.get("event_id"),
            event.get("session_id"),
            event.get("tool"),
            event.get("canonical_tool"),
            event.get("approval_id"),
            event.get("scenario"),
            event.get("status"),
        ):
            items.append({"kind": "runtime", "id": event.get("event_id"), "record": event, "card": format_runtime_card(event)})

    if needle:
        eval_bundle = _load_json(AUDIT_LOG_PATH)
        for event in eval_bundle.get("events") or []:
            if _match(
                needle,
                event.get("sample_id"),
                event.get("event_id"),
                event.get("file_name"),
                event.get("target_tool"),
                event.get("status"),
            ):
                items.append(
                    {
                        "kind": "eval",
                        "id": event.get("sample_id") or event.get("event_id"),
                        "record": event,
                        "card": format_eval_card(event),
                    }
                )

        supply = _load_json(SUPPLY_CHAIN_AUDIT_PATH)
        for row in supply.get("packages") or []:
            if _match(needle, row.get("package_id"), row.get("name"), row.get("action")):
                items.append({"kind": "supply", "id": row.get("package_id"), "record": row, "card": format_supply_card(row)})

        execution = _load_json(EXECUTION_AUDIT_PATH)
        for row in execution.get("tasks") or []:
            if _match(needle, row.get("task_id"), row.get("title"), row.get("action"), row.get("agent_id")):
                items.append({"kind": "execution", "id": row.get("task_id"), "record": row, "card": format_execution_card(row)})

    if needle:
        selected = items[: max(1, min(limit or 50, 50))]
        scope = "search"
    else:
        selected = [item for item in items if item["kind"] == "runtime"][: max(1, min(limit or 50, 50))]
        if not selected:
            selected = items[: max(1, min(limit or 50, 50))]
        scope = "recent"

    title = f"# 安智盾证据链导出\n\n查询：`{needle or '最近运行时判定'}`　共 {len(selected)} 条\n"
    body = "\n\n".join(item["card"] for item in selected) if selected else "_无匹配记录_"
    if not selected:
        text = "没有匹配的审计记录。用法：`/guard` 最近判定；`/guard <事件ID|会话|工具|样本>` 查证据链。"
    elif len(selected) == 1:
        text = selected[0]["card"]
    else:
        text = f"共 {len(selected)} 条。用 `/guard <id>` 打开单条证据链。\n\n" + "\n\n".join(item["card"] for item in selected)

    return {
        "query": needle,
        "scope": scope,
        "count": len(selected),
        "records": [{"kind": item["kind"], "id": item["id"], "record": item["record"]} for item in selected],
        "items": selected,
        "markdown": title + "\n" + body + "\n",
        "text": text,
    }


def query_evidence(query: str = "", *, limit: int = 8, audit_path=None) -> dict[str, Any]:
    found = _search_evidence(query, audit_path=audit_path, limit=max(1, min(limit, 20)))
    return {
        "ok": True,
        "query": found["query"],
        "count": found["count"],
        "text": found["text"],
        "items": [{"kind": item["kind"], "id": item["id"]} for item in found["items"]],
    }


def export_evidence(
    query: str = "",
    *,
    fmt: Literal["json", "md", "both"] = "both",
    export_dir: Path | None = None,
    audit_path=None,
) -> dict[str, Any]:
    """导出证据链为 JSON / Markdown 文件，写入 outputs/exports/。"""
    collected = _search_evidence(query, audit_path=audit_path, limit=50)
    if collected["count"] == 0:
        return {
            "ok": False,
            "query": query,
            "count": 0,
            "text": "没有可导出的审计记录。用法：`/guard export` 或 `/guard export <会话|事件ID>`。",
            "files": {},
        }

    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    slug = _safe_slug(query or "recent")
    out_dir = Path(export_dir) if export_dir else EVIDENCE_EXPORT_DIR
    out_dir.mkdir(parents=True, exist_ok=True)
    base = out_dir / f"evidence_{slug}_{stamp}_{uuid4().hex[:6]}"

    files: dict[str, str] = {}
    payload = {
        "ok": True,
        "exported_at": stamp,
        "query": collected["query"],
        "scope": collected["scope"],
        "count": collected["count"],
        "records": collected["records"],
    }

    wanted = {"json", "md"} if fmt == "both" else {fmt}
    if "json" in wanted:
        json_path = base.with_suffix(".json")
        json_path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
        files["json"] = str(json_path)
    if "md" in wanted:
        md_path = base.with_suffix(".md")
        md_path.write_text(collected["markdown"], encoding="utf-8")
        files["markdown"] = str(md_path)

    lines = [f"已导出证据链（{collected['count']} 条）。"]
    for kind, path in files.items():
        lines.append(f"- {kind}: `{path}`")
    return {
        "ok": True,
        "query": collected["query"],
        "count": collected["count"],
        "scope": collected["scope"],
        "format": fmt,
        "files": files,
        "text": "\n".join(lines),
        "markdown": collected["markdown"],
        "json": payload if "json" in wanted else None,
    }


def _safe_slug(value: str) -> str:
    text = re.sub(r"[^\w\u4e00-\u9fff\-]+", "_", (value or "evidence").strip())[:48]
    return text or "evidence"
