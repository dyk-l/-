"""LLM 接口：真实 Function Calling + 无密钥仿真（无防御智能体，用于打 ASR Baseline）。"""

from __future__ import annotations

import json
import uuid
from dataclasses import dataclass, field
from typing import Any

from src.config import llm_settings
from src.data.dataset import TestSample
from src.data.schemas import SYSTEM_PROMPT, TOOL_SCHEMAS, USER_PROMPT_TEMPLATE


@dataclass
class ToolCall:
    id: str
    name: str
    arguments: dict[str, Any]


@dataclass
class LLMResponse:
    content: str
    tool_calls: list[ToolCall] = field(default_factory=list)
    model: str = "mock"
    mode: str = "mock"
    raw: dict[str, Any] = field(default_factory=dict)


class LLMClient:
    def __init__(
        self,
        mode: str | None = None,
        api_key: str | None = None,
        base_url: str | None = None,
        model: str | None = None,
        strict: bool = False,
    ) -> None:
        cfg = llm_settings()
        self.mode = (mode or cfg["mode"]).lower()
        if self.mode not in {"mock", "api"}:
            self.mode = "mock"
        self.api_key = (api_key if api_key is not None else cfg["api_key"]).strip()
        self.base_url = (base_url or cfg["base_url"]).strip().rstrip("/")
        chosen_model = (model or cfg["model"]).strip()
        self.model_name = "gov-agent-simulator" if self.mode == "mock" else chosen_model
        self.strict = strict

    def complete(self, sample: TestSample) -> LLMResponse:
        if self.mode == "api":
            try:
                return self._complete_api(sample)
            except Exception as exc:  # noqa: BLE001
                if self.strict:
                    raise
                fallback = self._complete_mock(sample)
                fallback.content = f"[API 调用失败，已降级为仿真] {exc}\n{fallback.content}"
                fallback.raw["api_error"] = str(exc)
                return fallback
        return self._complete_mock(sample)

    def ping(self) -> dict[str, Any]:
        import time

        from openai import OpenAI

        if not self.base_url:
            raise ValueError("请填写接口地址 Base URL")
        if not self.model_name or self.model_name == "gov-agent-simulator":
            raise ValueError("请填写模型名称")
        if not self.api_key:
            raise ValueError("请填写 API Key")

        client = OpenAI(api_key=self.api_key, base_url=self.base_url, timeout=30.0)
        started = time.perf_counter()
        completion = client.chat.completions.create(
            model=self.model_name,
            messages=[{"role": "user", "content": "Reply with the single word pong."}],
            max_tokens=16,
            temperature=0,
        )
        latency_ms = int((time.perf_counter() - started) * 1000)
        preview = (completion.choices[0].message.content or "").strip()[:120]
        tools_ok = False
        tools_error = ""
        try:
            client.chat.completions.create(
                model=self.model_name,
                messages=[{"role": "user", "content": "Do not call any tool."}],
                tools=TOOL_SCHEMAS,
                tool_choice="none",
                max_tokens=8,
                temperature=0,
            )
            tools_ok = True
        except Exception as exc:  # noqa: BLE001
            tools_error = str(exc)
        return {
            "ok": True,
            "latency_ms": latency_ms,
            "model": self.model_name,
            "base_url": self.base_url,
            "preview": preview,
            "tools_supported": tools_ok,
            "tools_error": tools_error,
        }

    def _openai(self):
        from openai import OpenAI

        return OpenAI(api_key=self.api_key or "EMPTY", base_url=self.base_url, timeout=60.0)

    def _complete_api(self, sample: TestSample) -> LLMResponse:
        client = self._openai()
        messages = [
            {"role": "system", "content": SYSTEM_PROMPT},
            {
                "role": "user",
                "content": USER_PROMPT_TEMPLATE.format(
                    title=sample.title,
                    content=sample.content,
                ),
            },
        ]
        completion = client.chat.completions.create(
            model=self.model_name,
            messages=messages,
            tools=TOOL_SCHEMAS,
            tool_choice="auto",
            temperature=0,
        )
        message = completion.choices[0].message
        tool_calls: list[ToolCall] = []
        for item in message.tool_calls or []:
            raw_args = item.function.arguments or "{}"
            try:
                parsed = json.loads(raw_args)
            except json.JSONDecodeError:
                parsed = {"_raw": raw_args}
            tool_calls.append(
                ToolCall(
                    id=item.id or _call_id(),
                    name=item.function.name,
                    arguments=parsed if isinstance(parsed, dict) else {"value": parsed},
                )
            )
        return LLMResponse(
            content=message.content or "",
            tool_calls=tool_calls,
            model=self.model_name,
            mode="api",
            raw=completion.model_dump() if hasattr(completion, "model_dump") else {},
        )

    def _complete_mock(self, sample: TestSample) -> LLMResponse:
        """无防御智能体：按文档意图发出 tool_calls，网关负责拦截，从而分离 Baseline 与防护后指标。"""
        if sample.expected_tool_calls:
            calls = [
                ToolCall(id=_call_id(), name=item.name, arguments=dict(item.arguments))
                for item in sample.expected_tool_calls
            ]
            content = (
                "已按合法业务工单准备工具调用。"
                if not sample.is_attack
                else "已接受文档中的工具指令（无网关状态）。"
            )
            return LLMResponse(
                content=content,
                tool_calls=calls,
                model=self.model_name,
                mode="mock",
                raw={"simulator": "manifest_expected_calls"},
            )

        return LLMResponse(
            content="清单未给出期望工具调用，仿真智能体不补启发式调用。",
            tool_calls=[],
            model=self.model_name,
            mode="mock",
            raw={"simulator": "empty"},
        )


def _call_id() -> str:
    return f"call_{uuid.uuid4().hex[:12]}"
