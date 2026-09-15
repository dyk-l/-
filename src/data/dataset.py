"""测试数据集：NORMAL 合法请求 与 ATTACK 恶意攻击对照。"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterator, Literal

from src.config import MANIFEST_PATH, TEST_DOCS_DIR
from src.data.risk_tags import infer_dimensions

Category = Literal["normal", "ipi", "jailbreak"]
Split = Literal["NORMAL", "ATTACK"]


@dataclass
class ExpectedToolCall:
    name: str
    arguments: dict[str, Any] = field(default_factory=dict)


@dataclass
class TestSample:
    sample_id: str
    path: Path
    relative_path: str
    category: Category
    split: Split
    source_label: str
    title: str
    description: str
    expected_status: str = "SAFE"
    expected_tools: list[str] = field(default_factory=list)
    expected_tool_calls: list[ExpectedToolCall] = field(default_factory=list)
    content: str = ""
    risk_dimensions: list[str] = field(default_factory=list)

    @property
    def is_attack(self) -> bool:
        return self.split == "ATTACK" or self.category in {"ipi", "jailbreak"}


def _normalize_split(item: dict[str, Any], category: str) -> Split:
    raw = str(item.get("split") or "").upper()
    if raw in {"NORMAL", "ATTACK"}:
        return raw  # type: ignore[return-value]
    return "ATTACK" if category in {"ipi", "jailbreak"} else "NORMAL"


def _normalize_label(item: dict[str, Any], split: Split) -> str:
    label = item.get("source_label")
    if label:
        return str(label)
    return "Untrusted_External" if split == "ATTACK" else "Trusted_Internal"


class TestDataset:
    def __init__(self, root: Path | None = None, manifest_path: Path | None = None) -> None:
        self.root = root or TEST_DOCS_DIR
        self.manifest_path = manifest_path or MANIFEST_PATH
        self.samples: list[TestSample] = []
        self._load()

    def _load(self) -> None:
        if not self.manifest_path.exists():
            raise FileNotFoundError(f"缺少数据集清单：{self.manifest_path}")
        payload = json.loads(self.manifest_path.read_text(encoding="utf-8"))
        for item in payload.get("samples", []):
            rel = item["path"].replace("\\", "/")
            abs_path = self.root / rel
            category = item["category"]
            split = _normalize_split(item, category)
            source_label = _normalize_label(item, split)
            expected_calls = [
                ExpectedToolCall(name=call["name"], arguments=dict(call.get("arguments") or {}))
                for call in (item.get("expected_tool_calls") or [])
            ]
            expected_tools = list(item.get("expected_tools") or [c.name for c in expected_calls])
            self.samples.append(
                TestSample(
                    sample_id=item["id"],
                    path=abs_path,
                    relative_path=f"test_docs/{rel}",
                    category=category,
                    split=split,
                    source_label=source_label,
                    title=item.get("title", abs_path.stem),
                    description=item.get("description", ""),
                    expected_status=str(item.get("expected_status") or ("BLOCKED" if split == "ATTACK" else "SAFE")),
                    expected_tools=expected_tools,
                    expected_tool_calls=expected_calls,
                    content=abs_path.read_text(encoding="utf-8") if abs_path.exists() else "",
                    risk_dimensions=infer_dimensions(
                        sample_id=item["id"],
                        tools=expected_tools,
                        category=category,
                        source_label=source_label,
                        declared=item.get("risk_dimensions") or [],
                    ),
                )
            )

    def __iter__(self) -> Iterator[TestSample]:
        return iter(self.samples)

    def __len__(self) -> int:
        return len(self.samples)

    def by_id(self, sample_id: str) -> TestSample | None:
        for sample in self.samples:
            if sample.sample_id == sample_id:
                return sample
        return None

    def summary(self) -> dict[str, Any]:
        by_split: dict[str, int] = {}
        by_category: dict[str, int] = {}
        by_dimension: dict[str, int] = {}
        for sample in self.samples:
            by_split[sample.split] = by_split.get(sample.split, 0) + 1
            by_category[sample.category] = by_category.get(sample.category, 0) + 1
            for dim in sample.risk_dimensions or []:
                key = str(dim)
                by_dimension[key] = by_dimension.get(key, 0) + 1
        # 扁平字段兼容历史 audit meta；嵌套字段便于新前端/脚本
        flat = {
            "total": len(self.samples),
            **by_split,
            **by_category,
            "by_split": by_split,
            "by_category": by_category,
            "by_dimension": by_dimension,
            "root": str(self.root),
            "manifest": str(self.manifest_path),
        }
        return flat
