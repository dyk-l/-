"""会话级污点：先前轮次读过低信任/高密级数据后，会话标记为 Tainted。"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass
class TaintRecord:
    reason: str


class SessionTaintStore:
    def __init__(self) -> None:
        self._records: dict[str, TaintRecord] = {}

    def begin(self, session_id: str) -> None:
        self.clear(session_id)

    def mark(self, session_id: str, reason: str) -> None:
        if not session_id:
            return
        self._records[session_id] = TaintRecord(reason=reason)

    def clear(self, session_id: str) -> None:
        self._records.pop(session_id, None)

    def get(self, session_id: str) -> TaintRecord | None:
        return self._records.get(session_id)

    def is_tainted(self, session_id: str) -> bool:
        return session_id in self._records
