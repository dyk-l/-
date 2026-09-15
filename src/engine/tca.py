"""任务对象头（TCA）签发与校验。

落地默认使用独立密钥的 HMAC-SHA256（非 Charm/ABE）。
签名载荷绑定：对象 id、版本、eta、tca_id、kid、算法与可选业务 bind。
后续若接入配对密码学，可替换本模块实现而保持 AgentGate 调用面不变。
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Protocol

from src.config import OUTPUT_DIR, tca_hmac_secret_material

ALG = "HMAC-SHA256"


def _utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _canon(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _sha256(value: Any) -> str:
    if isinstance(value, bytes):
        payload = value
    else:
        payload = _canon(value)
    return hashlib.sha256(payload).hexdigest()


def compute_eta(payload: bytes, attrs: list[str], rp: list[dict[str, Any]], meta: dict[str, Any]) -> list[str]:
    """对象内容承诺：payload / attrs / rp / meta 的哈希元组。"""
    return [_sha256(payload), _sha256(attrs), _sha256(rp), _sha256(meta)]


def _signing_body(head: dict[str, Any]) -> dict[str, Any]:
    return {
        "alg": head.get("alg"),
        "tca_id": head.get("tca_id"),
        "kid": head.get("kid"),
        "id": head.get("id"),
        "v": head.get("v"),
        "eta": head.get("eta"),
        "iat": head.get("iat"),
        "bind": head.get("bind") or {},
    }


class ObjectHeadProvider(Protocol):
    tca_id: str
    kid: str
    currentversion: dict[str, int]

    def sign_head(
        self,
        pdo_id: str,
        version: int,
        eta: list[str],
        *,
        bind: dict[str, Any] | None = None,
    ) -> dict[str, Any]: ...

    def tca_verify(self, head: dict[str, Any]) -> bool: ...

    def register_version(self, pdo_id: str, version: int) -> None: ...

    def verify_puncture(
        self,
        before: list[dict[str, Any]],
        delta_rp: dict[str, Any],
        after: list[dict[str, Any]],
    ) -> bool: ...


class HmacTCA:
    """落地级 HMAC 对象头签发器。"""

    def __init__(self, tca_id: str, secret: bytes | None = None) -> None:
        self.tca_id = tca_id or "TCA0"
        material = secret if secret is not None else tca_hmac_secret_material()
        if not material:
            raise ValueError("TCA HMAC secret is empty")
        # 归一成 32 字节工作密钥，避免短口令直接进 HMAC
        self.secret = hashlib.sha256(material).digest()
        self.kid = hashlib.sha256(self.secret).hexdigest()[:16]
        self.currentversion: dict[str, int] = {}

    def sign_head(
        self,
        pdo_id: str,
        version: int,
        eta: list[str],
        *,
        bind: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        body = {
            "alg": ALG,
            "tca_id": self.tca_id,
            "kid": self.kid,
            "id": pdo_id,
            "v": int(version),
            "eta": list(eta),
            "iat": _utc_now(),
            "bind": dict(bind or {}),
        }
        signature = hmac.new(self.secret, _canon(body), hashlib.sha256).hexdigest()
        return {**body, "tca_sign": signature}

    def tca_verify(self, head: dict[str, Any]) -> bool:
        if not isinstance(head, dict):
            return False
        if str(head.get("alg") or "") != ALG:
            return False
        if str(head.get("tca_id") or "") != self.tca_id:
            return False
        if str(head.get("kid") or "") != self.kid:
            return False
        if "iat" not in head or "v" not in head or "id" not in head:
            return False
        expected = hmac.new(self.secret, _canon(_signing_body(head)), hashlib.sha256).hexdigest()
        provided = str(head.get("tca_sign") or "")
        return bool(provided) and hmac.compare_digest(expected, provided)

    def register_version(self, pdo_id: str, version: int) -> None:
        self.currentversion[pdo_id] = int(version)

    def verify_puncture(
        self,
        before: list[dict[str, Any]],
        delta_rp: dict[str, Any],
        after: list[dict[str, Any]],
    ) -> bool:
        return after == list(before) + [delta_rp]


def ensure_local_secret_file(path: Path | None = None) -> Path:
    """若环境变量未设密钥，确保本地密钥文件存在（仅本机试点）。"""
    target = path or (OUTPUT_DIR / ".tca_hmac_key")
    if os.getenv("TCA_HMAC_SECRET", "").strip():
        return target
    target.parent.mkdir(parents=True, exist_ok=True)
    if not target.exists():
        target.write_text(secrets.token_hex(32) + "\n", encoding="utf-8")
    return target
