"""项目路径与运行配置。"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

from dotenv import load_dotenv

PROJECT_ROOT = Path(__file__).resolve().parent.parent
load_dotenv(PROJECT_ROOT / ".env")


def _path_from_env(name: str, default: Path) -> Path:
    raw = os.getenv(name, "").strip()
    if not raw:
        return default
    candidate = Path(raw)
    return candidate if candidate.is_absolute() else (PROJECT_ROOT / candidate)


TEST_DOCS_DIR = _path_from_env("TEST_DOCS_DIR", PROJECT_ROOT / "test_docs")
POLICY_PATH = _path_from_env("POLICY_PATH", PROJECT_ROOT / "policies" / "ifc_policy.yaml")
OUTPUT_DIR = _path_from_env("OUTPUT_DIR", PROJECT_ROOT / "outputs")
AUDIT_LOG_PATH = OUTPUT_DIR / "audit_logs.json"
METRICS_HISTORY_PATH = OUTPUT_DIR / "metrics_history.json"
MANIFEST_PATH = TEST_DOCS_DIR / "manifest.json"
LLM_RUNTIME_PATH = OUTPUT_DIR / "llm_runtime.json"

SUPPLY_CHAIN_SAMPLES_DIR = _path_from_env(
    "SUPPLY_CHAIN_SAMPLES_DIR", PROJECT_ROOT / "supply_chain_samples"
)
SUPPLY_CHAIN_MANIFEST_PATH = SUPPLY_CHAIN_SAMPLES_DIR / "manifest.json"
SUPPLY_CHAIN_POLICY_PATH = _path_from_env(
    "SUPPLY_CHAIN_POLICY_PATH", PROJECT_ROOT / "policies" / "supply_chain_policy.json"
)
SUPPLY_CHAIN_AUDIT_PATH = OUTPUT_DIR / "supply_chain_audit.json"
SUPPLY_CHAIN_HISTORY_PATH = OUTPUT_DIR / "supply_chain_history.json"

EXECUTION_SAMPLES_DIR = _path_from_env("EXECUTION_SAMPLES_DIR", PROJECT_ROOT / "execution_samples")
EXECUTION_MANIFEST_PATH = EXECUTION_SAMPLES_DIR / "manifest.json"
EXECUTION_POLICY_PATH = _path_from_env(
    "EXECUTION_POLICY_PATH", PROJECT_ROOT / "policies" / "execution_gate_policy.json"
)
EXECUTION_AUDIT_PATH = OUTPUT_DIR / "execution_audit.json"
EXECUTION_HISTORY_PATH = OUTPUT_DIR / "execution_history.json"
SCENARIO_POLICY_PATH = _path_from_env(
    "SCENARIO_POLICY_PATH", PROJECT_ROOT / "policies" / "scenarios.json"
)
RUNTIME_AUDIT_PATH = _path_from_env(
    "RUNTIME_AUDIT_PATH", OUTPUT_DIR / "runtime_audit.jsonl"
)
RUNTIME_PENDING_PATH = _path_from_env(
    "RUNTIME_PENDING_PATH", OUTPUT_DIR / "runtime_pending.json"
)
EVIDENCE_EXPORT_DIR = _path_from_env(
    "EVIDENCE_EXPORT_DIR", OUTPUT_DIR / "exports"
)
TCA_HMAC_KEY_PATH = _path_from_env(
    "TCA_HMAC_KEY_PATH", OUTPUT_DIR / ".tca_hmac_key"
)
POLICY_TOKEN_PATH = _path_from_env(
    "POLICY_TOKEN_PATH", OUTPUT_DIR / ".policy_token"
)


def policy_auth_disabled() -> bool:
    """仅测试/紧急排障：POLICY_AUTH_DISABLED=1 时跳过 Bearer 校验。生产禁止开启。"""
    return os.getenv("POLICY_AUTH_DISABLED", "").strip().lower() in {"1", "true", "yes"}


def policy_token() -> str:
    """策略 API Bearer 令牌：优先环境变量，否则读取/生成本地文件。

    默认始终启用鉴权；插件 config.token 必须与此一致。
    """
    raw = os.getenv("POLICY_TOKEN", "").strip()
    if raw:
        return raw

    path = POLICY_TOKEN_PATH
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        text = path.read_text(encoding="utf-8").strip()
        if text:
            return text

    import secrets

    generated = secrets.token_urlsafe(32)
    path.write_text(generated + "\n", encoding="utf-8")
    return generated


def rotate_policy_token() -> str:
    """轮换策略令牌并写入 POLICY_TOKEN_PATH（同时更新进程内环境变量）。"""
    import secrets

    generated = secrets.token_urlsafe(32)
    POLICY_TOKEN_PATH.parent.mkdir(parents=True, exist_ok=True)
    POLICY_TOKEN_PATH.write_text(generated + "\n", encoding="utf-8")
    os.environ["POLICY_TOKEN"] = generated
    return generated


def tca_hmac_secret_material() -> bytes:
    """对象头 HMAC 密钥材料：优先环境变量，其次本地密钥文件，否则自动生成。

    生产请设置 TCA_HMAC_SECRET（任意足够长的口令或 hex）；不要把密钥提交进仓库。
    """
    raw = os.getenv("TCA_HMAC_SECRET", "").strip()
    if raw:
        # 支持 hex 编码的 32+ 字节密钥
        if len(raw) >= 64 and all(ch in "0123456789abcdefABCDEF" for ch in raw):
            try:
                return bytes.fromhex(raw)
            except ValueError:
                pass
        return raw.encode("utf-8")

    path = TCA_HMAC_KEY_PATH
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        text = path.read_text(encoding="utf-8").strip()
        if text:
            if len(text) >= 64 and all(ch in "0123456789abcdefABCDEF" for ch in text):
                try:
                    return bytes.fromhex(text)
                except ValueError:
                    pass
            return text.encode("utf-8")

    import secrets

    generated = secrets.token_hex(32)
    path.write_text(generated + "\n", encoding="utf-8")
    return bytes.fromhex(generated)


def server_host() -> str:
    return os.getenv("HOST", "0.0.0.0").strip() or "0.0.0.0"


def server_port() -> int:
    raw = os.getenv("PORT", "18210").strip()
    try:
        return int(raw)
    except ValueError:
        return 18210


def llm_mode() -> str:
    return os.getenv("LLM_MODE", "mock").strip().lower()


def llm_api_key() -> str:
    return os.getenv("LLM_API_KEY", "").strip()


def llm_base_url() -> str:
    return os.getenv("LLM_BASE_URL", "https://api.openai.com/v1").strip()


def llm_model() -> str:
    return os.getenv("LLM_MODEL", "gpt-4o-mini").strip()


def mask_api_key(key: str) -> str:
    text = (key or "").strip()
    if not text:
        return ""
    if len(text) <= 8:
        return "*" * len(text)
    return f"{text[:4]}****{text[-4:]}"


def _load_runtime() -> dict[str, Any]:
    if not LLM_RUNTIME_PATH.exists():
        return {}
    try:
        payload = json.loads(LLM_RUNTIME_PATH.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return {}
    return payload if isinstance(payload, dict) else {}


def llm_settings() -> dict[str, str]:
    runtime = _load_runtime()
    mode = str(runtime.get("mode") or llm_mode() or "mock").strip().lower()
    if mode not in {"mock", "api"}:
        mode = "mock"
    return {
        "mode": mode,
        "api_key": str(runtime.get("api_key") or llm_api_key() or "").strip(),
        "base_url": str(runtime.get("base_url") or llm_base_url() or "").strip().rstrip("/"),
        "model": str(runtime.get("model") or llm_model() or "").strip(),
        "provider": str(runtime.get("provider") or "custom").strip(),
    }


def public_llm_settings() -> dict[str, Any]:
    cfg = llm_settings()
    return {
        "mode": cfg["mode"],
        "provider": cfg["provider"],
        "base_url": cfg["base_url"],
        "model": cfg["model"],
        "has_api_key": bool(cfg["api_key"]),
        "api_key_masked": mask_api_key(cfg["api_key"]),
        "connected": bool(cfg["mode"] == "api" and cfg["api_key"] and cfg["base_url"] and cfg["model"]),
    }


def save_llm_settings(
    *,
    mode: str,
    base_url: str,
    model: str,
    provider: str = "custom",
    api_key: str | None = None,
) -> dict[str, Any]:
    current = llm_settings()
    key = (api_key if api_key is not None and api_key.strip() else current["api_key"]).strip()
    payload = {
        "mode": mode.strip().lower(),
        "provider": provider.strip() or "custom",
        "base_url": base_url.strip().rstrip("/"),
        "model": model.strip(),
        "api_key": key,
    }
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    LLM_RUNTIME_PATH.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    os.environ["LLM_MODE"] = payload["mode"]
    os.environ["LLM_BASE_URL"] = payload["base_url"]
    os.environ["LLM_MODEL"] = payload["model"]
    if key:
        os.environ["LLM_API_KEY"] = key
    _upsert_dotenv(
        {
            "LLM_MODE": payload["mode"],
            "LLM_BASE_URL": payload["base_url"],
            "LLM_MODEL": payload["model"],
            "LLM_API_KEY": key,
        }
    )
    return public_llm_settings()


def _upsert_dotenv(updates: dict[str, str]) -> None:
    path = PROJECT_ROOT / ".env"
    lines: list[str] = []
    if path.exists():
        lines = path.read_text(encoding="utf-8").splitlines()
    seen: set[str] = set()
    rewritten: list[str] = []
    for line in lines:
        stripped = line.strip()
        if stripped and not stripped.startswith("#") and "=" in line:
            name = line.split("=", 1)[0].strip()
            if name in updates:
                rewritten.append(f"{name}={updates[name]}")
                seen.add(name)
                continue
        rewritten.append(line)
    for name, value in updates.items():
        if name not in seen:
            rewritten.append(f"{name}={value}")
    path.write_text("\n".join(rewritten) + "\n", encoding="utf-8")
