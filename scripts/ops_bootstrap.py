#!/usr/bin/env python3
"""运维引导：确保策略令牌与对象头密钥就绪，并可同步到 OpenClaw 插件配置。"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.config import (  # noqa: E402
    POLICY_TOKEN_PATH,
    TCA_HMAC_KEY_PATH,
    policy_token,
    rotate_policy_token,
    tca_hmac_secret_material,
)


def _openclaw_config_path() -> Path:
    return Path.home() / ".openclaw" / "openclaw.json"


def sync_openclaw_token(token: str, *, scenario: str | None = None) -> Path:
    path = _openclaw_config_path()
    if not path.exists():
        raise FileNotFoundError(f"未找到 OpenClaw 配置：{path}")
    data = json.loads(path.read_text(encoding="utf-8"))
    plugins = data.setdefault("plugins", {})
    entries = plugins.setdefault("entries", {})
    entry = entries.setdefault("gov-agent-guard", {})
    entry["enabled"] = True
    cfg = entry.setdefault("config", {})
    cfg["policyUrl"] = cfg.get("policyUrl") or "http://127.0.0.1:18210"
    cfg["token"] = token
    cfg.setdefault("failClosed", True)
    cfg.setdefault("timeoutMs", 8000)
    if scenario:
        cfg["scenario"] = scenario
    allow = plugins.setdefault("allow", [])
    if "gov-agent-guard" not in allow:
        allow.append("gov-agent-guard")
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return path


def main() -> int:
    parser = argparse.ArgumentParser(description="安智盾运维引导")
    parser.add_argument("--rotate-token", action="store_true", help="轮换 POLICY_TOKEN")
    parser.add_argument("--sync-openclaw", action="store_true", help="把令牌写入 ~/.openclaw/openclaw.json")
    parser.add_argument("--scenario", default="", help="同步时可选写入 scenario（office|ops|...）")
    parser.add_argument("--show", action="store_true", help="打印当前令牌（谨慎使用）")
    args = parser.parse_args()

    # 确保密钥材料存在
    tca_hmac_secret_material()
    token = rotate_policy_token() if args.rotate_token else policy_token()

    print("安智盾运维引导")
    print(f"- POLICY_TOKEN 文件: {POLICY_TOKEN_PATH}")
    print(f"- TCA 密钥文件:     {TCA_HMAC_KEY_PATH}")
    print(f"- 令牌长度:         {len(token)}")
    if args.show or args.rotate_token:
        print(f"- POLICY_TOKEN:     {token}")
    else:
        print("- POLICY_TOKEN:     (已就绪；加 --show 可打印明文)")

    if args.sync_openclaw:
        path = sync_openclaw_token(token, scenario=args.scenario.strip() or None)
        print(f"- 已同步插件 token → {path}")
        print("  请执行: openclaw gateway restart")

    print()
    print("下一步：")
    print("1. 启动引擎: python run.py")
    print("2. 健康检查: curl http://127.0.0.1:18210/api/health")
    print("3. 策略调用需带: Authorization: Bearer <POLICY_TOKEN>")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
