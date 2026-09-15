#!/usr/bin/env bash
# 运维一键：确保令牌就绪并同步到 OpenClaw，然后提示重启 gateway。
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$ROOT"
export PATH="$HOME/.npm-global/bin:$PATH"

SCENARIO="${1:-}"
ARGS=(--sync-openclaw --show)
if [[ -n "$SCENARIO" ]]; then
  ARGS+=(--scenario "$SCENARIO")
fi
python3 "$SCRIPT_DIR/ops_bootstrap.py" "${ARGS[@]}"
if command -v openclaw >/dev/null 2>&1; then
  openclaw gateway restart
  echo "gateway restarted"
else
  echo "未找到 openclaw 命令，请手动 restart gateway"
fi
