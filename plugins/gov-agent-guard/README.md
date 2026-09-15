# 政企智能体策略门禁（OpenClaw 插件）

没有独立看板。审批和溯源都在 OpenClaw 里完成。

| 能力 | 怎么用 |
| --- | --- |
| 审核 UI | 策略判定为待审时，插件返回 `requireApproval`（工具调用与插件/Skill **安装**均支持）；OpenClaw 弹出批准/拒绝 |
| 证据链 | 聊天里输入 `/guard`；`/guard export [id]` 导出 JSON + Markdown 到引擎 `outputs/exports/` |
| 安装门禁 | `before_install` 扫描插件/Skill：硬风险阻断；疑似风险走审批后决定是否安装 |
| 令牌强制 | 未配置 `config.token` 时，`before_tool_call` / `before_install` **默认阻断**（可用 `ops_bootstrap --sync-openclaw`） |

## 安装

```bash
python run.py
openclaw plugins install --link ./plugins/gov-agent-guard
openclaw plugins enable gov-agent-guard
openclaw gateway restart
```

### WSL 注意

OpenClaw **不会**从 `/mnt/c/...`（Windows 盘挂载）加载插件：该路径通常是 `mode=777`，会被判定为 *world-writable* 并拒绝，报错类似 `Plugin artifact has no valid plugin manifest`。

请把插件放到 Linux 原生目录后再 link，例如：

```bash
cp -a "/mnt/c/Users/dyk/Desktop/揭榜挂帅/code/11/plugins/gov-agent-guard" ~/gov-agent-guard
chmod -R u=rwX,go=rX ~/gov-agent-guard
openclaw plugins install -l ~/gov-agent-guard --force --accept-capabilities
openclaw plugins enable gov-agent-guard
openclaw gateway restart
```

插件 manifest 文件为目录内的 `openclaw.plugin.json`（OpenClaw 2026.9+ 规范），与 `package.json` 里的 `openclaw.extensions` 成对出现。

配置示例见 `openclaw.example.json`。`plugins.allow` 须包含 `gov-agent-guard`。

## 命令

```text
/guard
/guard pending
/guard <事件ID|会话|工具|样本>
/guard export
/guard export <事件ID|会话>
```

例：`/guard office-2`、`/guard send_email`、`/guard ipi-002`、`/guard export demo-ops-write`。按会话 ID 查询时返回该会话的时间顺序证据链，不与评测语料混排。

导出文件写在策略引擎机器的 `outputs/exports/`（同时生成 `.json` 与 `.md`）。也可用 HTTP：`GET /v1/policy/export?q=<id>&format=both`。

审批弹层里会带失败规则，并提示用 `/guard <id>` 打开完整证据链。标题/说明受 OpenClaw 限制（标题 80 字、说明 512 字）。

引擎 `POLICY_TOKEN` 与插件 `token` **必须成对**（默认强制鉴权）。缺 `token` 时钩子路径直接阻断。用 `python scripts/ops_bootstrap.py --sync-openclaw` 同步。仅排障可设 `allowMissingToken: true`（生产禁止）。

OpenClaw 若回写 `allow-always`，引擎会把同一会话、同一工具、同一参数指纹记下，后续无需再带 `approvalId`。

## 判定

- 允许：不拦，OpenClaw 继续执行原工具
- 阻断：`{ block: true, blockReason }`
- 待审：弹出审核 UI；点允许/拒绝后回写 `POST /v1/policy/approvals/{id}`（安装与工具调用相同）
- 安装硬拦截：供应链判定 `BLOCK` 时直接 `{ block: true }`，不进入审批
