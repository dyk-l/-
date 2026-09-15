# 政企智能体安全评测与供应链检测

单机策略引擎 + OpenClaw 原生插件。`python run.py` 只提供判定 API，界面在 OpenClaw：待审弹出审核 UI，`/guard` 查询证据链。

## 三个板块

| 板块 | 测什么 | 入口 |
| --- | --- | --- |
| 供应链检测 | 已解包插件 / Skill / 脚本：行为、依赖、恶意逻辑、评级门禁。**不执行样本代码** | `python run_supply_chain_eval.py` |
| 智能体评测与审计溯源 | 数据 / 内容 / 执行 / 供应链（来文） / 合规五维工具调用评测 | `python run_eval.py --mode mock` |
| 工具调用与执行门禁 | 感知—决策—调用—执行：文件 / 命令 / 浏览器 / 接口的权限、动态策略、审批与任务链阻断 | `python run_execution_eval.py` |

## 启动

```bash
python -m pip install -r requirements.txt
python run.py
```

路径均相对项目根解析。环境变量见 `.env.example`。

## 板块一：插件、Skill 与脚本供应链安全检测

静态分析框架，对应后门、恶意下载、隐蔽外联和高危调用链。策略在 `policies/supply_chain_policy.json`。

```bash
python run_supply_chain_eval.py
python run_supply_chain_eval.py --reproduce sc-attack-001
python run_supply_chain_eval.py --path supply_chain_samples/benign_calendar_skill
```

指标：恶意检出率、自动阻断率、良性误拦 FPR、期望动作准确率。审计：`outputs/supply_chain_audit.json`。历史：`outputs/supply_chain_history.json`。

API：`GET /api/supply-chain`、`POST /api/supply-chain/eval`、`POST /api/supply-chain/reproduce/{package_id}`。

## 板块二：政企智能体安全评测与审计溯源

五维独立计算 ASR Baseline / 防护后 ASR / FPR。网关是 `policies/ifc_policy.yaml` 白名单，不是提示词。

```bash
python run_eval.py --mode mock
python run_eval.py --reproduce ipi-002
python run_eval.py --rescore
```

攻击复现、问题定位、效果验证（改策略后 `--rescore`）、持续优化（`outputs/metrics_history.json`）。

该板块中的「供应链安全」维度测的是**外部来文 / 附件 / 伪造域名进入办理流**，与板块一的插件安装门禁互补，不是同一套扫描器。

## 板块三：工具调用与任务执行的安全约束与审批控制

对齐 AgentGate 协议概念：属性策略树、限制策略 puncture（deny-overrides）、TCA 对象头验签、派生对象继承并沿 childs 传播。评测不落地执行命令/浏览器/外联。策略在 `policies/execution_gate_policy.json`。

```bash
python run_execution_eval.py
python run_execution_eval.py --reproduce ex-attack-005
```

API：`GET /api/execution`、`POST /api/execution/eval`、`POST /api/execution/reproduce/{task_id}`。

## 实际场景接入（纯 OpenClaw 插件）

本服务是**策略决策点**：不落地执行命令、浏览器或外联，也没有独立看板。装上插件后：

- 工具调用需要人审时，OpenClaw 弹出审核界面（Control 浮层 / 频道按钮 / `/approve`）
- 审计溯源：聊天里输入 `/guard`，弹出日志和证据链

```bash
python run.py
openclaw plugins install --link ./plugins/gov-agent-guard
openclaw plugins enable gov-agent-guard
openclaw gateway restart
```

**WSL**：不要直接从 `/mnt/c/...` link 插件（Windows 挂载目录常为 777，OpenClaw 会拒绝）。先 `cp` 到 `~/gov-agent-guard` 并 `chmod -R u=rwX,go=rX ~/gov-agent-guard`，再 `openclaw plugins install -l ~/gov-agent-guard --force --accept-capabilities`。策略引擎也请在 WSL 里 `python3 run.py` 启动。

```text
/guard
/guard pending
/guard <事件ID|会话|工具|样本>
```

配置写在 `plugins.entries.gov-agent-guard.config`。示例：`plugins/gov-agent-guard/openclaw.example.json`。

四个验证场景（`policies/scenarios.json`）：

| 场景 ID | 用途 | 默认可调用 |
| --- | --- | --- |
| `office` | 政务办公助手 | 邮件、日程、知识检索、读文件、政务域浏览 |
| `knowledge` | 知识检索问答 | 知识库、读文件、政务域浏览 |
| `process` | 业务流程办理 | 邮件/查库/导出/日程/检索/读文件/内网接口（外部来文默认待审批） |
| `ops` | 运维协同助手 | 白名单命令、运维文档、内网接口、插件安装扫描 |

无 OpenClaw 时仍可用 HTTP：`POST /v1/policy/check`、`GET /v1/policy/trace`。审批：`POST /v1/policy/approvals/{id}`。运行时审计：`outputs/runtime_audit.jsonl`（超过 2000 条自动截断）。待审与 allow-always 指纹：`outputs/runtime_pending.json`（重启不丢）。

未配置 `config.scenario` 时，引擎按 OpenClaw `agentId` 映射到 `office` / `knowledge` / `process` / `ops`（见 `policies/scenarios.json` 的 `agent_aliases`）。执行门禁内部智能体 ID 仍是 `agent_clerk` / `agent_admin`。

策略 API **默认强制** `POLICY_TOKEN`（Bearer）。未在 `.env` 配置时会写入 `outputs/.policy_token`；插件 `config.token` 必须一致，可用：

```bash
python scripts/ops_bootstrap.py --sync-openclaw --show
```

`/api/health` 与评测 CLI 不鉴权。紧急排障才允许 `POLICY_AUTH_DISABLED=1`（生产禁止）。

## 目录

- `supply_chain_samples/` 供应链对照包与 `manifest.json`
- `src/engine/supply_chain.py` 静态扫描与评级
- `test_docs/` 智能体对照样本
- `src/engine/ifc.py` 策略白名单网关
- `src/engine/benchmark.py` 五维指标
- `outputs/audit_logs.json` 智能体证据链
- `src/engine/execution_gate.py` 工具调用全流程门禁
- `execution_samples/manifest.json` 执行门禁对照任务
- `plugins/gov-agent-guard/` OpenClaw 插件（审批弹层 + `/guard` 证据链）
- `docs/使用文档.md` / `docs/作品说明书.md`
