import { definePluginEntry } from "openclaw/plugin-sdk/plugin-entry";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

const PLUGIN_ID = "gov-agent-guard";

function readOpenClawFileConfig() {
  try {
    const configPath = path.join(os.homedir(), ".openclaw", "openclaw.json");
    const raw = fs.readFileSync(configPath, "utf8");
    const data = JSON.parse(raw);
    const entry =
      data &&
      data.plugins &&
      data.plugins.entries &&
      data.plugins.entries[PLUGIN_ID];
    return (entry && entry.config) || {};
  } catch {
    return {};
  }
}

function pluginConfig(ctx) {
  return (
    (ctx && ctx.pluginConfig) ||
    (ctx && ctx.event && ctx.event.context && ctx.event.context.pluginConfig) ||
    (ctx &&
      ctx.config &&
      ctx.config.plugins &&
      ctx.config.plugins.entries &&
      ctx.config.plugins.entries[PLUGIN_ID] &&
      ctx.config.plugins.entries[PLUGIN_ID].config) ||
    readOpenClawFileConfig()
  );
}

function readHookConfig(event, ctx) {
  const fromEvent = event && event.context && event.context.pluginConfig;
  if (fromEvent && typeof fromEvent === "object" && Object.keys(fromEvent).length > 0) {
    return fromEvent;
  }
  return pluginConfig(ctx);
}

function policyRoot(config) {
  return String(config.policyUrl || "http://127.0.0.1:18210").replace(/\/+$/, "");
}

function resolveScenario(config, agentId) {
  if (config.scenario) {
    return config.scenario;
  }
  const map = config.agentMap && typeof config.agentMap === "object" ? config.agentMap : {};
  const key = String(agentId || "").trim();
  if (key && map[key]) {
    return map[key];
  }
  return undefined;
}

function failClosed(config) {
  return config.failClosed !== false;
}

function allowMissingToken(config) {
  // 仅紧急排障；生产禁止。默认缺 token 一律阻断钩子路径。
  return config.allowMissingToken === true;
}

function hasPolicyToken(config) {
  return Boolean(String((config && config.token) || "").trim());
}

function missingTokenBlock(kind) {
  return block(
    `未配置策略令牌（config.token），已阻断${kind}。请执行: python scripts/ops_bootstrap.py --sync-openclaw`,
  );
}

function timeoutMs(config) {
  const value = Number(config.timeoutMs);
  if (Number.isFinite(value) && value >= 500 && value <= 60000) {
    return value;
  }
  return 8000;
}

async function requestJson(url, config, options) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs(config));
  try {
    const headers = { Accept: "application/json", ...(options.headers || {}) };
    const token = String((config && config.token) || "").trim();
    if (token) {
      headers.Authorization = `Bearer ${token}`;
    }
    const response = await fetch(url, { ...options, headers, signal: controller.signal });
    const payload = await response.json().catch(() => ({}));
    if (!response.ok) {
      const detail = payload.detail || payload.message || `HTTP ${response.status}`;
      throw new Error(String(detail));
    }
    return payload;
  } finally {
    clearTimeout(timer);
  }
}

function postJson(url, body, config) {
  return requestJson(url, config, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
}

function block(reason) {
  return { block: true, blockReason: reason };
}

function attachApprovalCallback(hook, config, approvalId) {
  if (!hook || !hook.requireApproval || !approvalId) {
    return hook;
  }
  hook.requireApproval.onResolution = async (decision) => {
    const approved = decision === "allow-once" || decision === "allow-always";
    try {
      await postJson(
        `${policyRoot(config)}/v1/policy/approvals/${approvalId}`,
        {
          decision: approved ? "approved" : "rejected",
          note: `openclaw:${decision}`,
        },
        config,
      );
    } catch {
      // 审批回写失败不影响 OpenClaw 宿主已做出的决定。
    }
  };
  return hook;
}

export default definePluginEntry({
  id: PLUGIN_ID,
  name: "政企智能体策略门禁",
  description: "工具调用审批弹层 + /guard 证据链查询。不执行工具。",
  register(api) {
    api.on(
      "before_tool_call",
      async (event, ctx) => {
        const config = readHookConfig(event, ctx);
        if (!hasPolicyToken(config) && !allowMissingToken(config)) {
          return missingTokenBlock("工具调用");
        }
        const url = `${policyRoot(config)}/v1/policy/openclaw/before-tool-call`;
        try {
          const payload = await postJson(
            url,
            {
              toolName: event.toolName,
              params: event.params || {},
              sessionKey: ctx && ctx.sessionKey,
              sessionId: ctx && (ctx.sessionId || ctx.sessionKey),
              agentId: ctx && ctx.agentId,
              scenario: resolveScenario(config, ctx && ctx.agentId),
              source_label: config.sourceLabel,
            },
            config,
          );
          return attachApprovalCallback(payload.hook || undefined, config, payload.approvalId);
        } catch (error) {
          if (failClosed(config)) {
            return block(`策略引擎不可达，已阻断：${error.message || error}`);
          }
          return undefined;
        }
      },
      { priority: 80, timeoutMs: 12000 },
    );

    api.on(
      "before_install",
      async (event, ctx) => {
        const config = readHookConfig(event, ctx);
        if (!hasPolicyToken(config) && !allowMissingToken(config)) {
          return missingTokenBlock("安装");
        }
        const staged =
          event.stagedPath ||
          event.sourcePath ||
          event.path ||
          (event.package && event.package.path) ||
          "";
        const url = `${policyRoot(config)}/v1/policy/openclaw/before-install`;
        try {
          const payload = await postJson(
            url,
            {
              toolName: "install_plugin",
              stagedPath: staged,
              path: staged,
              sessionKey: "openclaw-install",
              agentId: (config && config.agentId) || "ops",
              scenario: resolveScenario(config, "ops") || config.scenario || "ops",
              source_label: config.sourceLabel,
            },
            config,
          );
          return attachApprovalCallback(payload.hook || undefined, config, payload.approvalId);
        } catch (error) {
          if (failClosed(config)) {
            return block(`策略引擎不可达，已阻止安装：${error.message || error}`);
          }
          return undefined;
        }
      },
      { priority: 80, timeoutMs: 12000 },
    );

    api.registerCommand({
      name: "guard",
      description:
        "查询政企策略审计与证据链。/guard 最近判定；/guard <id> 单条溯源；/guard pending 待审批；/guard export [id] 导出 JSON+Markdown。",
      acceptsArgs: true,
      requireAuth: true,
      handler: async (ctx) => {
        const config = pluginConfig(ctx);
        if (!hasPolicyToken(config) && !allowMissingToken(config)) {
          return {
            text: "未配置策略令牌（config.token）。请执行: python scripts/ops_bootstrap.py --sync-openclaw",
          };
        }
        const query = String((ctx && (ctx.args || ctx.commandBody)) || "")
          .replace(/^\/guard\b/i, "")
          .trim();
        try {
          const encoded = encodeURIComponent(query);
          const url = `${policyRoot(config)}/v1/policy/trace?q=${encoded}&limit=8`;
          const payload = await requestJson(url, config, { method: "GET" });
          return { text: payload.text || "没有审计数据。" };
        } catch (error) {
          return { text: `无法读取证据链：${error.message || error}` };
        }
      },
    });
  },
});
