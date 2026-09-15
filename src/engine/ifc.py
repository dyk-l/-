"""策略与参数白名单网关：来源标签 + 域名/SQL/导出目的地细粒度校验。"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal

import sqlglot
import yaml
from sqlglot import exp
from sqlglot.errors import ErrorLevel, ParseError

from src.config import POLICY_PATH
from src.data.dataset import TestSample
from src.data.llm import ToolCall
from src.data.schemas import HIGH_RISK_TOOLS
from src.engine.normalize import (
    fullwidth_to_halfwidth,
    high_entropy_tokens,
    longest_digit_run,
    nfkc,
    normalize_for_match,
)
from src.engine.session_taint import SessionTaintStore

Status = Literal["BLOCKED", "ALLOWED", "SAFE", "PENDING_APPROVAL"]
IDENT_RE = re.compile(r"[A-Za-z_][\w]*")
SQL_COMMENT_RE = re.compile(r"/\*.*?\*/|--[^\n]*", re.DOTALL)
RECIPIENT_SPLIT_RE = re.compile(r"[,;]+")
EMAIL_RE = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")
AT_TOKEN_RE = re.compile(r"\[(?:at)\]|\((?:at)\)|\{(?:at)\}", re.IGNORECASE)
DOT_TOKEN_RE = re.compile(r"\[(?:dot)\]|\((?:dot)\)|\{(?:dot)\}", re.IGNORECASE)
DEFAULT_CONTENT_FIELDS = ("subject", "body", "attachments")


@dataclass
class PolicyHit:
    rule_id: str
    passed: bool
    detail: str


@dataclass
class IFCDecision:
    status: Status
    reason: str
    target_tool: str | None
    high_risk: bool
    source_label: str
    would_execute: bool
    policy_hits: list[PolicyHit] = field(default_factory=list)
    hitl_required: bool = False


class PolicyWhitelistGateway:
    def __init__(self, policy_path: Path | None = None) -> None:
        self.policy_path = policy_path or POLICY_PATH
        self.policy = self._load_policy()
        self.high_risk_tools = set(self.policy.get("high_risk_tools") or HIGH_RISK_TOOLS)
        self.labels = self.policy.get("source_labels") or {}
        self.sessions = SessionTaintStore()

    def begin_session(self, session_id: str) -> None:
        self.sessions.begin(session_id)

    def _load_policy(self) -> dict[str, Any]:
        if not self.policy_path.exists():
            return {}
        return yaml.safe_load(self.policy_path.read_text(encoding="utf-8")) or {}

    def trust_rank(self, source_label: str) -> int:
        meta = self.labels.get(source_label) or {}
        if "trust_rank" in meta:
            return int(meta["trust_rank"])
        lowered = (source_label or "").lower()
        if "untrusted" in lowered or "external" in lowered:
            return 20
        if "trusted" in lowered or "internal" in lowered:
            return 80
        return 0

    def is_high_risk(self, tool_name: str | None) -> bool:
        return bool(tool_name) and tool_name in self.high_risk_tools

    def inspect_call(
        self,
        tool_name: str,
        arguments: dict[str, Any],
        *,
        source_label: str,
        session_id: str,
        sibling_calls: list[ToolCall] | None = None,
    ) -> IFCDecision:
        sample = TestSample(
            sample_id=session_id or "live",
            path=Path("."),
            relative_path="live",
            category="normal",
            split="NORMAL",
            source_label=source_label,
            title="runtime",
            description="",
        )
        call = ToolCall(id="live", name=tool_name, arguments=dict(arguments or {}))
        return self.inspect(sample, call, sibling_calls=sibling_calls, session_id=session_id)

    def inspect(
        self,
        sample: TestSample,
        tool_call: ToolCall | None,
        sibling_calls: list[ToolCall] | None = None,
        session_id: str | None = None,
    ) -> IFCDecision:
        label = sample.source_label
        rank = self.trust_rank(label)
        sid = (session_id or sample.sample_id or "").strip() or "default"

        if tool_call is None:
            return IFCDecision(
                status="SAFE",
                reason="未发出工具调用，按合法业务阅读/摘要处理。",
                target_tool=None,
                high_risk=False,
                source_label=label,
                would_execute=False,
                policy_hits=[PolicyHit("no_tool", True, "无工具调用")],
            )

        if not self.is_high_risk(tool_call.name):
            return IFCDecision(
                status="SAFE",
                reason=f"工具 `{tool_call.name}` 为低危办公动作，放行记录。",
                target_tool=tool_call.name,
                high_risk=False,
                source_label=label,
                would_execute=True,
                policy_hits=[PolicyHit("low_risk_tool", True, tool_call.name)],
            )

        hits = self._check_params(label, rank, tool_call, sibling_calls or [], sid)
        failed = [hit for hit in hits if not hit.passed]
        status, hitl_note, hitl_required = self._decide_status(rank, failed, tool_call)
        if status == "BLOCKED":
            return IFCDecision(
                status="BLOCKED",
                reason="；".join(f"[{h.rule_id}] {h.detail}" for h in failed),
                target_tool=tool_call.name,
                high_risk=True,
                source_label=label,
                would_execute=False,
                policy_hits=hits,
                hitl_required=False,
            )

        if status == "ALLOWED":
            taint_reason = self._taint_reason_after_read(rank, tool_call)
            if taint_reason:
                self.sessions.mark(sid, taint_reason)

        if hitl_required:
            hits.append(PolicyHit("hitl.pending_approval", True, hitl_note))

        reason = "；".join(f"[{h.rule_id}] {h.detail}" for h in hits) or "参数白名单校验通过"
        if hitl_note:
            reason = f"{hitl_note}；{reason}"
        return IFCDecision(
            status=status,
            reason=reason,
            target_tool=tool_call.name,
            high_risk=True,
            source_label=label,
            would_execute=status == "ALLOWED",
            policy_hits=hits,
            hitl_required=hitl_required,
        )

    def _decide_status(
        self,
        rank: int,
        failed: list[PolicyHit],
        call: ToolCall,
    ) -> tuple[Status, str, bool]:
        cfg = self.policy.get("hitl") or {}
        enabled = bool(cfg.get("enabled", True))
        doubt_ids = {str(item) for item in (cfg.get("doubt_rule_ids") or [])}
        if failed:
            hard = [hit for hit in failed if hit.rule_id not in doubt_ids]
            if hard or not enabled:
                return "BLOCKED", "", False
            return (
                "PENDING_APPROVAL",
                "命中疑虑规则，待人工审批（HITL）",
                True,
            )
        if (
            enabled
            and rank < 50
            and bool(cfg.get("untrusted_high_risk_pending", True))
            and self.is_high_risk(call.name)
        ):
            return (
                "PENDING_APPROVAL",
                f"不可信来源将办公动作升级为高危工具 `{call.name}`，待人工审批",
                True,
            )
        return "ALLOWED", "", False

    def _check_params(
        self,
        label: str,
        rank: int,
        call: ToolCall,
        sibling_calls: list[ToolCall],
        session_id: str,
    ) -> list[PolicyHit]:
        if call.name == "send_email":
            return self._check_email(label, rank, call.arguments, sibling_calls, session_id)
        if call.name == "query_database":
            return self._check_sql(label, rank, call.arguments, sibling_calls)
        if call.name == "export_confidential_data":
            return self._check_export(label, rank, call.arguments)
        return [PolicyHit("unknown_high_risk", False, f"未配置白名单的高危工具 `{call.name}`")]

    def _taint_reason_after_read(self, rank: int, call: ToolCall) -> str | None:
        cfg = self.policy.get("session_taint") or {}
        if cfg.get("enabled", True) is False:
            return None
        if call.name != "query_database":
            return None
        high_min = int(cfg.get("high_classification_min_trust") or 80)
        database = str(call.arguments.get("database") or "").strip()
        catalogs = (self.policy.get("sql") or {}).get("catalogs") or {}
        catalog = catalogs.get(database)
        if catalog and int(catalog.get("min_trust_rank") or 0) >= high_min:
            return f"读取高密级目录 `{database}`"
        if rank < 50 and cfg.get("taint_on_untrusted_query", True):
            return f"不可信来源读取数据库 `{database or '?'}`"
        if cfg.get("taint_on_sensitive_columns", True):
            trees, parse_error = _parse_sql_asts(str(call.arguments.get("sql") or ""))
            if not parse_error:
                _tables, columns, _star = _extract_sql_nodes(trees)
                sensitive = {c.lower() for c in (self.policy.get("sql") or {}).get("sensitive_columns") or []}
                leaked = [col for col in columns if col.lower() in sensitive]
                if leaked:
                    return f"读取敏感列 {leaked}"
        return None

    def _check_email(
        self,
        label: str,
        rank: int,
        args: dict[str, Any],
        sibling_calls: list[ToolCall],
        session_id: str,
    ) -> list[PolicyHit]:
        policy = self.policy.get("email") or {}
        hits: list[PolicyHit] = []
        taint_cfg = self.policy.get("session_taint") or {}
        if taint_cfg.get("enabled", True) and taint_cfg.get("block_email_while_tainted", True):
            record = self.sessions.get(session_id)
            if record:
                hits.append(
                    PolicyHit(
                        "session.tainted",
                        False,
                        f"会话已标记 Tainted（{record.reason}），清除前禁止向外部发送邮件",
                    )
                )
            else:
                hits.append(PolicyHit("session.tainted", True, "会话未标记 Tainted"))
        allowed = [d.lower() for d in policy.get("allowed_domains") or []]
        denied = [d.lower() for d in policy.get("denied_domains") or []]
        schema_fields = {str(item).lower() for item in (policy.get("schema_fields") or ["to", "subject", "body", "attachments", "cc", "bcc"])}
        extra_keys = [key for key in args.keys() if str(key).lower() not in schema_fields]
        if rank < 50 and extra_keys:
            hits.append(
                PolicyHit(
                    "ace.schema_isolation",
                    False,
                    f"不可信来源具体计划含未注册能力字段 {extra_keys}（ACE：concrete plan 不得超出 schema）",
                )
            )
        else:
            hits.append(PolicyHit("ace.schema_isolation", True, "工具参数未超出已注册 schema"))

        recipients = _collect_recipients(args, policy.get("extra_recipient_fields") or ["cc", "bcc"])
        content_fields = [
            str(item).lower()
            for item in (policy.get("content_fields") or DEFAULT_CONTENT_FIELDS)
        ]
        recipients.extend(_collect_nested_emails(args, skip_keys=set(content_fields)))
        recipients = _dedupe_recipients(recipients)

        if not recipients:
            hits.append(PolicyHit("email.recipient", False, "缺少收件人"))
        for field, addr in recipients:
            domain = _email_domain(addr)
            if not domain:
                hits.append(PolicyHit("email.recipient", False, f"{field} 收件人非法：{addr}"))
                continue
            denied_hit = _denied_domain_hit(domain, denied)
            if denied_hit:
                hits.append(
                    PolicyHit(
                        "email.denied_domain",
                        False,
                        f"来源 {label} → `{addr}`（{field}）命中域名黑名单 `{denied_hit}`",
                    )
                )
                continue
            if allowed and not _suffix_match(domain, allowed):
                hits.append(
                    PolicyHit(
                        "email.allowed_domain",
                        False,
                        f"来源 {label} → `{addr}`（{field}）不在收件域名白名单 {allowed}",
                    )
                )
                continue
            hits.append(
                PolicyHit(
                    "email.allowed_domain",
                    True,
                    f"来源 {label} → `{addr}`（{field}）通过域名白名单",
                )
            )

        if policy.get("block_nonwhitelist_in_content", True) and allowed:
            covert = []
            for field, addr in _content_channel_emails(args, content_fields):
                domain = _email_domain(addr)
                if not domain:
                    continue
                if _suffix_match(domain, allowed):
                    continue
                covert.append((field, addr, domain))
            if covert:
                shown = "、".join(f"`{addr}`（{field}）" for field, addr, _domain in covert)
                hits.append(
                    PolicyHit(
                        "email.cover_channel",
                        False,
                        f"正文/主题等非收件字段出现非白名单邮箱，视为隐秘通讯管道：{shown}",
                    )
                )
            else:
                hits.append(
                    PolicyHit(
                        "email.cover_channel",
                        True,
                        "正文/主题未夹带非白名单邮箱",
                    )
                )

        attachments = args.get("attachments") or []
        if policy.get("untrusted_forbid_attachments") and rank < 50 and attachments:
            hits.append(
                PolicyHit(
                    "email.untrusted_attachment",
                    False,
                    f"来源 {label} 禁止携带附件外发：{attachments}",
                )
            )
        else:
            hits.append(PolicyHit("email.untrusted_attachment", True, "附件策略通过"))

        if rank < 50:
            parts = _flatten_strings(args)
            blob = " ".join(parts)
            compact = normalize_for_match("中".join(parts))
            denylist = [str(item) for item in (policy.get("untrusted_body_denylist") or []) if item]
            leaked = []
            seen_tokens: set[str] = set()
            for token in denylist:
                needle = normalize_for_match(token)
                if needle and needle in compact and token not in seen_tokens:
                    leaked.append(token)
                    seen_tokens.add(token)
            pattern_hits = _pii_pattern_hits(blob, policy.get("untrusted_pii_patterns") or [])
            pattern_hits.extend(_pii_pattern_hits(compact, policy.get("untrusted_pii_patterns") or []))
            pattern_hits = list(dict.fromkeys(pattern_hits))
            if leaked or pattern_hits:
                hits.append(
                    PolicyHit(
                        "taint.email_sanitizer",
                        False,
                        f"不可信来源流入 send_email 未净化：词 {leaked or '—'}，模式 {pattern_hits or '—'}",
                    )
                )
            else:
                hits.append(PolicyHit("taint.email_sanitizer", True, "邮件参数通过污点净化"))

            min_digits = int(policy.get("untrusted_digit_run_min") or 11)
            digit_hit = ""
            for part in parts:
                digit_hit = longest_digit_run(part, min_len=min_digits)
                if digit_hit:
                    break
            entropy_min_len = int(policy.get("untrusted_entropy_min_len") or 20)
            entropy_bits = float(policy.get("untrusted_entropy_bits") or 3.8)
            entropy_hits = high_entropy_tokens(blob, min_len=entropy_min_len, min_bits=entropy_bits)
            if digit_hit or entropy_hits:
                detail = []
                if digit_hit:
                    detail.append(f"连续数字{len(digit_hit)}位（忽略分隔符）")
                if entropy_hits:
                    preview = entropy_hits[0][:24]
                    detail.append(f"高熵串 `{preview}`")
                hits.append(
                    PolicyHit(
                        "taint.pii_digit_entropy",
                        False,
                        "不可信来源发信参数树命中 PII 数字/熵检测：" + "；".join(detail),
                    )
                )
            else:
                hits.append(PolicyHit("taint.pii_digit_entropy", True, "参数树未出现高熵数字串"))

            if any(call.name == "query_database" for call in sibling_calls):
                hits.append(
                    PolicyHit(
                        "ifc.query_then_email",
                        False,
                        "不可信来源同一轮既查询数据库又发信，阻断邮件以防查询结果外流",
                    )
                )
            else:
                hits.append(PolicyHit("ifc.query_then_email", True, "本轮无查询+发信组合"))
        return hits

    def _check_sql(
        self,
        label: str,
        rank: int,
        args: dict[str, Any],
        sibling_calls: list[ToolCall],
    ) -> list[PolicyHit]:
        policy = self.policy.get("sql") or {}
        hits: list[PolicyHit] = []
        database = str(args.get("database") or "").strip()
        sql = str(args.get("sql") or "").strip()
        catalogs = policy.get("catalogs") or {}
        catalog = catalogs.get(database)

        if not catalog:
            hits.append(
                PolicyHit(
                    "sql.catalog_whitelist",
                    False,
                    f"数据库 `{database}` 未在可查询目录白名单中",
                )
            )
            return hits
        hits.append(PolicyHit("sql.catalog_whitelist", True, f"数据库 `{database}` 在白名单"))

        min_rank = int(catalog.get("min_trust_rank") or 0)
        if rank < min_rank:
            hits.append(
                PolicyHit(
                    "sql.min_trust",
                    False,
                    f"来源 {label}(rank={rank}) 低于库 `{database}` 最低信任 {min_rank}",
                )
            )
        else:
            hits.append(
                PolicyHit(
                    "sql.min_trust",
                    True,
                    f"来源 {label}(rank={rank}) 满足库 `{database}` 最低信任 {min_rank}",
                )
            )

        cleaned = _sanitize_sql(sql) if policy.get("strip_comments", True) else sql
        statements = [part.strip() for part in cleaned.split(";") if part.strip()]
        if not policy.get("split_statements", True):
            statements = [cleaned]
        if not statements:
            statements = [cleaned]

        trees, parse_error = _parse_sql_asts(
            sql,
            split_statements=bool(policy.get("split_statements", True)),
        )
        if parse_error:
            hits.append(PolicyHit("sql.ast_parse", False, parse_error))
        else:
            hits.append(PolicyHit("sql.ast_parse", True, f"已用 sqlglot 生成 {len(trees)} 棵 SQL AST"))

        allowed_tables = [t.lower() for t in catalog.get("allowed_tables") or []]
        allowed_cols = {c.lower() for c in catalog.get("allowed_columns") or []}
        sensitive = {c.lower() for c in policy.get("sensitive_columns") or []}
        deny_keywords = policy.get("deny_keywords") or []

        keyword_hit = ""
        for stmt in statements:
            upper = stmt.upper()
            for keyword in deny_keywords:
                pattern = r"\b" + re.escape(keyword.upper()).replace(r"\ ", r"\s+") + r"\b"
                if re.search(pattern, upper):
                    keyword_hit = keyword
                    break
            if keyword_hit:
                break

        tables, columns, star_hit = _extract_sql_nodes(trees)
        if not policy.get("forbid_select_star"):
            star_hit = False

        if rank < 50 and policy.get("untrusted_simple_projection_only", True) and not parse_error:
            complex_items = _complex_select_projections(trees)
            if complex_items:
                hits.append(
                    PolicyHit(
                        "sql.untrusted_simple_projection",
                        False,
                        "不可信来源只允许简单属性投影，禁止 SELECT 中的函数或算术拼接："
                        + "；".join(complex_items),
                    )
                )
            else:
                hits.append(
                    PolicyHit(
                        "sql.untrusted_simple_projection",
                        True,
                        "不可信来源 SELECT 均为简单属性投影",
                    )
                )

        if keyword_hit:
            hits.append(PolicyHit("sql.deny_keyword", False, f"SQL 含禁止关键字 `{keyword_hit}`"))
        else:
            hits.append(PolicyHit("sql.deny_keyword", True, "未命中 SQL 禁止关键字"))

        if star_hit:
            hits.append(PolicyHit("sql.select_star", False, "禁止 SELECT *"))
        else:
            hits.append(PolicyHit("sql.select_star", True, "投影列合法"))

        bad_tables = [t for t in tables if allowed_tables and t.lower() not in allowed_tables]
        if bad_tables:
            hits.append(
                PolicyHit(
                    "sql.table_whitelist",
                    False,
                    f"表 {bad_tables} 不在 `{database}` 表白名单 {allowed_tables}",
                )
            )
        else:
            shown = tables[0] if tables else "?"
            hits.append(PolicyHit("sql.table_whitelist", True, f"表 `{shown}` 在白名单"))

        bad_sensitive = [c for c in columns if c.lower() in sensitive]
        if bad_sensitive:
            hits.append(PolicyHit("sql.sensitive_column", False, f"投影含敏感字段 {bad_sensitive}"))
        else:
            hits.append(PolicyHit("sql.sensitive_column", True, "未投影敏感字段"))

        if allowed_cols:
            bad_cols = [c for c in columns if IDENT_RE.fullmatch(c) and c.lower() not in allowed_cols]
            if bad_cols:
                hits.append(
                    PolicyHit(
                        "sql.column_whitelist",
                        False,
                        f"列 {bad_cols} 不在列白名单 {sorted(allowed_cols)}",
                    )
                )
            else:
                hits.append(PolicyHit("sql.column_whitelist", True, "投影列均在白名单"))
        if rank < 50 and any(call.name == "send_email" for call in sibling_calls):
            hits.append(
                PolicyHit(
                    "ifc.query_then_email",
                    False,
                    "不可信来源同一轮查询并外发，阻断查询以防结果流入邮件",
                )
            )
        return hits

    def _check_export(self, label: str, rank: int, args: dict[str, Any]) -> list[PolicyHit]:
        policy = self.policy.get("export") or {}
        hits: list[PolicyHit] = []
        min_rank = int(policy.get("min_trust_rank") or 80)
        if rank < min_rank:
            hits.append(
                PolicyHit(
                    "export.min_trust",
                    False,
                    f"来源 {label} 不允许执行机密导出（需要 rank>={min_rank}）",
                )
            )
        else:
            hits.append(PolicyHit("export.min_trust", True, f"来源 {label} 满足导出信任门槛"))

        dest = str(args.get("destination") or "").strip()
        prefixes = list(policy.get("allowed_destination_prefixes") or [])
        if "?" in dest or "#" in dest:
            hits.append(
                PolicyHit(
                    "export.destination_trailer",
                    False,
                    f"导出目的地含查询串或片段：`{dest}`",
                )
            )
        elif prefixes and not any(dest.lower().startswith(p.lower()) for p in prefixes):
            hits.append(
                PolicyHit(
                    "export.destination_whitelist",
                    False,
                    f"导出目的地 `{dest}` 不在前缀白名单 {prefixes}",
                )
            )
        else:
            hits.append(PolicyHit("export.destination_whitelist", True, f"目的地 `{dest}` 通过白名单"))

        classification = str(args.get("classification") or "")
        denied = policy.get("denied_classifications_for_untrusted") or []
        if rank < 50 and classification in denied:
            hits.append(
                PolicyHit(
                    "export.classification",
                    False,
                    f"不可信来源禁止导出密级 `{classification}`",
                )
            )
        else:
            hits.append(PolicyHit("export.classification", True, f"密级 `{classification or '内部'}` 可接受"))
        return hits


def _sanitize_sql(sql: str) -> str:
    return SQL_COMMENT_RE.sub("", sql)


def _parse_sql_asts(sql: str, *, split_statements: bool = True) -> tuple[list[exp.Expression], str | None]:
    text = (sql or "").strip()
    if not text:
        return [], "SQL 为空，无法生成 AST"
    try:
        if split_statements:
            trees = sqlglot.parse(text, error_level=ErrorLevel.RAISE)
        else:
            tree = sqlglot.parse_one(text, error_level=ErrorLevel.RAISE)
            trees = [tree] if tree is not None else []
    except ParseError as exc:
        return [], f"SQL AST 解析失败：{exc}"
    except Exception as exc:  # noqa: BLE001
        return [], f"SQL AST 解析失败：{exc}"
    expressions = [tree for tree in trees if tree is not None]
    if not expressions:
        return [], "SQL AST 为空"
    return expressions, None


def _unwrap_projection(node: exp.Expression) -> exp.Expression:
    current = node
    while isinstance(current, (exp.Alias, exp.Paren)) and current.this is not None:
        current = current.this
    return current


def _is_simple_column_projection(node: exp.Expression) -> bool:
    target = _unwrap_projection(node)
    if not isinstance(target, exp.Column):
        return False
    if isinstance(target.this, exp.Star):
        return False
    name = target.name
    return bool(name) and name != "*"


def _describe_complex_projection(node: exp.Expression) -> str:
    target = _unwrap_projection(node)
    snippet = target.sql() if hasattr(target, "sql") else str(target)
    if isinstance(target, (exp.Add, exp.Sub, exp.Mul, exp.Div, exp.Mod, exp.Neg, exp.DPipe)):
        return f"算术/拼接 `{snippet}`"
    if isinstance(target, exp.Func):
        return f"标量函数 `{snippet}`"
    if isinstance(target, (exp.Case, exp.If)):
        return f"条件表达式 `{snippet}`"
    if isinstance(target, (exp.Subquery, exp.Select, exp.Exists)):
        return f"子查询投影 `{snippet}`"
    return f"非属性投影 `{snippet}`"


def _complex_select_projections(trees: list[exp.Expression]) -> list[str]:
    found: list[str] = []
    for tree in trees:
        for select in tree.find_all(exp.Select):
            for expr in select.expressions:
                if _is_star_projection(expr):
                    continue
                if _is_simple_column_projection(expr):
                    continue
                found.append(_describe_complex_projection(expr))
    return found


def _is_star_projection(node: exp.Expression) -> bool:
    target = node.this if isinstance(node, exp.Alias) else node
    if isinstance(target, exp.Star):
        return True
    if isinstance(target, exp.Column) and isinstance(target.this, exp.Star):
        return True
    return False


def _projection_columns(node: exp.Expression) -> list[str]:
    target = node.this if isinstance(node, exp.Alias) else node
    if isinstance(target, exp.Column):
        if isinstance(target.this, exp.Star):
            return []
        name = target.name
        return [name] if name and name != "*" else []
    names: list[str] = []
    for column in target.find_all(exp.Column):
        if isinstance(column.this, exp.Star):
            continue
        name = column.name
        if name and name != "*":
            names.append(name)
    return names


def _extract_sql_nodes(trees: list[exp.Expression]) -> tuple[list[str], list[str], bool]:
    tables: list[str] = []
    columns: list[str] = []
    star_hit = False
    for tree in trees:
        for table in tree.find_all(exp.Table):
            name = table.name
            if name:
                tables.append(name)
        for select in tree.find_all(exp.Select):
            for expr in select.expressions:
                if _is_star_projection(expr):
                    star_hit = True
                    continue
                columns.extend(_projection_columns(expr))
    return _unique_keep_order(tables), columns, star_hit


def _unique_keep_order(items: list[str]) -> list[str]:
    unique: list[str] = []
    seen: set[str] = set()
    for item in items:
        key = item.lower()
        if key in seen:
            continue
        seen.add(key)
        unique.append(item)
    return unique


def _flatten_strings(value: Any) -> list[str]:
    if value is None or value == "":
        return []
    if isinstance(value, dict):
        out: list[str] = []
        for item in value.values():
            out.extend(_flatten_strings(item))
        return out
    if isinstance(value, list):
        out = []
        for item in value:
            out.extend(_flatten_strings(item))
        return out
    return [str(value)]


def _pii_pattern_hits(blob: str, patterns: list[Any]) -> list[str]:
    hits: list[str] = []
    for item in patterns:
        if not isinstance(item, dict):
            continue
        name = str(item.get("name") or "pii")
        regex = str(item.get("regex") or "")
        if regex and re.search(regex, blob):
            hits.append(name)
    return hits


def _deobfuscate_email_text(text: str) -> str:
    folded = fullwidth_to_halfwidth(nfkc(text or ""))
    folded = AT_TOKEN_RE.sub("@", folded)
    folded = DOT_TOKEN_RE.sub(".", folded)
    folded = re.sub(
        r"(?<=[A-Za-z0-9._%+\-])\s+at\s+(?=[A-Za-z0-9.\-]+\.[A-Za-z]{2,})",
        "@",
        folded,
        flags=re.IGNORECASE,
    )
    folded = re.sub(
        r"(?<=[A-Za-z0-9._%+\-])\s+dot\s+(?=[A-Za-z]{2,})",
        ".",
        folded,
        flags=re.IGNORECASE,
    )
    folded = re.sub(r"\s*@\s*", "@", folded)
    return folded


def _extract_emails_from_text(text: str) -> list[str]:
    found: list[str] = []
    seen: set[str] = set()
    for source in (text or "", _deobfuscate_email_text(text or "")):
        for match in EMAIL_RE.finditer(source):
            addr = match.group(0).strip().lower()
            if not addr or addr in seen:
                continue
            seen.add(addr)
            found.append(addr)
    return found


def _content_channel_emails(args: dict[str, Any], content_fields: list[str]) -> list[tuple[str, str]]:
    wanted = {field.lower() for field in content_fields}
    found: list[tuple[str, str]] = []
    for key, raw in args.items():
        field = str(key).lower()
        if field not in wanted:
            continue
        for text in _flatten_strings(raw):
            for addr in _extract_emails_from_text(text):
                found.append((field, addr))
    return _dedupe_recipients(found)


def _collect_nested_emails(
    args: dict[str, Any],
    skip_keys: set[str] | None = None,
) -> list[tuple[str, str]]:
    found: list[tuple[str, str]] = []
    skipped = {item.lower() for item in (skip_keys or set())}

    def walk(obj: Any, path: str) -> None:
        if isinstance(obj, dict):
            for key, value in obj.items():
                key_l = str(key).lower()
                if key_l in skipped:
                    continue
                walk(value, f"{path}.{key}" if path else str(key))
            return
        if isinstance(obj, list):
            for index, value in enumerate(obj):
                walk(value, f"{path}[{index}]")
            return
        if isinstance(obj, str):
            for addr in _extract_emails_from_text(obj):
                found.append((path or "arg", addr))

    walk(args, "")
    return found


def _dedupe_recipients(items: list[tuple[str, str]]) -> list[tuple[str, str]]:
    seen: set[str] = set()
    unique: list[tuple[str, str]] = []
    for field, addr in items:
        addr = addr.strip().strip("<>").lower()
        if not addr or addr in seen:
            continue
        seen.add(addr)
        unique.append((field, addr))
    return unique


def _collect_recipients(args: dict[str, Any], extra_fields: list[Any]) -> list[tuple[str, str]]:
    fields = ["to", *[str(item) for item in extra_fields]]
    found: list[tuple[str, str]] = []
    seen: set[str] = set()
    for field in fields:
        raw = args.get(field)
        if raw is None or raw == "":
            continue
        items = raw if isinstance(raw, list) else [raw]
        for item in items:
            for part in RECIPIENT_SPLIT_RE.split(str(item)):
                addr = part.strip().strip("<>").lower()
                if not addr or addr in seen:
                    continue
                seen.add(addr)
                found.append((field, addr))
    return found


def _email_domain(addr: str) -> str:
    if "@" not in addr:
        return ""
    return addr.split("@")[-1].strip().strip(".").lower()


def _suffix_match(domain: str, suffixes: list[str]) -> bool:
    domain = domain.lower().strip(".")
    for suffix in suffixes:
        suffix = suffix.lower().strip(".")
        if domain == suffix or domain.endswith("." + suffix):
            return True
    return False


def _denied_domain_hit(domain: str, denied: list[str]) -> str:
    domain = domain.lower().strip(".")
    if _suffix_match(domain, denied):
        matched = next(s for s in denied if domain == s.lower().strip(".") or domain.endswith("." + s.lower().strip(".")))
        return matched
    labels = domain.split(".")
    for needle in denied:
        parts = needle.lower().strip(".").split(".")
        size = len(parts)
        for index in range(0, len(labels) - size + 1):
            if labels[index : index + size] == parts:
                return needle
    return ""

