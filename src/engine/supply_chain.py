"""插件、Skill 与脚本供应链静态检测。

设计借鉴 MALOSS 的分层分析、DONAPI 公开描述的混淆/API 行为序列、
以及 typosquatting 的高置信名称变体；本实现完全独立，且不会执行待测代码。
"""

from __future__ import annotations

import ast
import hashlib
import json
import re
import tomllib
from collections import Counter
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Literal
from urllib.parse import urlparse

from src.config import (
    OUTPUT_DIR,
    SUPPLY_CHAIN_AUDIT_PATH,
    SUPPLY_CHAIN_HISTORY_PATH,
    SUPPLY_CHAIN_MANIFEST_PATH,
    SUPPLY_CHAIN_POLICY_PATH,
    SUPPLY_CHAIN_SAMPLES_DIR,
)
from src.engine.normalize import shannon_entropy as _entropy

Severity = Literal["critical", "high", "medium", "low"]
GateAction = Literal["BLOCK", "REVIEW", "ALLOW"]

SUPPLY_CHAIN_METHODS: list[dict[str, str]] = [
    {
        "id": "behavior",
        "name": "代码行为检测",
        "description": "静态提取 Python AST、JavaScript 与 Shell 中的文件、网络、进程、环境变量和编码调用，不 import、不安装、不执行样本。",
        "method": "按文件记录 API、行号与证据；同一文件内按行号关联 source→sink。",
    },
    {
        "id": "dependency",
        "name": "依赖关系分析",
        "description": "解析 package.json、requirements.txt、pyproject.toml 与 Skill 清单，识别 typosquatting、依赖混淆和内部命名空间冲突。",
        "method": "包名归一化后做 omission / transposition / homoglyph 高置信比对，并对照内部前缀与公共源快照。",
    },
    {
        "id": "malicious_logic",
        "name": "恶意逻辑识别",
        "description": "识别安装钩子下载执行、凭据读取后外联、混淆载荷、隐蔽域名与高危调用链。",
        "method": "生命周期脚本、黑名单外联、敏感路径读取、高熵编码串与行为序列规则独立计分。",
    },
    {
        "id": "rating",
        "name": "安全评级与安装门禁",
        "description": "按严重度加权得到分数，输出 BLOCK / REVIEW / ALLOW 与可复现审计证据。",
        "method": "critical/high 证据或超过 block_score 直接拦截；边界能力进入 REVIEW；无显著风险 ALLOW。",
    },
]


def supply_chain_methods() -> list[dict[str, str]]:
    return [dict(item) for item in SUPPLY_CHAIN_METHODS]


TEXT_MANIFESTS = {
    "package.json",
    "requirements.txt",
    "pyproject.toml",
    "skill.md",
    "plugin.json",
}
LIFECYCLE_SCRIPTS = {"preinstall", "install", "postinstall", "prepare"}
HOMOGLYPHS = {"0": "o", "1": "l", "3": "e", "5": "s", "7": "t", "@": "a"}
URL_RE = re.compile(r"https?://[^\s\"'<>]+", re.IGNORECASE)
BASE64_RE = re.compile(r"(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{80,}={0,2}(?![A-Za-z0-9+/])")
SECRET_PATH_RE = re.compile(r"(?:\.ssh|\.aws|\.env|id_rsa|credentials|keychain|passwd)", re.I)


@dataclass
class Finding:
    rule_id: str
    severity: Severity
    category: str
    title: str
    detail: str
    file: str = ""
    line: int = 0
    evidence: str = ""
    source: str = "SkillGuard"


@dataclass
class BehaviorEvent:
    kind: str
    file: str
    line: int
    api: str


@dataclass
class PackageReport:
    package_id: str
    name: str
    ecosystem: str
    package_type: str
    path: str
    sha256: str
    files_scanned: int
    dependencies: list[str]
    findings: list[Finding]
    behavior_events: list[BehaviorEvent]
    behavior_sequences: list[str]
    score: int
    risk_level: str
    action: GateAction
    expected_label: str = "unknown"
    expected_action: str = ""
    correct: bool | None = None

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["localization"] = self.localization()
        payload["reproduction"] = {
            "package_id": self.package_id,
            "path": self.path,
            "last_action": self.action,
            "replay_api": f"/api/supply-chain/reproduce/{self.package_id}",
        }
        return payload

    def localization(self) -> dict[str, Any]:
        root = self.findings[0] if self.findings else None
        return {
            "root_cause": root.rule_id if root else "",
            "root_detail": root.detail if root else "",
            "failed_rules": [item.rule_id for item in self.findings],
            "behavior_sequences": list(self.behavior_sequences),
            "dependencies": list(self.dependencies),
            "risk_level": self.risk_level,
            "action": self.action,
            "score": self.score,
        }


def _utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _normalise_name(name: str) -> str:
    text = (name or "").strip().lower()
    if text.startswith("@") and "/" in text:
        scope, package = text.split("/", 1)
        return f"{scope}/{re.sub(r'[-_.]+', '-', package)}"
    return re.sub(r"[-_.]+", "-", text)


def _damerau_levenshtein(left: str, right: str) -> int:
    if left == right:
        return 0
    rows = len(left) + 1
    cols = len(right) + 1
    distance = [[0] * cols for _ in range(rows)]
    for i in range(rows):
        distance[i][0] = i
    for j in range(cols):
        distance[0][j] = j
    for i in range(1, rows):
        for j in range(1, cols):
            cost = 0 if left[i - 1] == right[j - 1] else 1
            distance[i][j] = min(
                distance[i - 1][j] + 1,
                distance[i][j - 1] + 1,
                distance[i - 1][j - 1] + cost,
            )
            if i > 1 and j > 1 and left[i - 1] == right[j - 2] and left[i - 2] == right[j - 1]:
                distance[i][j] = min(distance[i][j], distance[i - 2][j - 2] + cost)
    return distance[-1][-1]


def _typo_relation(candidate: str, trusted: str) -> str:
    candidate_n = _normalise_name(candidate)
    trusted_n = _normalise_name(trusted)
    if not candidate_n or candidate_n == trusted_n:
        return ""
    folded = "".join(HOMOGLYPHS.get(char, char) for char in candidate_n)
    if folded == trusted_n:
        return "homoglyph"
    if len(candidate_n) >= 5 and _damerau_levenshtein(candidate_n, trusted_n) == 1:
        if len(candidate_n) + 1 == len(trusted_n):
            return "omission"
        if len(candidate_n) == len(trusted_n) and sorted(candidate_n) == sorted(trusted_n):
            return "transposition"
        return "replacement/repetition"
    return ""


def _call_name(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        prefix = _call_name(node.value)
        return f"{prefix}.{node.attr}" if prefix else node.attr
    return ""


def _literal_string(node: ast.AST | None) -> str:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return ""


class SupplyChainScanner:
    """离线、无执行的供应链安装门禁。"""

    def __init__(self, policy_path: Path | None = None) -> None:
        self.policy_path = policy_path or SUPPLY_CHAIN_POLICY_PATH
        self.policy = json.loads(self.policy_path.read_text(encoding="utf-8"))
        self.weights = self.policy.get("risk_weights") or {}
        self.extensions = {str(item).lower() for item in self.policy.get("source_extensions") or []}

    def scan_corpus(
        self,
        root: Path | None = None,
        manifest_path: Path | None = None,
        output_path: Path | None = SUPPLY_CHAIN_AUDIT_PATH,
    ) -> dict[str, Any]:
        corpus = (root or SUPPLY_CHAIN_SAMPLES_DIR).resolve()
        manifest_file = manifest_path or SUPPLY_CHAIN_MANIFEST_PATH
        manifest = json.loads(manifest_file.read_text(encoding="utf-8"))
        reports: list[PackageReport] = []
        for item in manifest.get("packages") or []:
            relative = Path(str(item["path"]))
            target = (corpus / relative).resolve()
            if corpus != target and corpus not in target.parents:
                raise ValueError(f"样本路径越界：{relative}")
            reports.append(
                self.scan_package(
                    target,
                    package_id=str(item.get("id") or relative.name),
                    expected_label=str(item.get("expected_label") or "unknown"),
                    expected_action=str(item.get("expected_action") or ""),
                )
            )
        bundle = self._bundle(reports, manifest.get("dataset_name") or "supply-chain-bench")
        if output_path is not None:
            output_path.parent.mkdir(parents=True, exist_ok=True)
            output_path.write_text(json.dumps(bundle, ensure_ascii=False, indent=2), encoding="utf-8")
            if output_path.resolve() == SUPPLY_CHAIN_AUDIT_PATH.resolve():
                append_supply_chain_history(bundle.get("meta") or {})
        return bundle

    def reproduce_package(self, package_id: str) -> dict[str, Any]:
        """复现单包：按当前策略重新静态扫描，不执行代码，也不改写总审计。"""
        manifest = json.loads(SUPPLY_CHAIN_MANIFEST_PATH.read_text(encoding="utf-8"))
        item = next((row for row in (manifest.get("packages") or []) if str(row.get("id")) == package_id), None)
        if not item:
            raise ValueError(f"未找到供应链样本 {package_id}")
        relative = Path(str(item["path"]))
        target = (SUPPLY_CHAIN_SAMPLES_DIR / relative).resolve()
        if SUPPLY_CHAIN_SAMPLES_DIR.resolve() not in target.parents and target != SUPPLY_CHAIN_SAMPLES_DIR.resolve():
            raise ValueError(f"样本路径越界：{relative}")
        report = self.scan_package(
            target,
            package_id=package_id,
            expected_label=str(item.get("expected_label") or "unknown"),
            expected_action=str(item.get("expected_action") or ""),
        )
        prior = next(
            (row for row in (load_supply_chain_audit().get("packages") or []) if row.get("package_id") == package_id),
            None,
        )
        previous_action = str((prior or {}).get("action") or "")
        return {
            "replay_from": "static-rescan",
            "previous_action": previous_action,
            "status_changed": bool(previous_action) and previous_action != report.action,
            "report": report.to_dict(),
        }

    def scan_package(
        self,
        package_path: Path,
        *,
        package_id: str | None = None,
        expected_label: str = "unknown",
        expected_action: str = "",
    ) -> PackageReport:
        root = package_path.resolve()
        if not root.exists() or not root.is_dir():
            raise ValueError(f"待测包目录不存在：{root}")
        files = self._collect_files(root)
        metadata = self._metadata(root)
        name = metadata["name"] or root.name
        ecosystem = metadata["ecosystem"]
        dependencies = metadata["dependencies"]
        findings: list[Finding] = []
        events: list[BehaviorEvent] = []

        findings.extend(self._metadata_findings(root, metadata))
        findings.extend(self._name_findings(name, "package", ""))
        for dependency in dependencies:
            findings.extend(self._name_findings(dependency, "dependency", metadata.get("manifest", "")))
            if self._is_dependency_confusion(dependency):
                findings.append(
                    Finding(
                        rule_id="supply.dependency_confusion",
                        severity="critical",
                        category="dependency",
                        title="内部包名出现在公共源快照",
                        detail=f"依赖 `{dependency}` 同时符合内部命名空间且出现在公共仓库快照，存在依赖混淆风险。",
                        file=metadata.get("manifest", ""),
                        evidence=dependency,
                        source="typosquatting-inspired",
                    )
                )

        for path in files:
            relative = path.relative_to(root).as_posix()
            if path.suffix.lower() not in self.extensions:
                continue
            try:
                text = path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            findings.extend(self._obfuscation_findings(text, relative))
            findings.extend(self._url_findings(text, relative))
            if path.suffix.lower() == ".py":
                file_events, file_findings = self._scan_python(text, relative)
            else:
                file_events, file_findings = self._scan_textual_code(text, relative, path.suffix.lower())
            events.extend(file_events)
            findings.extend(file_findings)

        sequences, sequence_findings = self._correlate_behaviors(events)
        findings.extend(sequence_findings)
        findings = self._dedupe_findings(findings)
        score = min(100, sum(int(self.weights.get(item.severity, 0)) for item in findings))
        if any(item.severity == "critical" for item in findings) or score >= int(self.policy.get("block_score", 60)):
            action: GateAction = "BLOCK"
        elif score >= int(self.policy.get("review_score", 25)):
            action = "REVIEW"
        else:
            action = "ALLOW"
        if any(item.severity == "critical" for item in findings):
            risk_level = "critical"
        elif action == "BLOCK":
            risk_level = "high"
        elif action == "REVIEW":
            risk_level = "medium"
        else:
            risk_level = "low"
        correct = None if not expected_action else action == expected_action
        return PackageReport(
            package_id=package_id or root.name,
            name=name,
            ecosystem=ecosystem,
            package_type=metadata["package_type"],
            path=root.name,
            sha256=self._package_hash(root, files),
            files_scanned=len(files),
            dependencies=dependencies,
            findings=findings,
            behavior_events=events,
            behavior_sequences=sequences,
            score=score,
            risk_level=risk_level,
            action=action,
            expected_label=expected_label,
            expected_action=expected_action,
            correct=correct,
        )

    def _collect_files(self, root: Path) -> list[Path]:
        max_files = int(self.policy.get("max_files", 500))
        max_bytes = int(self.policy.get("max_file_bytes", 1048576))
        ignored = {"node_modules", ".git", ".venv", "venv", "dist", "build", "__pycache__"}
        files: list[Path] = []
        for path in sorted(root.rglob("*")):
            if any(part in ignored for part in path.relative_to(root).parts):
                continue
            if path.is_symlink() or not path.is_file():
                continue
            try:
                if path.stat().st_size > max_bytes:
                    continue
            except OSError:
                continue
            files.append(path)
            if len(files) >= max_files:
                break
        return files

    def _metadata(self, root: Path) -> dict[str, Any]:
        result: dict[str, Any] = {
            "name": root.name,
            "ecosystem": "generic",
            "package_type": "script",
            "dependencies": [],
            "scripts": {},
            "manifest": "",
        }
        package_json = root / "package.json"
        pyproject = root / "pyproject.toml"
        skill_md = root / "SKILL.md"
        requirements = root / "requirements.txt"
        if package_json.exists():
            try:
                data = json.loads(package_json.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                data = {}
            result.update(
                {
                    "name": str(data.get("name") or root.name),
                    "ecosystem": "npm",
                    "package_type": "plugin",
                    "dependencies": sorted(
                        set((data.get("dependencies") or {})) | set((data.get("devDependencies") or {}))
                    ),
                    "scripts": dict(data.get("scripts") or {}),
                    "manifest": "package.json",
                }
            )
        elif pyproject.exists():
            try:
                data = tomllib.loads(pyproject.read_text(encoding="utf-8"))
            except (OSError, tomllib.TOMLDecodeError):
                data = {}
            project = data.get("project") or {}
            raw_deps = project.get("dependencies") or []
            deps = [re.split(r"[<>=!~\[; ]", str(item), maxsplit=1)[0] for item in raw_deps]
            result.update(
                {
                    "name": str(project.get("name") or root.name),
                    "ecosystem": "pypi",
                    "package_type": "plugin",
                    "dependencies": sorted(set(filter(None, deps))),
                    "manifest": "pyproject.toml",
                }
            )
        elif requirements.exists():
            deps = []
            for line in requirements.read_text(encoding="utf-8", errors="replace").splitlines():
                clean = line.split("#", 1)[0].strip()
                if clean and not clean.startswith(("-", "http:", "https:")):
                    deps.append(re.split(r"[<>=!~\[; ]", clean, maxsplit=1)[0])
            result.update({"ecosystem": "pypi", "dependencies": sorted(set(deps)), "manifest": "requirements.txt"})
        if skill_md.exists():
            text = skill_md.read_text(encoding="utf-8", errors="replace")
            match = re.search(r"(?m)^name:\s*[\"']?([^\n\"']+)", text[:4000])
            if match:
                result["name"] = match.group(1).strip()
            result["package_type"] = "skill"
            if not result["manifest"]:
                result["manifest"] = "SKILL.md"
        return result

    def _metadata_findings(self, root: Path, metadata: dict[str, Any]) -> list[Finding]:
        findings: list[Finding] = []
        scripts = metadata.get("scripts") or {}
        for name, command in scripts.items():
            if name in LIFECYCLE_SCRIPTS:
                severity: Severity = "critical" if re.search(r"(?:curl|wget|powershell|node\s+-e|python\s+-c|bash\s+-c)", str(command), re.I) else "high"
                findings.append(
                    Finding(
                        rule_id="supply.lifecycle_script",
                        severity=severity,
                        category="install-hook",
                        title="安装阶段执行脚本",
                        detail=f"npm `{name}` 生命周期脚本会在安装阶段自动执行。",
                        file="package.json",
                        evidence=str(command)[:240],
                        source="MALOSS-inspired metadata",
                    )
                )
        if not metadata.get("manifest"):
            findings.append(
                Finding(
                    rule_id="supply.missing_manifest",
                    severity="low",
                    category="metadata",
                    title="缺少包清单",
                    detail="未发现 package.json、pyproject.toml、requirements.txt 或 SKILL.md。",
                )
            )
        return findings

    def _name_findings(self, name: str, role: str, file: str) -> list[Finding]:
        for trusted in self.policy.get("trusted_package_names") or []:
            relation = _typo_relation(name, str(trusted))
            if relation:
                return [
                    Finding(
                        rule_id="supply.typosquat",
                        severity="high",
                        category="name",
                        title="高置信名称仿冒",
                        detail=f"{role} `{name}` 与可信包 `{trusted}` 仅存在高置信 `{relation}` 差异，需核验来源。",
                        file=file,
                        evidence=f"{name} -> {trusted}",
                        source="typosquatting-inspired",
                    )
                ]
        return []

    def _is_dependency_confusion(self, dependency: str) -> bool:
        normal = _normalise_name(dependency)
        internal = any(normal.startswith(_normalise_name(prefix)) for prefix in self.policy.get("internal_name_prefixes") or [])
        public = normal in {_normalise_name(item) for item in self.policy.get("public_registry_snapshot") or []}
        return internal and public

    def _scan_python(self, text: str, file: str) -> tuple[list[BehaviorEvent], list[Finding]]:
        events: list[BehaviorEvent] = []
        findings: list[Finding] = []
        try:
            tree = ast.parse(text)
        except SyntaxError as exc:
            return events, [Finding("supply.python_parse", "medium", "static", "Python AST 解析失败", str(exc), file=file, line=exc.lineno or 0)]
        aliases: dict[str, str] = {}
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for item in node.names:
                    aliases[item.asname or item.name.split(".", 1)[0]] = item.name
            elif isinstance(node, ast.ImportFrom) and node.module:
                for item in node.names:
                    aliases[item.asname or item.name] = f"{node.module}.{item.name}"
        event_map = {
            "subprocess.run": "execute", "subprocess.call": "execute", "subprocess.Popen": "execute",
            "os.system": "execute", "os.popen": "execute", "eval": "execute", "exec": "execute",
            "requests.get": "network", "requests.post": "network", "urllib.request.urlopen": "network",
            "httpx.get": "network", "httpx.post": "network", "aiohttp.request": "network",
            "socket.create_connection": "network", "socket.socket": "network",
            "os.getenv": "environment", "os.environ.get": "environment",
            "base64.b64decode": "decode", "codecs.decode": "decode",
            "os.chmod": "permission", "Path.chmod": "permission",
        }
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                name = _call_name(node.func)
                head, separator, tail = name.partition(".")
                if head in aliases:
                    name = aliases[head] + (separator + tail if separator else "")
                kind = event_map.get(name)
                if kind:
                    events.append(BehaviorEvent(kind, file, getattr(node, "lineno", 0), name))
                if name == "open" or name.endswith(".open"):
                    path_arg = _literal_string(node.args[0] if node.args else None)
                    mode = _literal_string(node.args[1] if len(node.args) > 1 else None)
                    if SECRET_PATH_RE.search(path_arg):
                        events.append(BehaviorEvent("sensitive_read", file, getattr(node, "lineno", 0), f"open({path_arg})"))
                    elif any(flag in mode for flag in ("w", "a", "x")):
                        events.append(BehaviorEvent("file_write", file, getattr(node, "lineno", 0), "open(write)"))
                if isinstance(node.func, ast.Attribute) and node.func.attr in {"read_text", "read_bytes", "write_text", "write_bytes"}:
                    owner = node.func.value
                    path_arg = ""
                    if isinstance(owner, ast.Call) and _call_name(owner.func) in {"Path", "pathlib.Path"}:
                        path_arg = _literal_string(owner.args[0] if owner.args else None)
                    if node.func.attr.startswith("read") and SECRET_PATH_RE.search(path_arg):
                        events.append(BehaviorEvent("sensitive_read", file, getattr(node, "lineno", 0), f"Path({path_arg}).{node.func.attr}"))
                    elif node.func.attr.startswith("write"):
                        events.append(BehaviorEvent("file_write", file, getattr(node, "lineno", 0), node.func.attr))
                if kind == "execute":
                    findings.append(Finding("supply.dynamic_execution", "high", "execution", "动态代码或命令执行", f"检测到高危执行 API `{name}`。", file, getattr(node, "lineno", 0), name, "DONAPI-inspired API map"))
        events.sort(key=lambda item: (item.file, item.line))
        return events, findings

    def _scan_textual_code(self, text: str, file: str, suffix: str) -> tuple[list[BehaviorEvent], list[Finding]]:
        patterns = [
            ("sensitive_read", r"(?:\.ssh|\.aws|id_rsa|credentials|process\.env|/etc/passwd)", "sensitive source"),
            ("environment", r"(?:process\.env|Get-ChildItem\s+Env:|\$env:)", "environment"),
            ("network", r"(?:fetch\s*\(|axios\.|https?\.request|curl\s+|wget\s+|Invoke-WebRequest)", "network"),
            ("decode", r"(?:atob\s*\(|Buffer\.from\([^\n]+base64|base64\s+-d)", "decode"),
            ("file_write", r"(?:writeFile|writeFileSync|>\s*[/~.]|Set-Content)", "file write"),
            ("permission", r"(?:chmod\s+\+?x|fs\.chmod)", "permission"),
            ("execute", r"(?:\beval\s*\(|new\s+Function\s*\(|child_process|\.exec\s*\(|spawn\s*\(|bash\s+-c|sh\s+-c|powershell\s+-enc)", "execute"),
        ]
        events: list[BehaviorEvent] = []
        findings: list[Finding] = []
        for line_no, line in enumerate(text.splitlines(), start=1):
            for kind, pattern, api in patterns:
                if re.search(pattern, line, re.I):
                    events.append(BehaviorEvent(kind, file, line_no, api))
                    if kind == "execute":
                        findings.append(Finding("supply.dynamic_execution", "high", "execution", "动态代码或命令执行", "检测到命令执行或动态求值模式。", file, line_no, line.strip()[:240], "DONAPI-inspired API map"))
                    elif kind == "permission":
                        findings.append(Finding("supply.permission_change", "high", "permission", "修改可执行权限", "包内脚本会修改文件执行权限，安装前应由管理员复核。", file, line_no, line.strip()[:240], "DONAPI-inspired API map"))
        return events, findings

    def _obfuscation_findings(self, text: str, file: str) -> list[Finding]:
        lines = text.splitlines() or [text]
        max_line = max((len(line) for line in lines), default=0)
        identifiers = re.findall(r"\b[A-Za-z_$][A-Za-z0-9_$]*\b", text)
        identifier_entropy = _entropy("".join(identifiers))
        base64_hit = BASE64_RE.search(text)
        escaped = len(re.findall(r"(?:\\x[0-9a-fA-F]{2}|\\u[0-9a-fA-F]{4}|0x[0-9a-fA-F]+)", text))
        findings: list[Finding] = []
        signals = []
        if max_line >= 500:
            signals.append(f"最长行 {max_line} 字符")
        if base64_hit:
            signals.append(f"长编码串 {len(base64_hit.group(0))} 字符")
        if escaped >= 8:
            signals.append(f"十六进制/Unicode 转义 {escaped} 处")
        if len(identifiers) >= 20 and identifier_entropy >= 5.0:
            signals.append(f"标识符熵 {identifier_entropy:.2f}")
        if signals:
            findings.append(
                Finding(
                    rule_id="supply.obfuscation",
                    severity="medium",
                    category="obfuscation",
                    title="代码混淆特征",
                    detail="；".join(signals),
                    file=file,
                    evidence=(base64_hit.group(0)[:80] + "…") if base64_hit else "",
                    source="DONAPI-inspired features",
                )
            )
        return findings

    def _url_findings(self, text: str, file: str) -> list[Finding]:
        allowed = [str(item).lower() for item in self.policy.get("allowed_network_domains") or []]
        blocked = [str(item).lower() for item in self.policy.get("blocked_network_domains") or []]
        findings: list[Finding] = []
        for match in URL_RE.finditer(text):
            url = match.group(0).rstrip(".,);]")
            domain = (urlparse(url).hostname or "").lower()
            line = text.count("\n", 0, match.start()) + 1
            if any(domain == item or domain.endswith("." + item) for item in blocked):
                severity: Severity = "critical"
                title = "命中外联黑名单"
            elif allowed and not any(domain == item or domain.endswith("." + item) for item in allowed):
                severity = "medium"
                title = "未知外联域名"
            else:
                continue
            findings.append(Finding("supply.network_destination", severity, "network", title, f"硬编码网络目标 `{domain}`。", file, line, url, "MALOSS-inspired static"))
        return findings

    def _correlate_behaviors(self, events: list[BehaviorEvent]) -> tuple[list[str], list[Finding]]:
        grouped: dict[str, list[BehaviorEvent]] = {}
        for event in events:
            grouped.setdefault(event.file, []).append(event)
        definitions = [
            ("sensitive_read", "network", "敏感文件读取→网络外传", "critical", "supply.sequence_sensitive_exfil"),
            ("environment", "network", "环境变量读取→网络外传", "critical", "supply.sequence_env_exfil"),
            ("network", "execute", "网络下载→代码/命令执行", "critical", "supply.sequence_download_execute"),
            ("decode", "execute", "载荷解码→动态执行", "critical", "supply.sequence_decode_execute"),
            ("file_write", "execute", "文件落地→进程执行", "high", "supply.sequence_drop_execute"),
            ("permission", "execute", "修改权限→进程执行", "high", "supply.sequence_permission_execute"),
        ]
        sequences: list[str] = []
        findings: list[Finding] = []
        for file, items in grouped.items():
            items.sort(key=lambda item: item.line)
            for source, sink, label, severity, rule_id in definitions:
                source_event = next((item for item in items if item.kind == source), None)
                sink_event = next((item for item in items if item.kind == sink and (source_event is None or item.line >= source_event.line)), None)
                if source_event and sink_event:
                    sequences.append(f"{file}: {label}")
                    findings.append(
                        Finding(
                            rule_id=rule_id,
                            severity=severity,  # type: ignore[arg-type]
                            category="behavior-sequence",
                            title=label,
                            detail=f"静态 API 顺序：{source_event.api}@L{source_event.line} → {sink_event.api}@L{sink_event.line}。",
                            file=file,
                            line=source_event.line,
                            evidence=f"{source_event.kind} -> {sink_event.kind}",
                            source="DONAPI-inspired sequence",
                        )
                    )
        return sequences, findings

    def _dedupe_findings(self, findings: Iterable[Finding]) -> list[Finding]:
        unique: list[Finding] = []
        seen: set[tuple[str, str, int, str]] = set()
        for finding in findings:
            key = (finding.rule_id, finding.file, finding.line, finding.evidence)
            if key in seen:
                continue
            seen.add(key)
            unique.append(finding)
        order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        unique.sort(key=lambda item: (order[item.severity], item.file, item.line, item.rule_id))
        return unique

    def _package_hash(self, root: Path, files: list[Path]) -> str:
        digest = hashlib.sha256()
        for path in files:
            digest.update(path.relative_to(root).as_posix().encode("utf-8"))
            try:
                digest.update(path.read_bytes())
            except OSError:
                continue
        return digest.hexdigest()

    def _bundle(self, reports: list[PackageReport], dataset_name: str) -> dict[str, Any]:
        malicious = [item for item in reports if item.expected_label == "malicious"]
        benign = [item for item in reports if item.expected_label == "benign"]
        malicious_blocked = sum(item.action == "BLOCK" for item in malicious)
        malicious_detected = sum(item.action in {"BLOCK", "REVIEW"} for item in malicious)
        benign_blocked = sum(item.action == "BLOCK" for item in benign)
        benign_reviewed = sum(item.action == "REVIEW" for item in benign)
        correct = sum(item.correct is True for item in reports if item.correct is not None)
        labeled = sum(item.correct is not None for item in reports)
        status_counts = Counter(item.action for item in reports)
        severity_counts = Counter(finding.severity for item in reports for finding in item.findings)
        metrics = {
            "malicious_block_rate": round(malicious_blocked / len(malicious), 4) if malicious else 0.0,
            "malicious_detection_rate": round(malicious_detected / len(malicious), 4) if malicious else 0.0,
            "benign_block_fpr": round(benign_blocked / len(benign), 4) if benign else 0.0,
            "benign_review_rate": round(benign_reviewed / len(benign), 4) if benign else 0.0,
            "expected_action_accuracy": round(correct / labeled, 4) if labeled else 0.0,
            "review_rate": round(status_counts["REVIEW"] / len(reports), 4) if reports else 0.0,
        }
        meta = {
            "generated_at": _utc_now(),
            "dataset_name": dataset_name,
            "analysis_mode": "static-no-execution",
            "total_packages": len(reports),
            "malicious_packages": len(malicious),
            "benign_packages": len(benign),
            "status_counts": dict(status_counts),
            "severity_counts": dict(severity_counts),
            "metrics": metrics,
            "method_sources": ["MALOSS-inspired", "DONAPI-inspired", "typosquatting-inspired"],
            "methods": supply_chain_methods(),
        }
        meta["optimization"] = build_supply_chain_optimization(meta, reports)
        return {
            "meta": meta,
            "packages": [item.to_dict() for item in reports],
        }


def load_supply_chain_audit(path: Path | None = None) -> dict[str, Any]:
    target = path or SUPPLY_CHAIN_AUDIT_PATH
    if not target.exists():
        return {"meta": {}, "packages": []}
    payload = json.loads(target.read_text(encoding="utf-8"))
    payload.setdefault("meta", {})
    payload.setdefault("packages", [])
    return payload


def load_supply_chain_history() -> list[dict[str, Any]]:
    if not SUPPLY_CHAIN_HISTORY_PATH.exists():
        return []
    try:
        payload = json.loads(SUPPLY_CHAIN_HISTORY_PATH.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return []
    return payload if isinstance(payload, list) else []


def append_supply_chain_history(meta: dict[str, Any]) -> None:
    snapshot = {
        "generated_at": meta.get("generated_at") or "",
        "metrics": dict(meta.get("metrics") or {}),
        "status_counts": dict(meta.get("status_counts") or {}),
        "malicious_packages": meta.get("malicious_packages"),
        "benign_packages": meta.get("benign_packages"),
    }
    history = load_supply_chain_history()
    if history and history[-1].get("generated_at") == snapshot["generated_at"]:
        history[-1] = snapshot
    else:
        history.append(snapshot)
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    SUPPLY_CHAIN_HISTORY_PATH.write_text(
        json.dumps(history[-20:], ensure_ascii=False, indent=2),
        encoding="utf-8",
    )


def build_supply_chain_optimization(meta: dict[str, Any], reports: list[PackageReport]) -> dict[str, Any]:
    metrics = meta.get("metrics") or {}
    actions: list[str] = []
    missed = [
        item.package_id
        for item in reports
        if item.expected_label == "malicious" and item.action == "ALLOW"
    ]
    false_block = [
        item.package_id
        for item in reports
        if item.expected_label == "benign" and item.action == "BLOCK"
    ]
    if missed:
        actions.append(f"恶意组件未被拦截：{', '.join(missed)}。优先核对外联、安装钩子和行为序列规则。")
    elif float(metrics.get("malicious_detection_rate") or 0) >= 1:
        actions.append("恶意组件均已检出。下一轮扩招未知插件或新行为序列，而不是继续调已命中规则。")
    if false_block:
        actions.append(f"正常组件被误拦：{', '.join(false_block)}。核对待信包名与评分门槛。")
    if float(metrics.get("benign_review_rate") or 0) > 0:
        actions.append("存在正常组件进入复核。管理员能力脚本应保持 REVIEW，不得默认放行。")
    history = load_supply_chain_history()
    delta: dict[str, Any] = {}
    if history:
        prev = (history[-1].get("metrics") or {})
        delta = {
            "malicious_detection_rate": round(
                float(metrics.get("malicious_detection_rate") or 0) - float(prev.get("malicious_detection_rate") or 0),
                4,
            ),
            "benign_block_fpr": round(
                float(metrics.get("benign_block_fpr") or 0) - float(prev.get("benign_block_fpr") or 0),
                4,
            ),
            "previous_at": history[-1].get("generated_at") or "",
        }
        if delta["malicious_detection_rate"] < 0:
            actions.append("相对上次扫描，恶意检出率下降。先用单包复现定位失效规则。")
        if delta["benign_block_fpr"] > 0:
            actions.append("相对上次扫描，正常组件误拦上升。对照评分门槛做效果验证。")
    rule_counts: Counter[str] = Counter()
    for item in reports:
        if item.expected_label != "malicious":
            continue
        seen: set[str] = set()
        for finding in item.findings:
            if finding.rule_id in seen:
                continue
            seen.add(finding.rule_id)
            rule_counts[finding.rule_id] += 1
    return {
        "missed_malicious": missed,
        "false_blocked": false_block,
        "top_detection_rules": [{"rule_id": key, "malicious_hits": value} for key, value in rule_counts.most_common(8)],
        "history_delta": delta,
        "next_actions": actions,
    }
