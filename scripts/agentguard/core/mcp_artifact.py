import json
import os
import re
from typing import Any, Dict, Iterable, List, Sequence, Tuple

from .analyzer import SkillAnalyzer
from .rules import CRITICAL, HIGH, MEDIUM


MAX_CAPTURE_BYTES = 10 * 1024 * 1024
MAX_EVENTS = 10000
MAX_DEPTH = 40
MAX_TEXT_LENGTH = 200000
SECRET_PATTERNS = (
    (re.compile(r"(?i)\b(authorization\s*[:=]\s*bearer\s+)[A-Za-z0-9._~+/-]{8,}"), r"\1[已脱敏]"),
    (re.compile(r"(?i)\b(api[_-]?key|access[_-]?token|refresh[_-]?token|password|secret|cookie)"
                r"(\s*[:=]\s*['\"]?)[^\s'\",;}]{6,}"), r"\1\2[已脱敏]"),
    (re.compile(r"\bsk-[A-Za-z0-9_-]{12,}\b"), "sk-[已脱敏]"),
    (re.compile(r"\bey[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b"), "[JWT 已脱敏]"),
    (re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----", re.DOTALL),
     "[私钥已脱敏]"),
)


class McpCaptureError(ValueError):
    """MCP 审计包无法安全解析。"""


def load_mcp_capture(filepath: str) -> Any:
    """读取 JSON 或 JSONL 审计包；不执行其中任何内容。"""
    try:
        size = os.path.getsize(filepath)
    except OSError as exc:
        raise McpCaptureError(f"无法读取审计包: {exc}") from exc
    if size > MAX_CAPTURE_BYTES:
        raise McpCaptureError(f"审计包超过 {MAX_CAPTURE_BYTES} 字节限制")
    try:
        with open(filepath, "r", encoding="utf-8", errors="strict") as source:
            raw = source.read()
    except (OSError, UnicodeError) as exc:
        raise McpCaptureError(f"无法读取 UTF-8 审计包: {exc}") from exc
    return parse_mcp_capture(raw)


def parse_mcp_capture(raw: str) -> Any:
    """解析受大小限制的 JSON/JSONL 文本。"""
    if len(raw.encode("utf-8")) > MAX_CAPTURE_BYTES:
        raise McpCaptureError(f"审计包超过 {MAX_CAPTURE_BYTES} 字节限制")
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        events = []
        for line_no, line in enumerate(raw.splitlines(), 1):
            if not line.strip():
                continue
            if len(events) >= MAX_EVENTS:
                raise McpCaptureError(f"JSONL 事件超过 {MAX_EVENTS} 条限制")
            try:
                events.append(json.loads(line))
            except json.JSONDecodeError as exc:
                raise McpCaptureError(f"JSONL 第 {line_no} 行不是合法 JSON: {exc.msg}") from exc
        if not events:
            raise McpCaptureError("审计包不是合法 JSON 或 JSONL")
        return events


def redact_mcp_secret(text: str) -> str:
    """在证据进入报告前脱敏常见凭据格式。"""
    redacted = text
    for pattern, replacement in SECRET_PATTERNS:
        redacted = pattern.sub(replacement, redacted)
    return redacted


class McpArtifactAnalyzer:
    """审计已捕获的 MCP 清单与调用结果，不连接或调用 MCP。"""

    _CROSS_TOOL = re.compile(
        r"(?:must|always|first|before\s+(?:using|answering|continuing)|required\s+to)"
        r"[^\n.!?;]{0,80}\b(?:call|invoke|use|run)\b[^\n.!?;]{0,60}\b(?:tool|function|command)\b|"
        r"(?:必须|务必|始终|先|在.{0,12}之前)[^\n。！？；]{0,80}(?:调用|使用|运行|执行)"
        r"[^\n。！？；]{0,40}(?:工具|函数|命令)",
        re.IGNORECASE,
    )
    _SECRET_ARGUMENT = re.compile(
        r"(?:include|provide|pass|attach|insert|copy)[^\n.!?;]{0,80}"
        r"(?:password|api[ _-]?key|access[ _-]?token|credential|private key|cookie)|"
        r"(?:提供|传入|附加|插入|复制|携带)[^\n。！？；]{0,80}"
        r"(?:密码|口令|API[ _-]?密钥|访问令牌|凭据|私钥|Cookie)",
        re.IGNORECASE,
    )
    _FAKE_AUTHORITY = re.compile(
        r"(?:this|these)\s+(?:instructions?|tool output|message)\s+(?:is|are)\s+"
        r"(?:trusted|authoritative|higher priority|a system message)|"
        r"(?:trust|obey|follow)\s+(?:this|these)\s+(?:instructions?|tool output)|"
        r"(?:本|这些)(?:指令|工具输出|消息).{0,20}(?:可信|权威|优先级更高|系统消息)|"
        r"(?:信任|服从|遵循)(?:本|这些)(?:指令|工具输出)",
        re.IGNORECASE,
    )
    _AGENT_DIRECTED = re.compile(
        r"(?:you|the\s+agent|assistant|model)\s+(?:must|should|need\s+to|has\s+to)|"
        r"(?:必须|应当|需要|务必)(?:让|要求)?(?:Agent|代理|助手|模型)?",
        re.IGNORECASE,
    )
    _MUTATING_NAME = re.compile(
        r"(?:^|[_-])(?:create|update|write|send|publish|execute|run|upload|approve|grant|"
        r"delete|remove|drop|destroy)(?:$|[_-])", re.IGNORECASE)
    _DESTRUCTIVE_NAME = re.compile(
        r"(?:^|[_-])(?:delete|remove|drop|destroy|wipe|revoke)(?:$|[_-])", re.IGNORECASE)

    def __init__(self) -> None:
        self.base = SkillAnalyzer()
        self.prompt_rules = self.base.prompt_rules

    def analyze(self, capture: Any, source: str) -> Dict[str, Any]:
        self._validate_shape(capture, 0)
        issues: List[Dict[str, Any]] = []
        surfaces = list(self._extract_surfaces(capture, "$", "capture", 0))
        for path, context, text in surfaces:
            issues.extend(self._scan_surface(source, path, context, text))
        issues.extend(self._inspect_tool_metadata(capture, source))
        issues.extend(self._detect_chains(issues, source))
        return {
            "name": f"MCP Capture: {os.path.basename(source)}",
            "path": source,
            "issues": self._deduplicate(issues),
            "surface_count": len(surfaces),
        }

    def _validate_shape(self, value: Any, depth: int) -> None:
        if depth > MAX_DEPTH:
            raise McpCaptureError(f"JSON 嵌套超过 {MAX_DEPTH} 层限制")
        if isinstance(value, str) and len(value) > MAX_TEXT_LENGTH:
            raise McpCaptureError(f"单个文本字段超过 {MAX_TEXT_LENGTH} 字符限制")
        if isinstance(value, dict):
            for item in value.values():
                self._validate_shape(item, depth + 1)
        elif isinstance(value, list):
            if len(value) > MAX_EVENTS:
                raise McpCaptureError(f"数组元素超过 {MAX_EVENTS} 条限制")
            for item in value:
                self._validate_shape(item, depth + 1)

    def _extract_surfaces(self, value: Any, path: str, context: str,
                          depth: int) -> Iterable[Tuple[str, str, str]]:
        if depth > MAX_DEPTH:
            return
        if isinstance(value, dict):
            # tools/call 请求的 params.arguments 来自调用方，不属于 MCP 服务端输出。
            is_tool_call_request = value.get("method") == "tools/call" and "result" not in value
            for key, item in value.items():
                if is_tool_call_request and key == "params":
                    continue
                child_path = f"{path}.{key}"
                child_context = self._context_for(key, path, context)
                if isinstance(item, str) and self._is_text_surface(key, path, context):
                    yield child_path, child_context, item
                elif isinstance(item, (dict, list)):
                    yield from self._extract_surfaces(item, child_path, child_context, depth + 1)
        elif isinstance(value, list):
            for index, item in enumerate(value):
                child_path = f"{path}[{index}]"
                if isinstance(item, str) and context in {
                        "tool_metadata", "tool_result", "prompt", "resource", "error"}:
                    yield child_path, context, item
                else:
                    yield from self._extract_surfaces(item, child_path, context, depth + 1)

    @staticmethod
    def _context_for(key: str, path: str, current: str) -> str:
        lowered = key.lower()
        if lowered in {"tools", "inputschema", "outputschema", "annotations"} or ".tools" in path:
            return "tool_metadata"
        if lowered in {"prompts", "prompt", "messages"} or ".prompts" in path:
            return "prompt"
        if lowered in {"resources", "resource", "contents"} or ".resources" in path:
            return "resource"
        if lowered in {"structuredcontent", "content"}:
            return "tool_result"
        if lowered in {"error", "errors", "message", "data"} and current != "tool_metadata":
            return "error"
        return current

    @staticmethod
    def _is_text_surface(key: str, path: str, context: str) -> bool:
        lowered = key.lower()
        if lowered in {"description", "title", "text", "message", "error", "data", "prompt"}:
            return True
        if context in {"tool_result", "prompt", "resource", "error"}:
            return lowered not in {"type", "mimeType", "uri", "name", "id"}
        if context == "tool_metadata":
            return lowered in {
                "name", "description", "title", "default", "examples", "const"
            }
        return False

    def _scan_surface(self, source: str, path: str, context: str,
                      text: str) -> List[Dict[str, Any]]:
        normalized = self.base._normalize(text)
        # MCP 工具名称常用下划线、连字符或点号分词。攻击者可把完整注入指令
        # 藏在 name 中规避基于自然语言空白的规则，因此仅在名称表面还原分词。
        if context == "tool_metadata" and path.lower().endswith(".name"):
            normalized = re.sub(r"[_.-]+", " ", normalized)
        issues: List[Dict[str, Any]] = []
        for rule in self.prompt_rules:
            for match in rule.pattern.finditer(normalized):
                if self.base._is_negated(normalized, match.start()):
                    continue
                # 工具描述可合法声明“删除文件、上传数据”等能力。对工具元数据
                # 中的业务动作，只有明确面向 Agent 的命令才按投毒处理。
                if (context == "tool_metadata" and rule.id in {
                        "PI-003", "PI-004", "PI-005", "PI-006"}
                        and not self._AGENT_DIRECTED.search(normalized)):
                    continue
                critical = rule.id in {"PI-001", "PI-003", "PI-004", "PI-005", "PI-009"}
                issues.append(self._issue(
                    "MCP-RUNTIME-001", "MCP Tool Poisoning",
                    CRITICAL if critical else HIGH, source, path, match.group(0),
                    f"MCP {self._context_label(context)}包含可操纵 Agent 的危险指令",
                    f"MCP {context} contains instructions capable of manipulating an agent"))
        for rule_id, pattern, level, zh, en in (
            ("MCP-RUNTIME-002", self._CROSS_TOOL, HIGH,
             "MCP 内容强制 Agent 调用其他工具，可能形成跨工具劫持",
             "MCP content coerces the agent to invoke another tool"),
            ("MCP-RUNTIME-003", self._SECRET_ARGUMENT, CRITICAL,
             "MCP 内容要求把凭据或秘密作为参数提供",
             "MCP content requests credentials or secrets as arguments"),
            ("MCP-RUNTIME-004", self._FAKE_AUTHORITY, CRITICAL,
             "MCP 内容伪造可信或高优先级身份",
             "MCP content claims false trust or higher-priority authority"),
        ):
            match = pattern.search(normalized)
            if match:
                issues.append(self._issue(rule_id, "MCP Tool Poisoning", level,
                                          source, path, match.group(0), zh, en))
        return issues

    def _inspect_tool_metadata(self, capture: Any, source: str) -> List[Dict[str, Any]]:
        issues: List[Dict[str, Any]] = []
        for path, tool in self._find_named_arrays(capture, "$", "tools"):
            if not isinstance(tool, dict):
                continue
            name = str(tool.get("name", ""))
            annotations = tool.get("annotations")
            if not isinstance(annotations, dict):
                issues.append(self._issue(
                    "MCP-RUNTIME-005", "MCP Tool Metadata", MEDIUM, source, path, name,
                    "MCP 工具清单缺少副作用 annotations，调用方无法可靠预判风险",
                    "MCP tool listing lacks side-effect annotations"))
                continue
            if self._MUTATING_NAME.search(name) and annotations.get("readOnlyHint") is True:
                issues.append(self._issue(
                    "MCP-RUNTIME-006", "MCP Annotation Mismatch", CRITICAL,
                    source, path, name,
                    "MCP 工具名称显示可能修改状态，但宣称 readOnlyHint=true",
                    "MCP tool name suggests mutation but claims readOnlyHint=true"))
            if self._DESTRUCTIVE_NAME.search(name) and annotations.get("destructiveHint") is False:
                issues.append(self._issue(
                    "MCP-RUNTIME-007", "MCP Annotation Mismatch", CRITICAL,
                    source, path, name,
                    "MCP 工具名称显示可能具有破坏性，但宣称 destructiveHint=false",
                    "MCP tool name suggests destruction but claims destructiveHint=false"))
        return issues

    def _find_named_arrays(self, value: Any, path: str,
                           target: str) -> Iterable[Tuple[str, Any]]:
        if isinstance(value, dict):
            is_tool_call_request = value.get("method") == "tools/call" and "result" not in value
            for key, item in value.items():
                if is_tool_call_request and key == "params":
                    continue
                child = f"{path}.{key}"
                if key == target and isinstance(item, list):
                    for index, entry in enumerate(item):
                        yield f"{child}[{index}]", entry
                else:
                    yield from self._find_named_arrays(item, child, target)
        elif isinstance(value, list):
            for index, item in enumerate(value):
                yield from self._find_named_arrays(item, f"{path}[{index}]", target)

    def _detect_chains(self, issues: Sequence[Dict[str, Any]],
                       source: str) -> List[Dict[str, Any]]:
        rule_ids = {issue["rule_id"] for issue in issues}
        if "MCP-RUNTIME-002" in rule_ids and ({"MCP-RUNTIME-001", "MCP-RUNTIME-003", "MCP-RUNTIME-004"} & rule_ids):
            return [self._issue(
                "MCP-RUNTIME-CHAIN-001", "MCP Tool Poisoning Chain", CRITICAL,
                source, "$", "跨工具调用 + 危险指令",
                "MCP 内容把跨工具调用与越权、凭据或伪造权威指令组合",
                "MCP content combines cross-tool invocation with unsafe instructions")]
        return []

    @staticmethod
    def _context_label(context: str) -> str:
        return {
            "tool_metadata": "工具描述或参数 schema",
            "tool_result": "工具返回值",
            "prompt": "Prompt",
            "resource": "Resource",
            "error": "错误消息",
        }.get(context, "协议内容")

    def _issue(self, rule_id: str, category: str, level: str, source: str,
               path: str, snippet: str, desc_zh: str, desc_en: str) -> Dict[str, Any]:
        return self.base._custom_issue(
            rule_id, category, level, source, 1,
            redact_mcp_secret(f"{path}: {snippet}"), desc_zh, desc_en)

    @staticmethod
    def _deduplicate(issues: Iterable[Dict[str, Any]]) -> List[Dict[str, Any]]:
        result: List[Dict[str, Any]] = []
        seen = set()
        for issue in issues:
            key = (issue["rule_id"], issue["file"], issue["snippet"])
            if key not in seen:
                seen.add(key)
                result.append(issue)
        return result
