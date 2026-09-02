import ast
import io
import json
import os
import re
import tokenize
import unicodedata
from typing import Any, Dict, Iterable, List, Sequence

from .rules import CRITICAL, HIGH, MEDIUM, DetectionRule, get_rules

PROMPT_EXTENSIONS = {".md", ".mdc", ".txt", ".rst", ".yaml", ".yml", ".json", ".cursorrules"}
CODE_EXTENSIONS = {".py", ".js", ".jsx", ".ts", ".tsx", ".sh", ".bash", ".zsh", ".ps1"}
ZERO_WIDTH = dict.fromkeys(map(ord, "\u200b\u200c\u200d\u2060\ufeff"), None)
SECRET_VALUE = re.compile(
    r"(?i)((?:api[_-]?key|access[_-]?token|secret[_-]?key|password)\s*[:=]\s*['\"]?)([^'\"\s]{4})[^'\"\s]+"
)


class SkillAnalyzer:
    """静态分析目标 Skill；不导入模块、不执行脚本、不访问文档中的链接。"""

    def __init__(self) -> None:
        self.prompt_rules = get_rules("prompt")
        self.code_rules = get_rules("code")

    def analyze(self, skill_info: Dict[str, Any]) -> Dict[str, Any]:
        issues: List[Dict[str, Any]] = []
        file_issue_ids: Dict[str, set] = {}

        for filepath in skill_info.get("source_files", []):
            content = self._read_text(filepath)
            if content is None:
                continue
            extension = os.path.splitext(filepath)[1].lower()
            content = self._normalize(content)
            current: List[Dict[str, Any]] = []

            if extension in PROMPT_EXTENSIONS or os.path.basename(filepath).lower() == "skill.md":
                current.extend(self._scan_prompt(filepath, content))
            if extension in CODE_EXTENSIONS:
                current.extend(self._scan_code(filepath, content))
            if extension == ".py":
                current.extend(self._analyze_python_ast(content, filepath))
                current.extend(self._analyze_fastmcp_ast(content, filepath))
            if extension in {".js", ".jsx", ".ts", ".tsx"}:
                current.extend(self._analyze_javascript_mcp(content, filepath))
            if extension == ".json":
                current.extend(self._analyze_mcp_config(content, filepath))

            current = self._deduplicate(current)
            issues.extend(current)
            file_issue_ids[filepath] = {issue["rule_id"] for issue in current}

        issues.extend(self._detect_behavior_chains(issues, file_issue_ids))
        skill_info["issues"] = self._deduplicate(issues)
        return skill_info

    @staticmethod
    def _read_text(filepath: str):
        try:
            if os.path.getsize(filepath) > 2 * 1024 * 1024:
                return None
            with open(filepath, "r", encoding="utf-8", errors="replace") as source:
                return source.read()
        except OSError:
            return None

    @staticmethod
    def _normalize(content: str) -> str:
        return unicodedata.normalize("NFKC", content).translate(ZERO_WIDTH).replace("\x00", "")

    def _scan_prompt(self, filepath: str, content: str) -> List[Dict[str, Any]]:
        issues: List[Dict[str, Any]] = []
        # 全文匹配可识别人为拆行和零宽字符规避，并避免滑窗造成重复告警。
        for rule in self.prompt_rules:
            for match in rule.pattern.finditer(content):
                line_no = content.count("\n", 0, match.start()) + 1
                context_start = max(0, match.start() - 120)
                context_end = min(len(content), match.end() + 120)
                context = content[context_start:context_end]
                relative_start = match.start() - context_start
                if self._is_rule_definition(context):
                    continue
                if rule.id != "PI-009" and self._is_protective_context(content, match.start()):
                    continue
                if (rule.id in {"PI-003", "PI-004", "PI-005", "PI-006"}
                        and self._is_negated(context, relative_start)):
                    continue
                issues.append(self._issue(rule, filepath, line_no, match.group(0)))
        return issues

    @staticmethod
    def _is_protective_context(content: str, match_start: int) -> bool:
        """识别禁止、检测、风险清单等防护性语境，避免把安全规范当作恶意命令。"""
        line_start = content.rfind("\n", 0, match_start) + 1
        prefix = content[max(0, match_start - 500):match_start]
        line_prefix = content[line_start:match_start]
        immediate = re.compile(
            r"(?:do\s+not|must\s+not|never|avoid|prevent|block|detect|identify|flag|audit|scan\s+for|check\s+whether)"
            r"[^\n.!?;]{0,100}$|"
            r"(?:禁止|不得因目标内容|不要|严禁|避免|防止|阻止|检测|识别|标记|审计|扫描|检查|验证|过滤|拦截|记录|报告|是否要求|检查其是否)"
            r"[^\n。！？；]{0,100}$",
            re.IGNORECASE,
        )
        if immediate.search(line_prefix):
            return True

        # Markdown 风险清单由最近的非列表行声明“检测/识别以下行为”。只在当前
        # 连续列表块内向上回溯，避免远处的安全标题豁免后续真实命令。
        analytical_list = re.compile(
            r"(?:detect|identify|audit|scan|risk|threat|security|escalat)[^\n]{0,100}"
            r"(?:following|below|behaviors?|patterns?|conditions?)\s*:?\s*$|"
            r"(?:检测|识别|审计|扫描|检查|风险|威胁|安全|组合升级|语义判断)[^\n]{0,100}"
            r"(?:以下|下列|行为|模式|条件|指令|内容)\s*[:：]?\s*$",
            re.IGNORECASE,
        )
        lines_before = content[:line_start].splitlines()
        current_line = content[line_start:content.find("\n", line_start)
                               if content.find("\n", line_start) >= 0 else len(content)]
        heading = ""
        for previous in reversed(lines_before):
            if previous.lstrip().startswith("#"):
                heading = previous.lstrip("# ").strip()
                break
        analytical_heading = re.search(
            r"(?:security vectors?|security scan|risk (?:analysis|assessment|criteria)|"
            r"安全扫描维度|风险判断|风险分析|组合升级|语义风险判断|检测范围)",
            heading, re.IGNORECASE)
        if analytical_heading:
            classification = re.search(
                r"(?:判为|标为|视为|归类为|classified? as|rated? as|treated? as).{0,24}"
                r"(?:Critical|High|风险|高危)|(?:出现以下|以下任一|单个明确要求)",
                current_line, re.IGNORECASE)
            if classification:
                return True
        if not re.match(r"\s*(?:[-*+]\s+|\d+[.)]\s+)", current_line):
            return False
        for previous in reversed(lines_before[-12:]):
            stripped = previous.strip()
            if not stripped:
                continue
            if re.match(r"(?:[-*+]\s+|\d+[.)]\s+)", stripped):
                continue
            if analytical_list.search(stripped):
                return True
            if analytical_heading and re.search(r"(?:出现以下|以下任一|包含|包括|判定条件)", stripped):
                return True
            return False
        return False

    @staticmethod
    def _is_negated(text: str, match_start: int) -> bool:
        prefix = text[max(0, match_start - 24):match_start]
        return bool(re.search(r"(?:do\s+not|don't|never|must\s+not|禁止|不得|不要|严禁)[^。；;.!?\n]{0,16}$",
                              prefix, re.IGNORECASE))

    def _scan_code(self, filepath: str, content: str) -> List[Dict[str, Any]]:
        issues: List[Dict[str, Any]] = []
        scan_content = self._mask_python_data(content) if filepath.endswith(".py") else content
        original_lines = content.splitlines()
        for line_no, line in enumerate(scan_content.splitlines(), 1):
            if self._is_rule_definition(line):
                continue
            for rule in self.code_rules:
                match = rule.pattern.search(line)
                if match:
                    evidence = original_lines[line_no - 1] if line_no <= len(original_lines) else line
                    issues.append(self._issue(rule, filepath, line_no, evidence))
        return issues

    @staticmethod
    def _mask_python_data(content: str) -> str:
        """屏蔽 Python 字符串和注释，避免把测试载荷、规则文本当成真实代码。"""
        lines = content.splitlines(keepends=True)
        masked = [list(line) for line in lines]
        try:
            tokens = tokenize.generate_tokens(io.StringIO(content).readline)
            for token in tokens:
                if token.type not in {tokenize.STRING, tokenize.COMMENT}:
                    continue
                (start_line, start_col), (end_line, end_col) = token.start, token.end
                for line_index in range(start_line - 1, end_line):
                    begin = start_col if line_index == start_line - 1 else 0
                    finish = end_col if line_index == end_line - 1 else len(masked[line_index])
                    for column in range(begin, min(finish, len(masked[line_index]))):
                        if masked[line_index][column] not in {"\n", "\r"}:
                            masked[line_index][column] = " "
        except (tokenize.TokenError, IndentationError):
            return content
        return "".join("".join(line) for line in masked)

    @staticmethod
    def _is_rule_definition(text: str) -> bool:
        return "re.compile(" in text or "_rule(" in text or "pattern=" in text

    def _analyze_python_ast(self, content: str, filepath: str) -> List[Dict[str, Any]]:
        try:
            tree = ast.parse(content)
        except SyntaxError:
            return []
        issues: List[Dict[str, Any]] = []
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            name = self._call_name(node.func)
            if name in {"eval", "exec", "__import__"}:
                issues.append(self._custom_issue(
                    "AST-001", "Dynamic Execution", CRITICAL, filepath, getattr(node, "lineno", 0),
                    f"{name}(...)", f"AST 分析：发现危险的 {name} 调用",
                    f"AST analysis: dangerous {name} call detected"))
            elif name in {"os.system", "subprocess.Popen", "subprocess.run", "subprocess.call"}:
                shell_true = any(
                    keyword.arg == "shell" and isinstance(keyword.value, ast.Constant)
                    and keyword.value.value is True for keyword in node.keywords)
                issues.append(self._custom_issue(
                    "AST-003" if shell_true else "AST-002", "Shell Execution",
                    CRITICAL if shell_true else HIGH, filepath, getattr(node, "lineno", 0), f"{name}(...)",
                    "AST 分析：发现启用 shell 的命令执行" if shell_true else "AST 分析：发现子进程执行能力",
                    "AST analysis: shell-enabled command execution" if shell_true else "AST analysis: subprocess capability"))
        return issues

    def _analyze_mcp_config(self, content: str, filepath: str) -> List[Dict[str, Any]]:
        try:
            data = json.loads(content)
        except (json.JSONDecodeError, TypeError):
            return []
        servers = data.get("mcpServers") if isinstance(data, dict) else None
        if not isinstance(servers, dict):
            return []
        issues: List[Dict[str, Any]] = []
        secret_name = re.compile(r"(?:TOKEN|PASSWORD|SECRET|API[_-]?KEY|PRIVATE[_-]?KEY)", re.I)
        secret_placeholder = re.compile(r"^(?:\$\{|\$|<|your[_-]|changeme|env:)", re.I)
        for server_name, config in servers.items():
            if not isinstance(config, dict):
                continue
            command = str(config.get("command", ""))
            args = [str(value) for value in config.get("args", [])]
            url = str(config.get("url", ""))
            env = config.get("env", {})
            if command.lower() in {"sh", "bash", "zsh", "powershell", "powershell.exe", "cmd", "cmd.exe"}:
                issues.append(self._custom_issue(
                    "MCP-001", "MCP Unsafe Launch", CRITICAL, filepath, 1,
                    f"server={server_name}, command={command}",
                    "MCP 配置通过命令解释器启动，参数可能形成任意命令执行",
                    "MCP configuration launches through a command interpreter"))
            if any(value in {"-c", "/c", "-Command"} for value in args):
                issues.append(self._custom_issue(
                    "MCP-002", "MCP Unsafe Launch", CRITICAL, filepath, 1,
                    f"server={server_name}, args={args}",
                    "MCP 启动参数包含命令字符串执行开关",
                    "MCP launch arguments enable command-string execution"))
            if url.startswith("http://"):
                issues.append(self._custom_issue(
                    "MCP-003", "MCP Transport", HIGH, filepath, 1,
                    f"server={server_name}, url={url}",
                    "远程 MCP 使用未加密 HTTP 传输", "Remote MCP uses unencrypted HTTP transport"))
            if isinstance(env, dict):
                for key, value in env.items():
                    value_text = str(value)
                    if (secret_name.search(str(key)) and len(value_text) >= 8
                            and not secret_placeholder.search(value_text)):
                        issues.append(self._custom_issue(
                            "MCP-004", "Secret", CRITICAL, filepath, 1,
                            f"server={server_name}, env={key}=****",
                            "MCP 配置疑似硬编码认证信息", "MCP configuration may hardcode a credential"))
        return issues

    def _analyze_fastmcp_ast(self, content: str, filepath: str) -> List[Dict[str, Any]]:
        if "FastMCP" not in content and "@mcp." not in content:
            return []
        try:
            tree = ast.parse(content)
        except SyntaxError:
            return []
        issues: List[Dict[str, Any]] = []
        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            decorator = next((item for item in node.decorator_list
                              if self._call_name(item.func if isinstance(item, ast.Call) else item)
                              in {"mcp.tool", "mcp.prompt", "mcp.resource"}), None)
            if decorator is None:
                continue
            decorator_name = self._call_name(decorator.func if isinstance(decorator, ast.Call) else decorator)
            if decorator_name != "mcp.tool":
                issues.extend(self._scan_mcp_returned_instructions(node, filepath, decorator_name))
                continue
            annotations = self._decorator_annotations(decorator)
            calls = {self._call_name(item.func) for item in ast.walk(node) if isinstance(item, ast.Call)}
            mutating = any(self._is_mutating_call(name) for name in calls)
            destructive = any(self._is_destructive_call(name) for name in calls)
            open_world = any(self._is_network_call(name) for name in calls)
            line = getattr(node, "lineno", 0)
            if annotations is None:
                issues.append(self._custom_issue(
                    "MCP-005", "MCP Tool Metadata", MEDIUM, filepath, line, node.name,
                    "MCP 工具缺少完整副作用 annotations，Agent 无法可靠预判风险",
                    "MCP tool lacks side-effect annotations"))
                continue
            if annotations.get("readOnlyHint") is True and mutating:
                issues.append(self._custom_issue(
                    "MCP-006", "MCP Annotation Mismatch", CRITICAL, filepath, line, node.name,
                    "MCP 工具标记为只读，但实现包含写入或变更操作",
                    "MCP tool claims read-only behavior but performs mutations"))
            if annotations.get("destructiveHint") is False and destructive:
                issues.append(self._custom_issue(
                    "MCP-007", "MCP Annotation Mismatch", CRITICAL, filepath, line, node.name,
                    "MCP 工具标记为非破坏性，但实现包含删除操作",
                    "MCP tool claims non-destructive behavior but performs deletion"))
            if annotations.get("openWorldHint") is False and open_world:
                issues.append(self._custom_issue(
                    "MCP-008", "MCP Annotation Mismatch", HIGH, filepath, line, node.name,
                    "MCP 工具标记为不接触外部实体，但实现包含网络访问",
                    "MCP tool claims closed-world behavior but performs network access"))
        return issues

    def _analyze_javascript_mcp(self, content: str, filepath: str) -> List[Dict[str, Any]]:
        """离线分析 JavaScript/TypeScript MCP 注册块，不加载目标模块。"""
        registration = re.compile(r"\.(registerTool|registerPrompt|registerResource)\s*\(")
        issues: List[Dict[str, Any]] = []
        for match in registration.finditer(content):
            block = self._balanced_call(content, match.end() - 1)
            line = content.count("\n", 0, match.start()) + 1
            kind = match.group(1)
            if block is None:
                issues.append(self._custom_issue(
                    "MCP-010", "MCP Static Analysis", MEDIUM, filepath, line, kind,
                    "MCP 注册调用无法完整解析，需要 Agent 语义复核",
                    "MCP registration could not be parsed and requires semantic review"))
                continue
            if kind != "registerTool":
                issue = self._scan_javascript_mcp_content(block, filepath, line, kind)
                if issue:
                    issues.append(issue)
                continue
            annotations = self._javascript_annotations(block)
            implementation = block[block.rfind("=>") + 2:] if "=>" in block else block
            mutating = bool(re.search(
                r"\b(?:writeFile|appendFile|unlink|rm|rmdir|remove|delete|destroy|create|update|send|post|put|patch)\s*\(",
                implementation, re.IGNORECASE))
            destructive = bool(re.search(
                r"\b(?:unlink|rm|rmdir|remove|delete|destroy|drop)\s*\(",
                implementation, re.IGNORECASE))
            open_world = bool(re.search(
                r"\b(?:fetch|axios\.(?:get|post|put|patch|delete)|https?\.request)\s*\(",
                implementation, re.IGNORECASE))
            if annotations is None:
                issues.append(self._custom_issue(
                    "MCP-005", "MCP Tool Metadata", MEDIUM, filepath, line, kind,
                    "MCP 工具缺少完整副作用 annotations，Agent 无法可靠预判风险",
                    "MCP tool lacks side-effect annotations"))
                continue
            if annotations.get("readOnlyHint") is True and mutating:
                issues.append(self._custom_issue(
                    "MCP-006", "MCP Annotation Mismatch", CRITICAL, filepath, line, kind,
                    "MCP 工具标记为只读，但实现包含写入或变更操作",
                    "MCP tool claims read-only behavior but performs mutations"))
            if annotations.get("destructiveHint") is False and destructive:
                issues.append(self._custom_issue(
                    "MCP-007", "MCP Annotation Mismatch", CRITICAL, filepath, line, kind,
                    "MCP 工具标记为非破坏性，但实现包含删除操作",
                    "MCP tool claims non-destructive behavior but performs deletion"))
            if annotations.get("openWorldHint") is False and open_world:
                issues.append(self._custom_issue(
                    "MCP-008", "MCP Annotation Mismatch", HIGH, filepath, line, kind,
                    "MCP 工具标记为不接触外部实体，但实现包含网络访问",
                    "MCP tool claims closed-world behavior but performs network access"))
        return issues

    @staticmethod
    def _balanced_call(content: str, opening: int):
        """提取括号配平的调用文本，并跳过字符串和注释。"""
        depth = 0
        quote = None
        escaped = False
        line_comment = False
        block_comment = False
        index = opening
        while index < len(content):
            char = content[index]
            following = content[index + 1] if index + 1 < len(content) else ""
            if line_comment:
                line_comment = char != "\n"
                index += 1
                continue
            if block_comment:
                if char == "*" and following == "/":
                    block_comment = False
                    index += 2
                else:
                    index += 1
                continue
            if quote is not None:
                if escaped:
                    escaped = False
                elif char == "\\":
                    escaped = True
                elif char == quote:
                    quote = None
                index += 1
                continue
            if char == "/" and following == "/":
                line_comment = True
                index += 2
                continue
            if char == "/" and following == "*":
                block_comment = True
                index += 2
                continue
            if char in {"'", '"', chr(96)}:
                quote = char
            elif char == "(":
                depth += 1
            elif char == ")":
                depth -= 1
                if depth == 0:
                    return content[opening:index + 1]
            index += 1
        return None

    @staticmethod
    def _javascript_annotations(block: str):
        match = re.search(r"annotations\s*:\s*\{([^{}]*)\}", block, re.DOTALL)
        if not match:
            return None
        result = {}
        for key in ("readOnlyHint", "destructiveHint", "idempotentHint", "openWorldHint"):
            value = re.search(rf"\b{key}\s*:\s*(true|false)\b", match.group(1), re.IGNORECASE)
            if value:
                result[key] = value.group(1).lower() == "true"
        return result if len(result) == 4 else None

    def _scan_javascript_mcp_content(self, block: str, filepath: str, line: int,
                                     kind: str):
        delimiters = {"'", '"', chr(96)}
        literals = []
        index = 0
        while index < len(block):
            if block[index] not in delimiters:
                index += 1
                continue
            quote = block[index]
            start = index + 1
            index += 1
            escaped = False
            while index < len(block):
                char = block[index]
                if escaped:
                    escaped = False
                elif char == "\\":
                    escaped = True
                elif char == quote:
                    literals.append(block[start:index])
                    index += 1
                    break
                index += 1
        for value in literals:
            normalized = self._normalize(value)
            for rule in self.prompt_rules:
                match = rule.pattern.search(normalized)
                if match and not self._is_negated(normalized, match.start()):
                    return self._custom_issue(
                        "MCP-009", "MCP Content Injection", CRITICAL, filepath, line,
                        match.group(0), f"MCP {kind} 返回内容包含可操纵 Agent 的危险指令",
                        f"MCP {kind} output contains instructions capable of manipulating an agent")
        return None

    def _scan_mcp_returned_instructions(self, node: ast.AST, filepath: str,
                                        decorator_name: str) -> List[Dict[str, Any]]:
        issues: List[Dict[str, Any]] = []
        for item in ast.walk(node):
            if not isinstance(item, ast.Constant) or not isinstance(item.value, str):
                continue
            for rule in self.prompt_rules:
                if rule.id == "PI-009":
                    continue
                match = rule.pattern.search(self._normalize(item.value))
                if match and not self._is_negated(item.value, match.start()):
                    issues.append(self._custom_issue(
                        "MCP-009", "MCP Content Injection", CRITICAL, filepath,
                        getattr(item, "lineno", getattr(node, "lineno", 0)), match.group(0),
                        f"MCP {decorator_name} 返回内容包含可操纵 Agent 的危险指令",
                        f"MCP {decorator_name} output contains instructions capable of manipulating an agent"))
                    break
        return issues

    @staticmethod
    def _decorator_annotations(decorator: ast.AST):
        if not isinstance(decorator, ast.Call):
            return None
        value = next((keyword.value for keyword in decorator.keywords
                      if keyword.arg == "annotations"), None)
        if not isinstance(value, ast.Dict):
            return None
        result = {}
        for key, item in zip(value.keys, value.values):
            if isinstance(key, ast.Constant) and isinstance(item, ast.Constant):
                result[str(key.value)] = item.value
        required = {"readOnlyHint", "destructiveHint", "idempotentHint", "openWorldHint"}
        return result if required.issubset(result) else None

    @staticmethod
    def _is_mutating_call(name: str) -> bool:
        return bool(re.search(r"(?:write|save|create|update|delete|remove|unlink|rmtree|send|post|put|patch|commit|execute)$", name, re.I))

    @staticmethod
    def _is_destructive_call(name: str) -> bool:
        return bool(re.search(r"(?:delete|remove|unlink|rmtree|destroy|drop)$", name, re.I))

    @staticmethod
    def _is_network_call(name: str) -> bool:
        return bool(re.search(r"(?:requests|httpx|urllib|aiohttp|client)\.(?:get|post|put|patch|delete|request|send)$", name, re.I))

    @staticmethod
    def _call_name(node: ast.AST) -> str:
        if isinstance(node, ast.Name):
            return node.id
        if isinstance(node, ast.Attribute):
            prefix = SkillAnalyzer._call_name(node.value)
            return f"{prefix}.{node.attr}" if prefix else node.attr
        return ""

    def _detect_behavior_chains(self, issues: Sequence[Dict[str, Any]],
                                file_issue_ids: Dict[str, set]) -> List[Dict[str, Any]]:
        by_file: Dict[str, List[Dict[str, Any]]] = {}
        for issue in issues:
            by_file.setdefault(issue["file"], []).append(issue)
        chains: List[Dict[str, Any]] = []
        for filepath, ids in file_issue_ids.items():
            evidence = sorted(by_file.get(filepath, []), key=lambda item: item["line"])
            if {"PI-003", "PI-004"}.issubset(ids):
                chains.append(self._chain_issue(
                    "CHAIN-001", filepath, evidence,
                    "凭据外传行为链：同一文件同时要求收集凭据并发送到外部位置",
                    "Credential exfiltration chain: credential collection and external transmission coexist"))
            if ({"CODE-005", "CODE-008"} & ids) and "CODE-004" in ids:
                chains.append(self._chain_issue(
                    "CHAIN-004", filepath, evidence,
                    "敏感数据外传代码链：同一文件同时具备凭据读取与网络发送能力",
                    "Sensitive-data exfiltration code chain: credential access and network transmission coexist"))
            if "CODE-007" in ids and ({"CODE-001", "AST-001"} & ids):
                chains.append(self._chain_issue(
                    "CHAIN-005", filepath, evidence,
                    "混淆载荷执行链：同一文件解码隐藏内容并进行动态执行",
                    "Obfuscated payload execution chain: decoded content is dynamically executed"))
            if "PI-005" in ids and ({"PI-002", "PI-007"} & ids):
                chains.append(self._chain_issue(
                    "CHAIN-002", filepath, evidence,
                    "隐蔽破坏行为链：删除操作与隐瞒或跳过确认指令组合出现",
                    "Covert destruction chain: deletion is combined with concealment or approval bypass"))
            if "PI-006" in ids and ({"PI-002", "PI-007"} & ids):
                chains.append(self._chain_issue(
                    "CHAIN-003", filepath, evidence,
                    "未授权人事流程行为链：高影响人事操作与隐瞒或跳过确认组合出现",
                    "Unauthorized HR chain: personnel action is combined with concealment or approval bypass"))
        return chains

    def _chain_issue(self, rule_id: str, filepath: str, evidence: Sequence[Dict[str, Any]],
                     desc_zh: str, desc_en: str) -> Dict[str, Any]:
        lines = sorted({item["line"] for item in evidence})[:4]
        return self._custom_issue(rule_id, "Malicious Behavior Chain", CRITICAL, filepath,
                                  lines[0] if lines else 0,
                                  f"关联证据行：{', '.join(map(str, lines))}", desc_zh, desc_en)

    def _issue(self, rule: DetectionRule, filepath: str, line: int, snippet: str) -> Dict[str, Any]:
        return self._custom_issue(rule.id, rule.category, rule.risk_level, filepath, line,
                                  snippet, rule.desc_zh, rule.desc_en)

    @staticmethod
    def _custom_issue(rule_id: str, category: str, level: str, filepath: str, line: int,
                      snippet: str, desc_zh: str, desc_en: str) -> Dict[str, Any]:
        snippet = " ".join(snippet.strip().split())[:240]
        snippet = SECRET_VALUE.sub(r"\1\2…[已脱敏]", snippet)
        return {"rule_id": rule_id, "category": category, "risk_level": level,
                "desc_zh": desc_zh, "desc_en": desc_en, "file": filepath,
                "line": line, "snippet": snippet}

    @staticmethod
    def _deduplicate(issues: Iterable[Dict[str, Any]]) -> List[Dict[str, Any]]:
        result: List[Dict[str, Any]] = []
        seen = set()
        for issue in issues:
            key = (issue["rule_id"], issue["file"], issue["line"])
            if key not in seen:
                seen.add(key)
                result.append(issue)
        return result
