import re
from dataclasses import dataclass
from typing import List, Pattern, Tuple

CRITICAL = "Critical"
HIGH = "High"
MEDIUM = "Medium"
LOW = "Low"


@dataclass(frozen=True)
class DetectionRule:
    id: str
    category: str
    risk_level: str
    pattern: Pattern[str]
    desc_zh: str
    desc_en: str
    scope: str


def _rule(rule_id: str, category: str, level: str, expression: str,
          desc_zh: str, desc_en: str, scope: str) -> DetectionRule:
    return DetectionRule(rule_id, category, level,
                         re.compile(expression, re.IGNORECASE),
                         desc_zh, desc_en, scope)


# 提示词规则使用“动作 + 敏感对象”组合，兼顾中英文并降低单关键词误报。
PROMPT_RULES: Tuple[DetectionRule, ...] = (
    _rule("PI-001", "Prompt Injection", HIGH,
          r"(?:ignore|disregard|override|forget)\s+(?:all\s+)?(?:(?:previous|prior)\s+)?(?:system|developer|user)?\s*(?:instructions?|rules?|messages?)|(?:忽略|无视|覆盖|忘掉).{0,16}(?:之前|先前|上级|系统|开发者|用户).{0,12}(?:指令|规则|要求|消息)",
          "指令层级劫持：要求代理忽略或覆盖上级指令",
          "Instruction hierarchy hijack: asks the agent to ignore higher-priority instructions", "prompt"),
    _rule("PI-002", "Concealment", HIGH,
          r"(?:do\s+not|don't|never)\s+(?:tell|inform|notify|show)\s+(?:the\s+)?(?:user|owner|administrator)|(?:secretly|silently|without\s+(?:the\s+)?user(?:'s)?\s+knowledge)|(?:不要|不得|禁止).{0,10}(?:告知|通知|提醒|展示).{0,8}(?:用户|所有者|管理员)|(?:悄悄|秘密地|暗中|静默地|在用户不知情的情况下)",
          "隐蔽执行：要求对用户隐藏行为或结果",
          "Concealed execution: asks the agent to hide actions or results", "prompt"),
    _rule("PI-003", "Credential Access", CRITICAL,
          r"\b(?:read|collect|extract|find|copy|steal|dump|harvest)\b[^\n.!?;]{0,60}(?:passwords?|api[ _-]?keys?|access[ _-]?tokens?|credentials?|\.env|\.ssh|keychain|browser cookies?)|(?:读取|收集|提取|查找|复制|窃取|导出|抓取)[^\n。！？；]{0,48}(?:密码|口令|API[ _-]?密钥|访问令牌|凭据|\.env|\.ssh|钥串|浏览器[^\n。！？；]{0,8}(?:Cookie|缓存))",
          "凭据窃取指令：要求读取或收集密码、密钥、令牌等敏感信息",
          "Credential theft instruction: asks to collect passwords, keys, or tokens", "prompt"),
    _rule("PI-004", "Data Exfiltration", CRITICAL,
          r"\b(?:send|upload|post|forward|exfiltrate|transmit)\b[^\n.!?;]{0,80}(?:webhook|https?://|remote server|external (?:url|host)|specified (?:url|location))|(?:发送|上传|外传|回传|转发|提交)[^\n。！？；]{0,80}(?:webhook|https?://|远程服务器|外部地址|指定(?:位置|地址|网址|服务器))",
          "数据外传指令：要求把数据发送到外部或指定位置",
          "Data exfiltration instruction: asks to send data to an external destination", "prompt"),
    _rule("PI-005", "Destructive Action", CRITICAL,
          r"\b(?:delete|remove|erase|wipe|destroy|shred)\b[^\n.!?;]{0,48}(?:(?:user|project|workspace|system|source|all)\s+files?|folders?|director(?:y|ies)|repository|workspace|logs?|backups?)|rm\s+-rf|(?:删除|移除|清空|擦除|销毁|粉碎)[^\n。！？；]{0,48}(?:用户文件|项目文件|系统文件|全部文件|目录|文件夹|仓库|工作区|日志|备份)",
          "破坏性指令：要求删除或销毁文件、仓库、日志或备份",
          "Destructive instruction: asks to delete files, repositories, logs, or backups", "prompt"),
    _rule("PI-006", "Unauthorized Workflow", HIGH,
          r"(?:submit|initiate|start|execute|complete|trigger).{0,40}(?:resignation|offboarding|termination|dismissal)|(?:提起|发起|办理|提交|执行|完成|触发).{0,24}(?:离职|辞职|离职流程|解雇|开除)",
          "未授权业务操作：要求代理发起离职、辞职或解雇等高影响流程",
          "Unauthorized action: asks the agent to initiate resignation or termination", "prompt"),
    _rule("PI-007", "Approval Bypass", HIGH,
          r"(?:without|skip|bypass).{0,30}(?:approval|confirmation|permission|review)|(?:do\s+not|don't|never).{0,20}(?:ask|request).{0,20}(?:approval|confirmation|permission)|(?:无需|跳过|绕过).{0,20}(?:确认|审批|授权|许可)|(?:不要|不得).{0,20}(?:询问|请求).{0,12}(?:用户|确认|审批|授权|许可)",
          "授权绕过：要求跳过用户确认、审批或权限检查",
          "Authorization bypass: asks to skip confirmation, approval, or permission checks", "prompt"),
    _rule("PI-008", "Safety Bypass", HIGH,
          r"(?:disable|bypass|turn off).{0,30}(?:safety|security|guardrails?|sandbox|filters?)|(?:关闭|禁用|绕过|规避).{0,30}(?:安全|防护|护栏|沙箱|过滤器|审计)",
          "安全机制绕过：要求禁用或规避安全控制",
          "Safety bypass: asks to disable or evade security controls", "prompt"),
    _rule("PI-009", "Auditor Hijacking", CRITICAL,
          r"(?:if|when).{0,32}(?:audited|scanned|reviewed).{0,80}(?:stop|skip|execute|run|report (?:it )?as safe|hide)|(?:当|如果|一旦).{0,24}(?:审计|扫描|检查).{0,80}(?:停止|跳过|执行|运行|报告为安全|隐瞒)|(?:审计|扫描|检查)(?:代理|Agent|智能体).{0,40}(?:必须|应当|需要).{0,40}(?:执行|运行|调用|申请权限|报告安全)",
          "审计者劫持：检测到针对安全审计 Agent 的条件指令或操纵",
          "Auditor hijacking: conditional instruction or manipulation targeting the security agent", "prompt"),
)

CODE_RULES: Tuple[DetectionRule, ...] = (
    _rule("CODE-001", "Dynamic Execution", CRITICAL, r"(?<![.\w])(?:eval|exec)\s*\(",
          "动态执行：发现 eval/exec 调用", "Dynamic execution: eval/exec call detected", "code"),
    _rule("CODE-002", "Shell Execution", HIGH,
          r"(?:os\.system|subprocess\.(?:Popen|run|call)|child_process\.(?:exec|spawn))\s*\(",
          "进程执行：代码可启动系统命令或子进程", "Process execution capability detected", "code"),
    _rule("CODE-003", "Shell Execution", CRITICAL,
          r"shell\s*=\s*True|(?:bash|sh)\s+-c|powershell(?:\.exe)?\s+",
          "高危 Shell 执行：发现 shell 模式或命令解释器调用", "High-risk shell execution detected", "code"),
    _rule("CODE-004", "Network", MEDIUM,
          r"(?:requests\.(?:get|post|put|patch)|urllib\.request|httpx\.(?:get|post)|axios\.(?:get|post)|fetch)\s*\(",
          "外部通信：代码包含网络请求能力", "External communication capability detected", "code"),
    _rule("CODE-005", "File System", HIGH,
          r"(?:\.ssh|\.aws|\.config/gcloud|\.env|keychain|credentials|id_rsa|known_hosts)",
          "敏感路径访问：代码引用凭据或敏感配置位置", "Sensitive credential path referenced", "code"),
    _rule("CODE-008", "Credential Access", HIGH,
          r"(?:os\.environ|process\.env|keyring\.|getenv\s*\(\s*['\"](?:TOKEN|PASSWORD|SECRET|API[_-]?KEY))",
          "敏感数据访问：代码读取环境凭据或系统钥匙串", "Sensitive environment or keyring access detected", "code"),
    _rule("CODE-006", "Destructive Action", HIGH,
          r"(?:shutil\.rmtree|os\.remove|os\.unlink|fs\.rmSync|rm\s+-rf)\s*\(?",
          "破坏性文件操作：代码包含删除文件或目录的能力", "Destructive file operation detected", "code"),
    _rule("CODE-007", "Obfuscation", HIGH,
          r"(?:base64\.b64decode|zlib\.decompress|fromCharCode)\s*\(",
          "混淆载荷：发现编码或压缩内容的运行时还原", "Runtime payload decoding detected", "code"),
    _rule("SEC-001", "Secret", CRITICAL,
          r"(?:api[_-]?key|access[_-]?token|secret[_-]?key|password)\s*[:=]\s*['\"][^'\"\r\n]{12,}['\"]",
          "硬编码凭据：源码中可能包含明文密钥或密码", "Possible hardcoded credential detected", "code"),
)

SECURITY_RULES = PROMPT_RULES + CODE_RULES


def get_rules(scope: str = "all") -> List[DetectionRule]:
    return list(SECURITY_RULES if scope == "all" else
                (rule for rule in SECURITY_RULES if rule.scope == scope))
