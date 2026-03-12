import re
from dataclasses import dataclass
from typing import List, Dict

@dataclass
class DetectionRule:
    id: str
    category: str
    risk_level: str  # Critical, High, Medium, Low
    pattern: re.Pattern
    desc_zh: str
    desc_en: str

# 风险等级常数
CRITICAL = "Critical"
HIGH = "High"
MEDIUM = "Medium"
LOW = "Low"

# 定义规则集
SECURITY_RULES: List[DetectionRule] = [
    # 1. 后门代码检测 (Backdoor Detection)
    DetectionRule(
        id="BD-001", category="Backdoor", risk_level=CRITICAL,
        pattern=re.compile(r'base64\.b64decode\(|zlib\.decompress\(', re.I),
        desc_zh="隐藏执行逻辑: 发现代码混淆或加密函数调用（如 b64decode/decompress）",
        desc_en="Hidden Logic: Detected obfuscated or encoded code execution"
    ),
    DetectionRule(
        id="BD-002", category="Backdoor", risk_level=HIGH,
        pattern=re.compile(r'if\s+.*(time|date).*(==|in).*:.*?eval\(', re.I | re.DOTALL),
        desc_zh="逻辑炸弹: 基于时间的条件触发式动态代码执行",
        desc_en="Logic Bomb: Time-based conditional logic triggering dynamic execution"
    ),

    # 2. 可疑网络行为检测 (Network Behavior)
    DetectionRule(
        id="NW-001", category="Network", risk_level=MEDIUM,
        pattern=re.compile(r'(requests\.(get|post|put)|urllib\.request|fetch\(|axios\.|http\.client)', re.I),
        desc_zh="外部请求: 发现 HTTP/HTTPS 远程请求调用",
        desc_en="External Request: HTTP/HTTPS network calls detected"
    ),
    DetectionRule(
        id="NW-002", category="Network", risk_level=HIGH,
        pattern=re.compile(r'(webhook|callback_url)\s*=', re.I),
        desc_zh="Webhook 通信: 可能的外传或第三方 webhook 调用",
        desc_en="Webhook Communication: Potential external webhook integration"
    ),

    # 3. 硬编码密钥检测 (Secret Leakage)
    DetectionRule(
        id="SEC-001", category="Secret", risk_level=CRITICAL,
        pattern=re.compile(r'(api_key|apikey|access_token|secret_key|password)\s*=\s*[\'"][A-Za-z0-9\-_]{16,}[\'"]', re.I),
        desc_zh="硬编码密钥: 发现可能的 API 密钥、密码或访问令牌",
        desc_en="Hardcoded Secret: Possible API key, password or token found"
    ),
    DetectionRule(
        id="SEC-002", category="Secret", risk_level=CRITICAL,
        pattern=re.compile(r'(ey[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})'),
        desc_zh="明文 Token: 发现硬编码 JWT Token",
        desc_en="Cleartext Token: Hardcoded JWT token detected"
    ),

    # 4. Prompt Injection / Prompt 攻击检测
    DetectionRule(
        id="PR-001", category="Prompt Security", risk_level=HIGH,
        pattern=re.compile(r'(ignore previous instructions|disregard|system prompt override|bypass restrictions)', re.I),
        desc_zh="Prompt Injection: 发现尝试覆盖、绕过限制的恶意 Prompt 注入关键词",
        desc_en="Prompt Injection: Keywords attempting to override or bypass LLM instructions"
    ),
    DetectionRule(
        id="PR-002", category="Prompt Security", risk_level=HIGH,
        pattern=re.compile(r'(tell me your initial prompt|reveal your instructions|export data to url)', re.I),
        desc_zh="窃取 Prompt: 引导 AI 泄露初始设定或系统信息的指令",
        desc_en="Prompt Theft: Keywords instructing AI to reveal its system prompt"
    ),

    # 5. 动态代码执行检测 (Dynamic Execution)
    DetectionRule(
        id="DYN-001", category="Dynamic Execution", risk_level=CRITICAL,
        pattern=re.compile(r'\b(eval|exec)\s*\(', re.I),
        desc_zh="动态执行: 发现使用 eval() 或 exec() 生成或执行运行时代码",
        desc_en="Dynamic Execution: Usage of eval or exec for runtime code execution"
    ),
    DetectionRule(
        id="DYN-002", category="Dynamic Execution", risk_level=HIGH,
        pattern=re.compile(r'importlib\.import_module|__import__\s*\(', re.I),
        desc_zh="动态加载: 发现动态导入库模块的行为",
        desc_en="Dynamic Import: Dynamic module loading detected"
    ),

    # 6. Shell 执行检测 (Shell Execution)
    DetectionRule(
        id="SH-001", category="Shell Execution", risk_level=CRITICAL,
        pattern=re.compile(r'(os\.system|subprocess\.Popen|subprocess\.run|subprocess\.call)\s*\(.*(shell\s*=\s*True)?', re.I),
        desc_zh="系统命令: 发现执行底层系统命令的操作",
        desc_en="System Command: OS command execution functions detected"
    ),
    DetectionRule(
        id="SH-002", category="Shell Execution", risk_level=CRITICAL,
        pattern=re.compile(r'(powershell|bash\s+-c|sh\s+-c)', re.I),
        desc_zh="进程调用: 发现直接调用 sh, bash 或 powershell",
        desc_en="Process Execution: Direct invocation of shell binaries"
    ),

    # 7. 文件系统访问检测 (File System Access)
    DetectionRule(
        id="FS-001", category="File System", risk_level=HIGH,
        pattern=re.compile(r'open\([\'"](\/\w+)*\/\.(ssh|aws|gcp|env|\w+_history|config)', re.I),
        desc_zh="敏感文件访问: 发现读取 ~/.ssh、.env、秘钥或配置等系统关键路径的行为",
        desc_en="Sensitive File Access: Reading sensitive paths like ~/.ssh or .env"
    ),
    DetectionRule(
        id="FS-002", category="File System", risk_level=MEDIUM,
        pattern=re.compile(r'(os\.chmod|os\.chown|shutil\.rmtree)', re.I),
        desc_zh="系统修改: 试图更改文件权限或删除目录结构",
        desc_en="System Modification: Altering file permissions or recursive deletion"
    ),

    # 8. 数据外传检测 (Data Exfiltration)
    DetectionRule(
        id="EX-001", category="Data Exfiltration", risk_level=CRITICAL,
        pattern=re.compile(r'requests\.post\([\'"].*?[\'"].*?(data|json)\s*=\s*(os\.environ|environ|pwd|history)', re.I),
        desc_zh="数据外泄: 检测到上传系统环境变量、敏感数据的可疑行径",
        desc_en="Data Leak: Exfiltrating environment variables or sensitive local data"
    ),

    # 9. 涉及依赖扫描关键词 (Supply Chain)
    # 此类规则可匹配 package.json 或 requirements.txt 等模块声明
    DetectionRule(
        id="SC-001", category="Supply Chain", risk_level=MEDIUM,
        pattern=re.compile(r'(pypi-malicious|npm-typosquatting|install\s+http)', re.I),
        desc_zh="可疑依赖: 安装了不受信任的来源包或已知高危关联词汇",
        desc_en="Suspicious Dependency: Untrusted package source or known risky module"
    ),

    # 10. AI Agent 恶意行为检测 (AI Behavior Override)
    DetectionRule(
        id="AI-001", category="AI Behavior", risk_level=HIGH,
        pattern=re.compile(r'(agent\.override|mutate_agent_state|disable_safety_filters|auto_approve=True)', re.I),
        desc_zh="控制 AI 行为: 试图绕过 AI 安全过滤、劫持状态或自动静默同意",
        desc_en="AI Override: Attempting to bypass safety filters or hijack agent state"
    )
]

def get_rules() -> List[DetectionRule]:
    return SECURITY_RULES
