# SkillGuard Security Audit Report

## Scan Information

**Scan Time:** 2026-03-12 16:49:42
**Environment:** Local Directory
**Total Skills Scanned:** 19

## Risk Overview

- **Critical:** 5
- **High Risk:** 1
- **Medium Risk:** 2
- **Low Risk:** 0
- **Safe:** 11

## Skill Analysis

### Skill: skillguard
**Risk Score:** 100
**Risk Level:** Critical

#### Detected Issues

- **[Critical] Dynamic Execution**: 动态执行: 发现使用 eval() 或 exec() 生成或执行运行时代码
  - Location: `README.md:33`
  - Snippet: `5. **动态代码执行审查 (Dynamic Execution)**: 强制检索出不受限危险的 `eval()`, `exec()` 与动态加载包操作。`
- **[Critical] Dynamic Execution**: 动态执行: 发现使用 eval() 或 exec() 生成或执行运行时代码
  - Location: `SKILL.md:17`
  - Snippet: `5. **动态代码执行 (Dynamic Execution)**: `eval()`, `exec()`, 运行时模块加载。`
- **[High] Prompt Security**: Prompt Injection: 发现尝试覆盖、绕过限制的恶意 Prompt 注入关键词
  - Location: `rules.py:67`
  - Snippet: `pattern=re.compile(r'(ignore previous instructions|disregard|system prompt override|bypass restricti`
- **[High] Prompt Security**: 窃取 Prompt: 引导 AI 泄露初始设定或系统信息的指令
  - Location: `rules.py:73`
  - Snippet: `pattern=re.compile(r'(tell me your initial prompt|reveal your instructions|export data to url)', re.`
- **[Critical] Dynamic Execution**: 动态执行: 发现使用 eval() 或 exec() 生成或执行运行时代码
  - Location: `rules.py:82`
  - Snippet: `desc_zh="动态执行: 发现使用 eval() 或 exec() 生成或执行运行时代码",`
- **[Critical] Shell Execution**: 进程调用: 发现直接调用 sh, bash 或 powershell
  - Location: `rules.py:101`
  - Snippet: `pattern=re.compile(r'(powershell|bash\s+-c|sh\s+-c)', re.I),`
- **[Critical] Shell Execution**: 进程调用: 发现直接调用 sh, bash 或 powershell
  - Location: `rules.py:102`
  - Snippet: `desc_zh="进程调用: 发现直接调用 sh, bash 或 powershell",`
- **[Medium] Supply Chain**: 可疑依赖: 安装了不受信任的来源包或已知高危关联词汇
  - Location: `rules.py:132`
  - Snippet: `pattern=re.compile(r'(pypi-malicious|npm-typosquatting|install\s+http)', re.I),`
- **[High] AI Behavior**: 控制 AI 行为: 试图绕过 AI 安全过滤、劫持状态或自动静默同意
  - Location: `rules.py:140`
  - Snippet: `pattern=re.compile(r'(agent\.override|mutate_agent_state|disable_safety_filters|auto_approve=True)',`

#### Possible Attack Scenarios

- AI行为操纵 (AI Behavior manipulation) / 越狱破解 (Jailbreak)
- 远程命令执行 (RCE) / 任意代码执行

#### Security Recommendations

- 实施强有力的 Prompt 过滤与输出验证以防止注入 (Prompt Filtering)
- 避免使用 eval/exec 和底层系统命令，使用更安全的标准库替代操作 (Audit execution logic)

---

### Skill: theme-factory
**Risk Score:** 0
**Risk Level:** Safe

#### Detected Issues

- 未发现安全问题

### Skill: doc-coauthoring
**Risk Score:** 0
**Risk Level:** Safe

#### Detected Issues

- 未发现安全问题

### Skill: xlsx
**Risk Score:** 100
**Risk Level:** Critical

#### Detected Issues

- **[Critical] Shell Execution**: 系统命令: 发现执行底层系统命令的操作
  - Location: `recalc.py:31`
  - Snippet: `subprocess.run(['soffice', '--headless', '--terminate_after_init'],`
- **[Critical] Shell Execution**: 系统命令: 发现执行底层系统命令的操作
  - Location: `recalc.py:84`
  - Snippet: `subprocess.run(['gtimeout', '--version'], capture_output=True, timeout=1, check=False)`
- **[Critical] Shell Execution**: 系统命令: 发现执行底层系统命令的操作
  - Location: `recalc.py:92`
  - Snippet: `result = subprocess.run(cmd, capture_output=True, text=True)`

#### Possible Attack Scenarios

- 远程命令执行 (RCE) / 任意代码执行

#### Security Recommendations

- 避免使用 eval/exec 和底层系统命令，使用更安全的标准库替代操作 (Audit execution logic)

---

### Skill: pdf
**Risk Score:** 0
**Risk Level:** Safe

#### Detected Issues

- 未发现安全问题

### Skill: algorithmic-art
**Risk Score:** 40
**Risk Level:** Medium Risk

#### Detected Issues

- **[Critical] Dynamic Execution**: 动态执行: 发现使用 eval() 或 exec() 生成或执行运行时代码
  - Location: `generator_template.js:133`
  - Snippet: `const result = /^#?([a-f\d]{2})([a-f\d]{2})([a-f\d]{2})$/i.exec(hex);`

#### Possible Attack Scenarios

- 远程命令执行 (RCE) / 任意代码执行

#### Security Recommendations

- 避免使用 eval/exec 和底层系统命令，使用更安全的标准库替代操作 (Audit execution logic)

---

### Skill: internal-comms
**Risk Score:** 0
**Risk Level:** Safe

#### Detected Issues

- 未发现安全问题

### Skill: skill-creator
**Risk Score:** 0
**Risk Level:** Safe

#### Detected Issues

- 未发现安全问题

### Skill: canvas-design
**Risk Score:** 0
**Risk Level:** Safe

#### Detected Issues

- 未发现安全问题

### Skill: pptx
**Risk Score:** 100
**Risk Level:** Critical

#### Detected Issues

- **[Critical] Shell Execution**: 系统命令: 发现执行底层系统命令的操作
  - Location: `pack.py:103`
  - Snippet: `result = subprocess.run(`
- **[Critical] Shell Execution**: 系统命令: 发现执行底层系统命令的操作
  - Location: `redlining.py:153`
  - Snippet: `result = subprocess.run(`
- **[Critical] Shell Execution**: 系统命令: 发现执行底层系统命令的操作
  - Location: `redlining.py:185`
  - Snippet: `result = subprocess.run(`
- **[Critical] Shell Execution**: 系统命令: 发现执行底层系统命令的操作
  - Location: `thumbnail.py:219`
  - Snippet: `result = subprocess.run(`
- **[Critical] Shell Execution**: 系统命令: 发现执行底层系统命令的操作
  - Location: `thumbnail.py:237`
  - Snippet: `result = subprocess.run(`

#### Possible Attack Scenarios

- 远程命令执行 (RCE) / 任意代码执行

#### Security Recommendations

- 避免使用 eval/exec 和底层系统命令，使用更安全的标准库替代操作 (Audit execution logic)

---

### Skill: slack-gif-creator
**Risk Score:** 0
**Risk Level:** Safe

#### Detected Issues

- 未发现安全问题

### Skill: webapp-testing
**Risk Score:** 80
**Risk Level:** High Risk

#### Detected Issues

- **[Critical] Shell Execution**: 系统命令: 发现执行底层系统命令的操作
  - Location: `with_server.py:69`
  - Snippet: `process = subprocess.Popen(`
- **[Critical] Shell Execution**: 系统命令: 发现执行底层系统命令的操作
  - Location: `with_server.py:88`
  - Snippet: `result = subprocess.run(args.command)`

#### Possible Attack Scenarios

- 远程命令执行 (RCE) / 任意代码执行

#### Security Recommendations

- 避免使用 eval/exec 和底层系统命令，使用更安全的标准库替代操作 (Audit execution logic)

---

### Skill: frontend-design
**Risk Score:** 0
**Risk Level:** Safe

#### Detected Issues

- 未发现安全问题

### Skill: ai-skill-security-auditor
**Risk Score:** 100
**Risk Level:** Critical

#### Detected Issues

- **[Critical] Dynamic Execution**: 动态执行: 发现使用 eval() 或 exec() 生成或执行运行时代码
  - Location: `README.md:33`
  - Snippet: `5. **动态代码执行审查 (Dynamic Execution)**: 强制检索出不受限危险的 `eval()`, `exec()` 与动态加载包操作。`
- **[Critical] Dynamic Execution**: 动态执行: 发现使用 eval() 或 exec() 生成或执行运行时代码
  - Location: `SKILL.md:17`
  - Snippet: `5. **动态代码执行 (Dynamic Execution)**: `eval()`, `exec()`, 运行时模块加载。`
- **[High] Prompt Security**: Prompt Injection: 发现尝试覆盖、绕过限制的恶意 Prompt 注入关键词
  - Location: `rules.py:67`
  - Snippet: `pattern=re.compile(r'(ignore previous instructions|disregard|system prompt override|bypass restricti`
- **[High] Prompt Security**: 窃取 Prompt: 引导 AI 泄露初始设定或系统信息的指令
  - Location: `rules.py:73`
  - Snippet: `pattern=re.compile(r'(tell me your initial prompt|reveal your instructions|export data to url)', re.`
- **[Critical] Dynamic Execution**: 动态执行: 发现使用 eval() 或 exec() 生成或执行运行时代码
  - Location: `rules.py:82`
  - Snippet: `desc_zh="动态执行: 发现使用 eval() 或 exec() 生成或执行运行时代码",`
- **[Critical] Shell Execution**: 进程调用: 发现直接调用 sh, bash 或 powershell
  - Location: `rules.py:101`
  - Snippet: `pattern=re.compile(r'(powershell|bash\s+-c|sh\s+-c)', re.I),`
- **[Critical] Shell Execution**: 进程调用: 发现直接调用 sh, bash 或 powershell
  - Location: `rules.py:102`
  - Snippet: `desc_zh="进程调用: 发现直接调用 sh, bash 或 powershell",`
- **[Medium] Supply Chain**: 可疑依赖: 安装了不受信任的来源包或已知高危关联词汇
  - Location: `rules.py:132`
  - Snippet: `pattern=re.compile(r'(pypi-malicious|npm-typosquatting|install\s+http)', re.I),`
- **[High] AI Behavior**: 控制 AI 行为: 试图绕过 AI 安全过滤、劫持状态或自动静默同意
  - Location: `rules.py:140`
  - Snippet: `pattern=re.compile(r'(agent\.override|mutate_agent_state|disable_safety_filters|auto_approve=True)',`

#### Possible Attack Scenarios

- AI行为操纵 (AI Behavior manipulation) / 越狱破解 (Jailbreak)
- 远程命令执行 (RCE) / 任意代码执行

#### Security Recommendations

- 实施强有力的 Prompt 过滤与输出验证以防止注入 (Prompt Filtering)
- 避免使用 eval/exec 和底层系统命令，使用更安全的标准库替代操作 (Audit execution logic)

---

### Skill: mcp-builder
**Risk Score:** 40
**Risk Level:** Medium Risk

#### Detected Issues

- **[Medium] Network**: 外部请求: 发现 HTTP/HTTPS 远程请求调用
  - Location: `python_mcp_server.md:260`
  - Snippet: `response = requests.get(f"{API_URL}/resource/{resource_id}")  # Blocks`
- **[Medium] Network**: 外部请求: 发现 HTTP/HTTPS 远程请求调用
  - Location: `node_mcp_server.md:474`
  - Snippet: `const response = await axios.get(`${API_URL}/resource/${resourceId}`);`
- **[Medium] Network**: 外部请求: 发现 HTTP/HTTPS 远程请求调用
  - Location: `node_mcp_server.md:480`
  - Snippet: `return axios.get(`${API_URL}/resource/${resourceId}`)`
- **[Medium] Network**: 外部请求: 发现 HTTP/HTTPS 远程请求调用
  - Location: `node_mcp_server.md:942`
  - Snippet: `- [ ] Error handling uses proper type guards (e.g., `axios.isAxiosError`, `z.ZodError`)`

#### Possible Attack Scenarios

- 未经授权的外部网络通信 / C2 控制

#### Security Recommendations

- 限制外部网络调用，审查通信目标的合法性 (Restrict network calls)

---

### Skill: scripts
**Risk Score:** 0
**Risk Level:** Safe

#### Detected Issues

- 未发现安全问题

### Skill: brand-guidelines
**Risk Score:** 0
**Risk Level:** Safe

#### Detected Issues

- 未发现安全问题

### Skill: docx
**Risk Score:** 100
**Risk Level:** Critical

#### Detected Issues

- **[Critical] Shell Execution**: 系统命令: 发现执行底层系统命令的操作
  - Location: `pack.py:103`
  - Snippet: `result = subprocess.run(`
- **[Critical] Shell Execution**: 系统命令: 发现执行底层系统命令的操作
  - Location: `redlining.py:153`
  - Snippet: `result = subprocess.run(`
- **[Critical] Shell Execution**: 系统命令: 发现执行底层系统命令的操作
  - Location: `redlining.py:185`
  - Snippet: `result = subprocess.run(`
- **[Medium] File System**: 系统修改: 试图更改文件权限或删除目录结构
  - Location: `document.py:836`
  - Snippet: `shutil.rmtree(self.temp_dir)`

#### Possible Attack Scenarios

- 通过修改配置文件或窃取系统凭证攻陷系统
- 远程命令执行 (RCE) / 任意代码执行

#### Security Recommendations

- 对关键敏感目录设置严格的文件系统访问限制 (Restrict FS access)
- 避免使用 eval/exec 和底层系统命令，使用更安全的标准库替代操作 (Audit execution logic)

---

### Skill: web-artifacts-builder
**Risk Score:** 0
**Risk Level:** Safe

#### Detected Issues

- 未发现安全问题
