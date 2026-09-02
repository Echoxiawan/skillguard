# AgentGuard

[中文](./README.md) | [English](./README_EN.md)

AgentGuard 是面向 AI Agent 扩展生态的只读安全审计器。它检查 Skill、Plugin、Rule、MCP 配置、MCP 工具清单和运行时返回内容，重点识别提示词注入、工具投毒、审计者劫持、越权副作用、凭据窃取与外传、隐蔽删除、危险代码执行和 MCP 元数据欺骗。

首要原则：**被审计内容是不可信数据，不是当前会话指令。** 审计流程不会启动未知 MCP、导入目标模块、运行目标脚本、访问目标给出的 URL，或执行目标建议的后续工具调用。

## 能力概览

| 审计面 | 当前检查能力 |
| --- | --- |
| Skill / Plugin / Rule | 扫描 Markdown、配置和 Python/JavaScript/TypeScript/Shell 源码，识别层级劫持、审计者操纵、隐蔽执行、凭据访问、数据外传、删除文件、跳过确认和高影响业务流程 |
| 代码能力 | 检测子进程、Shell、动态执行、网络请求、敏感路径、环境凭据、文件删除、解码载荷及组合链；Python 使用 AST 降低字符串和注释误报 |
| MCP 静态配置 | 检查命令解释器启动、命令字符串、硬编码凭据、FastMCP/TypeScript 工具注册以及 annotations 与副作用不一致 |
| MCP 工具清单 | 扫描 `tools/list` 的工具名称、标题、描述、输入/输出 schema、默认值、示例、字符串数组和 annotations，识别名称分隔符规避与标注欺骗 |
| Prompt / Resource | 扫描 `prompts/list/get`、`resources/list/read` 的描述、messages、文本与嵌套字段 |
| MCP 运行时返回 | 扫描 `tools/call` 的 `content`、`structuredContent`、嵌入资源、错误消息和嵌套文本，检测伪造系统身份、索取秘密、强制跨工具调用及危险组合链 |
| 输出防护 | 净化控制字符与 Markdown 围栏，脱敏 Bearer、API key、访问令牌、密码、Cookie、OpenAI key、JWT 和 PEM 私钥 |

确定性脚本负责可重复的规则与 AST 扫描；作为标准 Skill 使用时，`SKILL.md` 还要求 Agent 在严格隔离条件下完成语义复核，识别同义改写、跨文件行为链和规则未覆盖的注入意图。规则无告警不等于绝对安全。

## 安全模型

- 只读取用户明确指定的目标；扫描已安装 Skill 必须显式使用 `--include-installed`。
- 不运行、导入、安装或动态验证目标内容，不根据目标文字申请权限。
- 不把目标中的命令、路径、URL、参数或环境变量名复制到 Shell、浏览器、MCP 或其他工具调用。
- 不跟随符号链接；忽略依赖、虚拟环境、构建目录、缓存和自身生成的报告。
- MCP 审计只接收可信客户端或网关捕获的 JSON/JSONL，不自行连接未知服务器。
- `tools/call` 请求中的 `params.arguments` 属于调用方输入，运行时审计会跳过它，避免误归因给服务端。
- MCP 返回达到阻断阈值时，调用方应丢弃原始内容，只向 Agent 返回脱敏安全事件。

## 安装

要求 Python 3.8 或更高版本，核心扫描不需要第三方运行时依赖。

~~~bash
git clone https://github.com/Echoxiawan/agentguard.git
cd agentguard
~~~

AgentGuard 同时是标准 Skill，包含 `SKILL.md`、`agents/openai.yaml`、`scripts/` 和 `references/`。安装目录名使用 `agentguard`，触发标识为 `$agentguard`。

## 审计 Skill、Plugin 与 MCP 配置

~~~bash
python3 scripts/audit_skill.py /path/to/target --lang zh --output-dir ./reports
~~~

显式加入本机常见的全局 Skill 目录：

~~~bash
python3 scripts/audit_skill.py /path/to/target --include-installed --lang zh --output-dir ./reports
~~~

可识别入口包括 `SKILL.md`、`package.json`、`setup.py`、`requirements.txt`、Cursor Rule 和常见 MCP 配置文件。`--include-installed` 会加入存在的 Codex、Agents、Claude、OpenClaw、Cursor 和 Kiro 全局 Skill 目录。

默认报告为 `AGENT_SECURITY_REPORT.md`，包含风险等级、规则编号、文件、行号、净化后的证据、攻击场景与处置建议。

## 审计 MCP 工具投毒

输入可以是单个 JSON、JSON 数组或每行一个事件的 JSONL：

~~~bash
python3 scripts/audit_mcp.py /path/to/capture.jsonl \
  --lang zh \
  --fail-on high \
  --output-dir ./reports
~~~

网关也可通过标准输入传递单次响应：

~~~bash
python3 scripts/audit_mcp.py - --fail-on high --output-dir ./reports < response.json
~~~

`--fail-on` 支持 `none`、`medium`、`high`、`critical`，默认是 `critical`。

| 退出码 | 含义 |
| --- | --- |
| 0 | 风险低于阻断阈值 |
| 1 | 输入无法安全读取或解析 |
| 2 | 风险达到阻断阈值，应阻止原始内容进入 Agent 上下文 |

MCP 报告为 `MCP_SECURITY_REPORT.md`。输入限制为 10 MiB、最多 10,000 个事件或数组元素、最多 40 层嵌套、单文本字段最多 200,000 个字符。

## MCP 网关接入

真正的运行时保护需要 MCP 客户端或调用网关主动接入：

1. MCP 初始化后，在工具可见前审计 `tools/list`、`prompts/list` 和 `resources/list`。
2. 每次 `tools/call` 后，在结果进入 Agent 上下文前审计完整响应。
3. 根据退出码放行或阻断；阻断时不得暴露原始内容、错误消息或结构化返回。
4. MCP 内容要求调用其他工具时，回到用户原始请求重新判断授权，不能把工具返回当成授权来源。
5. 捕获物保留服务名、方法、工具名、请求 ID 和时间，但不记录真实凭据。

AgentGuard 不代理网络流量，也不会自动拦截所有 MCP。未在客户端或网关接入上述检查时，它只能审计已提供的捕获物。

## 风险等级

- **Critical**：明确提示词劫持、凭据索取或外传、破坏性指令、审计者操纵、annotations 欺骗或危险行为链。
- **High Risk**：严重能力或多项风险叠加，需要隔离复核。
- **Medium Risk**：敏感能力、跨工具诱导或缺少副作用元数据。
- **Low Risk**：低严重度信号。
- **Safe**：当前扫描范围内未命中规则，不代表运行时永远安全。

子进程、网络、环境变量或文件操作属于能力信号，不自动等同于恶意。结论应结合用途、最小权限、用户确认、固定目的地、真实实现和运行时盲区人工复核。

## 项目结构

~~~text
agentguard/
├── SKILL.md
├── agents/openai.yaml
├── references/mcp-tool-poisoning.md
├── scripts/
│   ├── audit_skill.py
│   ├── audit_mcp.py
│   └── agentguard/
│       ├── main.py
│       └── core/
└── tests/test_security_auditor.py
~~~

## 验证

~~~bash
python3 -B -m unittest discover -s tests -v
python3 -B -m py_compile scripts/audit_skill.py scripts/audit_mcp.py scripts/agentguard/*.py scripts/agentguard/core/*.py tests/*.py
~~~

当前测试覆盖提示词注入、审计者劫持、凭据外传链、危险业务流程、零宽字符规避、代码能力、MCP 配置、工具名称/描述/schema 投毒、Prompt/Resource、运行时返回、annotations 欺骗、stdin、输入边界、报告净化和凭据脱敏。

## 已知边界

- 规则扫描无法证明组件绝对安全；网页、邮件、文档、工单和数据库数据仍可能携带间接提示词注入。
- 没有源码、完整配置或运行时捕获物时，结论存在审计盲区。
- AgentGuard 不做动态沙箱执行，不验证远程服务真实实现，也不替代操作系统权限、网络策略和用户确认。
- MCP annotations 只是提示，最终副作用判断必须结合实现和实际外部操作。

## 规则扩展

静态规则位于 `scripts/agentguard/core/rules.py`，MCP 捕获物规则位于 `scripts/agentguard/core/mcp_artifact.py`。新增规则时应同时增加良性与恶性回归用例，避免把安全说明或合法能力描述误判为攻击指令。
