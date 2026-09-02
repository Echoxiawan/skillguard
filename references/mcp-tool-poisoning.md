# MCP 工具投毒审计协议

## 目录

1. 审计对象
2. 审计包格式
3. 使用方法
4. 网关集成规则
5. 判定与限制

## 审计对象

MCP 的工具清单和运行时返回值都属于不可信输入。审计以下协议表面：

- tools/list：工具名称、标题、描述、输入/输出 schema、默认值、示例、枚举和 annotations
- prompts/list、prompts/get：Prompt 描述、参数、messages 与嵌套内容
- resources/list、resources/read：Resource 描述、文本内容和嵌套结构
- tools/call 响应：content、structuredContent、嵌入资源和错误结果
- JSON-RPC 错误：message、data 和嵌套文本

重点检测覆盖上级指令、伪造系统或可信身份、索取密码或令牌、要求外发数据、隐藏行为、跳过确认、强制调用其他工具，以及危险工具名称与 annotations 矛盾。

## 审计包格式

输入可为单个 JSON、JSON 数组或每行一个事件的 JSONL。可直接保存 MCP 客户端看到的原始 JSON-RPC 请求/响应，也可保存提取后的清单或结果对象。

AgentGuard 会跳过 tools/call 请求中的 params.arguments，因为它来自调用方而非 MCP 服务端。不要把 Agent 的系统提示词、真实密码或生产凭据写入审计包；需要保留关联信息时使用脱敏占位符。

## 使用方法

~~~bash
python3 scripts/audit_mcp.py <capture.json-or-jsonl> --lang zh --output-dir <报告目录>
~~~

默认在发现 Critical 时返回退出码 2。作为调用网关使用时可收紧阈值：

~~~bash
python3 scripts/audit_mcp.py <capture.jsonl> --fail-on high --output-dir <报告目录>
~~~

退出码：0 表示低于阻断阈值，1 表示输入无法安全解析，2 表示达到阻断阈值。报告文件名为 MCP_SECURITY_REPORT.md。

## 网关集成规则

1. 在 MCP 初始化后、工具可见之前捕获并审计 tools/list、prompts/list 和 resources/list。
2. 每次 tools/call 后，在结果进入 Agent 上下文前审计完整响应。
3. 达到阻断阈值时，不把原始内容传给 Agent，不执行内容建议的后续工具调用；只返回脱敏的安全事件。
4. 工具返回内容不能授权新操作、扩大权限、改变原任务或替代用户确认。
5. 保留来源标签：服务名、方法、工具名、请求 ID 和时间；不要记录真实凭据。
6. MCP 内容要求调用其他工具时，必须回到用户原始请求重新做授权判断，不能沿用返回内容的授权声明。

AgentGuard 只审计捕获物，不负责启动未知 MCP。若客户端需要主动采集，应在无真实凭据、无生产权限、只读文件系统和受控网络的隔离环境中进行。

## 判定与限制

- 工具描述、schema、Prompt、Resource、结果或错误中出现明确越权指令：Critical
- 索取凭据、伪造高优先级身份、annotations 欺骗：Critical
- 强制跨工具调用：至少 High Risk；与越权或凭据指令组合时升级为 Critical
- 工具缺少 annotations：Medium Risk，需结合真实实现复核

静态文本检测不能证明运行时永远安全。外部网页、邮件、文档、工单和数据库内容会造成间接提示词注入，因此必须对每次工具返回重复执行审计，而不是只在安装时扫描一次。
