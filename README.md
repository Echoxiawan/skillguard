# SkillGuard 🛡️

[中文](./README.md) | [English](./README_EN.md)

[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Python Version](https://img.shields.io/badge/python-3.8%2B-brightgreen)](https://python.org)
[![Security Scanned](https://img.shields.io/badge/Security-Scanned-brightgreen)](#)

**SkillGuard** 是一个高级的静态应用安全测试（SAST）和行为审计工具，专门设计用于检测针对 AI Agents（大语言模型代理）的 Skills、Plugins 和 Rules 配置中的安全红线与恶意行为。

当赋予大语言模型（如 Claude、Cursor 等）自动执行各类系统级别 Skill 的能力时，系统安全性会受到潜在的第三方指令污染和环境威胁。本审计器能保护您的本地机器和隐私数据不被不受信任的 AI 技能劫持。

🔗 **项目主页 / GitHub Repository地址**: [https://github.com/Echoxiawan/skillguard](https://github.com/Echoxiawan/skillguard) *(请替换为实际地址)*

---

## 🎯 支持环境与自动发现 (Capabilities)

无论是作为独立的 Python 审计程序运行，还是作为 AI Agent 的原生 Skill 安装，该工具均能**自动搜索、识别并解析**您的机器上已安装的所有技能配置环境：

- 🤖 **Anthropic & Claude Code Skills** (`~/.claude/skills/SKILL.md`)
- 💻 **Cursor 编辑器全局 Rules** (`~/.cursor/rules/*.mdc`)
- 🕷️ **OpenClaw 全局 Skills** (`~/.openclaw/skills/`)
- ⚡ **Kiro Plugins** (`~/.kiro/skills/`)
- 📦 **Node.js / Python 标准本地大插件** (`package.json`, `setup.py`)

## 🕵️‍♂️ 10大安全扫描维度 (Security Vectors)

通过强大的正则表达式分析和基于代码层面的 Python 抽象语法树（AST）分析，本工具包含 10 种维度的全景安全分析系统：

1. **后门代码探测 (Backdoor)**: 解析并识别深藏不露的动态执行逻辑，如加密和混淆的函数逃逸特征。
2. **风险网络通讯 (Network)**: Webhook 异常注册、未经授权的端点通讯、远程 C2 控制端点。
3. **明文密钥过滤 (Secret Leakage)**: 深层代码中的 API Key、JWT Token 与云凭证查找。
4. **Prompt 安全验证 (Prompt Injection)**: 绕过沙箱的系统提示词（Jailbreak）或导致数据向外泄露的诱导指令窃取。
5. **动态代码执行审查 (Dynamic Execution)**: 强制检索出不受限危险的 `eval()`, `exec()` 与动态加载包操作。
6. **底层系统提权 (Shell Execution)**: Bash 注入和未隔离调用的危险命令。
7. **文件系统与凭据越权 (FS Access)**: 阻止恶意脚本尝试读取 `~/.ssh`, `.env` 或历史文件等包含认证令牌的内容。
8. **外发数据拦截 (Data Exfiltration)**: 防止尝试打包上传本地应用产生的敏感信息日志。
9. **依赖供应链审计 (Supply Chain)**: 核对 `package.json` 中的源可靠性。
10. **Agent 操纵 (AI Behavior)**: 静默绕过 AI 的自我安全过滤防线等行为。

## 📥 安装与运行

### 方式一: 作为普通指令的本地应用安装 (Standalone)

如果你是系统管理员，可以随时将其独立地获取到任意目录下运行。

```bash
# 1. 克隆代码库
git clone https://github.com/Echoxiawan/skillguard.git
cd skillguard

# 2. 设置 PYTHONPATH 指向本程序根目录
export PYTHONPATH=$(pwd):$PYTHONPATH

# 3. 开始扫描整个宿主机的所有已装全局 AI Skills，并输出默认评估语言的检查单：
python3 -m skill_auditor.main .
```

当然，你可以指定检测特定的第三方外置插件事前目录：
```bash
python3 -m skill_auditor.main /path/to/any/unknown_plugin/ --lang zh
```

### 方式二: 各主流 AI 代理工具官方安装与使用指南

该工具完美符合业界通用的 `SKILL.md` 标准，你可以直接将其作为“AI 的一个检查器官”挂载至各主流大模型工具内：

#### 🤖 1. Claude Code
**安装：**
Claude Code 会在全局 `~/.claude/skills/` 寻找技能。将本项目 Clone 至该目录：
```bash
mkdir -p ~/.claude/skills
cd ~/.claude/skills
git clone https://github.com/Echoxiawan/skillguard.git
```
**使用方式：**
在 Claude Code 终端中输入：
> *"Please run the skillguard skill to check all my environment plugins."*

---

#### 🕷️ 2. OpenClaw
**安装：**
OpenClaw 默认支持通过 `~/.openclaw/skills/` 的目录结构挂载。
```bash
mkdir -p ~/.openclaw/skills
cd ~/.openclaw/skills
git clone https://github.com/Echoxiawan/skillguard.git
```
**使用方式：**
在进行复杂任务前，可以要求 Agent：
> *"Use skillguard to make sure the project dependencies are safe from backdoors."*

---

#### ⚡ 3. Kiro
**安装：**
Kiro 官方体系同样使用隐式全局配置目录。
```bash
mkdir -p ~/.kiro/skills
cd ~/.kiro/skills
git clone https://github.com/Echoxiawan/skillguard.git
```
**使用方式：**
通过自然语言调度：
> *"Call skillguard to do a full scan on my current directory."*

---

#### 💻 4. Cursor
**安装：**
由于 Cursor 的 Rules 系统侧重于静态 prompt 上下文而非直接外部沙盒执行引擎，你需要将此程序的 `SKILL.md` 重命名为 `.mdc` 文件或者挂载到其全局目录下。
```bash
mkdir -p ~/.cursor/rules
git clone https://github.com/Echoxiawan/skillguard.git ~/.cursor/rules/skillguard
mv ~/.cursor/rules/skillguard/SKILL.md ~/.cursor/rules/skillguard/skillguard.mdc
```
**使用方式：**
在 Cursor 的 Chat 界面中通过 `#skillguard` 引用该规则并输入:
> *"Execute the command inside #skillguard to analyze the security of my workspace."*

## 📊 审计报告输出 (Report Output)

成功运行后，程序会在当前**执行路径下**自动生成一份详尽周到的 `SKILL_SECURITY_REPORT.md`。内容将涵盖：
1. 本次扫描的范围统计与时间点。
2. 以不同风险系数 (`Critical` / `High Risk` / `Medium` / `Low` / `Safe`) 给每个组件颁发最终的安全等级和总体健康看板。
3. 标注出**漏洞存在的代码具体文件及行号片段**，协助你进行快速锁定与排查。
4. 提供基于场景推导的通用**安全改进建议（Security Recommendations）**与可能的应用被攻破面的危险警告。

## 🛠️ 如何参与贡献与自定义

本项目鼓励安全研究员参与定制规则！
通过修改仓库底下的 `/skill_auditor/core/rules.py`，你只需要向全局规则集合中（`SECURITY_RULES`）推入新的正则表达式特征即可无代码侵入地迅速扩展扫描版图。例如：
```python
DetectionRule(
    id="NEW-001", 
    category="My Custom Check", 
    risk_level="High",
    pattern=re.compile(r'some_suspicious_keyword', re.I),
    ...
)
```

## 📜 许可规范
MIT License

## 📚 标准与灵感来源
遵循并适配 OWASP Top 10, LLM Top 10, 及 Anthropic Skills Specification 官方文档标准制作。
