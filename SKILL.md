---
name: skillguard
description: SkillGuard 高级AI安全审计工具，用于扫描并检测AI代理Skill/Plugin中的后门代码、Prompt越狱、密钥泄露等10类安全威胁。
---

# SkillGuard

你正在使用 **SkillGuard**，这是一个专业用于帮助 AI (如 Claude, Cursor, Kiro, OpenClaw 等) 审计其他 AI Skill / 插件的安全工具。它通过静态代码分析（SAST）和抽象语法树（AST）技术深度扫描目标的执行逻辑。

## 能力范围

此 Skill 可通过运行指定的 Python 代码对目标技能目录进行以下高级威胁检测，并给出一份详尽的打分和评估 Markdown 报告：
1. **后门代码检测 (Backdoor Detection)**: 隐藏执行逻辑、条件触发、加密逃逸。
2. **可疑网络行为 (Network Behavior)**: Webhook 挂钩、未知 API 通信。
3. **硬编码密钥 (Secret Leakage)**: 明文密码、JWT Tokens、API Keys。
4. **Prompt 攻击检测 (Prompt Security)**: Prompt 覆盖指令、系统规则越狱、Prompt 窃取。
5. **动态代码执行 (Dynamic Execution)**: `eval()`, `exec()`, 运行时模块加载。
6. **Shell/系统执行 (Shell Execution)**: 底层 OS Shell 注入与调用。
7. **文件系统访问 (File System)**: 访问敏感目录（如 `~/.ssh`, `.env`）。
8. **数据外传 (Data Exfiltration)**: 读取敏感文件并尝试上传的行为机制。
9. **依赖安全扫描 (Supply Chain)**: 恶意第三方包、可疑依赖。
10. **AI Agent 恶意行为**: 静默修改状态、覆盖安全底线操作等。

## 使用方法

当你被要求审计、扫描、检查某个 AI 技能或插件，或是探测某个文件目录是否对 AI 系统安全时，**必须执行本 Skill 提供的审计扫描程序**。

### 命令行执行方式

在你的终端/Bash环境中执行核心分析程序。由于本 Skill 可以被安装在任何机器的任意目录下，执行代码时请确保自动将当前 Skill 的根目录所在路径加入 `PYTHONPATH`。

```bash
# 进入包含此 SKILL.md 的目录（即本 Skill 的安装目录）
export PYTHONPATH=$(pwd):$PYTHONPATH
python3 -m skill_auditor.main <TARGET_DIRECTORY_PATH> --lang <REPORT_LANGUAGE>
```

**参数说明:**
- `<TARGET_DIRECTORY_PATH>`: （必填）要扫描的技能/插件所在目录（绝对路径或相对路径）。如果扫描当前目录请使用 `.`。
- `--lang`: （可选）生成的安全报告语言。可选值：`zh` (中文), `en` (英文), `auto` (自动)。默认：`auto`。

该命令执行完毕后，在当前项目根目录下会自动生成一份 `SKILL_SECURITY_REPORT.md`。

## 示例 (Examples)

### 示例 1: 扫描指定的未知 AI 技能插件，并生成中文报告
```bash
# 假设当前所在目录为 skillguard 的安装根目录
export PYTHONPATH=$(pwd):$PYTHONPATH
python3 -m skill_auditor.main /path/to/unknown_skill --lang zh
```

### 示例 2: 审计当前分析的目录下的应用安全性，并输出英文报告
```bash
# 假设当前所在目录为 skillguard 的安装根目录
export PYTHONPATH=$(pwd):$PYTHONPATH
python3 -m skill_auditor.main . --lang en
```

## 使用指南 (Guidelines)

1. **绝对不要试图手动运行/导入未知技能**: 在确定技能绝对安全之前，**禁止**运行目标插件的入口文件或模块进行动态调试，请严格依赖本 Skill 的静态审计脚本。
2. **阅读生成的报告**: `skill_auditor.main` 成功运行后，**必须**使用读取文件工具读取生成的 `SKILL_SECURITY_REPORT.md`，并将其中汇总出的的关键危险结果（如 Critical 或 High Risk）告知人类用户。
3. **安全建议**: 针对报告中提供的每个安全问题（如：硬编码密钥），你应主动向用户传达 `SKILL_SECURITY_REPORT.md` 内生成的修复建议和潜在攻击面信息。
4. **保持警惕**: 有的恶意技能会针对审计工具（如本工具）进行反向探测和隐藏，在审计高危对象时提高安全红线，严禁放过任何 `eval` 以及网络传输函数。
