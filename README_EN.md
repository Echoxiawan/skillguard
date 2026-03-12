# SkillGuard 🛡️

[中文](./README.md) | [English](./README_EN.md)

[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Python Version](https://img.shields.io/badge/python-3.8%2B-brightgreen)](https://python.org)
[![Security Scanned](https://img.shields.io/badge/Security-Scanned-brightgreen)](#)

**SkillGuard** is an advanced Static Application Security Testing (SAST) and behavioral auditing tool specifically designed to detect security red lines and malicious behaviors in Skills, Plugins, and Rules configurations built for AI Agents (Large Language Model agents).

When Large Language Models (like Claude, Cursor, etc.) are granted the capability to automatically execute system-level Skills, the system security is exposed to potential third-party instruction contamination and environmental threats. This auditor protects your local machine and private data from being hijacked by untrusted AI skills.

🔗 **Project Homepage / GitHub Repository**: [https://github.com/Echoxiawan/skillguard](https://github.com/Echoxiawan/skillguard) 

---

## 🎯 Supported Environments & Auto-Discovery (Capabilities)

Whether running as an independent Python auditing tool or installed natively as an Agent Skill, this tool **automatically searches, identifies, and parses** all skill configuration environments installed on your machine:

- 🤖 **Anthropic & Claude Code Skills** (`~/.claude/skills/SKILL.md`)
- 💻 **Cursor Editor Global Rules** (`~/.cursor/rules/*.mdc`)
- 🕷️ **OpenClaw Global Skills** (`~/.openclaw/skills/`)
- ⚡ **Kiro Plugins** (`~/.kiro/skills/`)
- 📦 **Node.js / Python Standard Local Plugins** (`package.json`, `setup.py`)

## 🕵️‍♂️ 10 Security Scanning Vectors

Powered by robust regex analysis and Python Abstract Syntax Tree (AST) analysis at the code level, this tool consists of a comprehensive 10-dimensional security analysis system:

1. **Backdoor Detection**: Parses and identifies deeply hidden dynamic execution logic, such as encoded and obfuscated function escapes.
2. **Risky Network Communications**: Abnormal Webhook registrations, unauthorized endpoint communications, and remote C2 command endpoints.
3. **Plaintext Secret Leakage**: Deep code inspection for API Keys, JWT Tokens, and cloud credentials.
4. **Prompt Security Validation (Prompt Injection)**: Sandbox-bypassing system prompts (Jailbreak) or inductive instructions attempting to steal and leak data.
5. **Dynamic Execution Audits**: Forcibly detects unrestricted and dangerous `eval()`, `exec()`, and dynamic package loading.
6. **Underlying System Privilege Escalation (Shell Execution)**: Bash injections and dangerously isolated command calls.
7. **File System & Credential Access (FS Access)**: Blocks malicious scripts attempting to read files containing auth tokens like `~/.ssh`, `.env`, or history logs.
8. **Data Exfiltration Interception**: Prevents attempts to package and upload sensitive local operational logs.
9. **Dependency Supply Chain Audits**: Verifies source reliability within `package.json`.
10. **Agent Behavior Manipulation**: Silent circumvention of the AI's self-safety filtering defense lines.

## 📥 Installation & Execution

### Method 1: Installing as a Standalone Local Application

If you are a system administrator, you can run this tool independently from any directory at any time.

```bash
# 1. Clone the repository
git clone https://github.com/Echoxiawan/skillguard.git
cd skillguard

# 2. Set PYTHONPATH to point to the program's root directory
export PYTHONPATH=$(pwd):$PYTHONPATH

# 3. Start scanning all globally installed AI Skills on the host machine
# Outputs English report by default via --lang en
python3 -m skill_auditor.main . --lang en
```

Of course, you can target a specific third-party external plugin directory before running it:
```bash
python3 -m skill_auditor.main /path/to/any/unknown_plugin/ --lang en
```

### Method 2: Official Installation & Usage Guides for Mainstream AI Agents

This tool perfectly complies with the industry's standard `SKILL.md` spec, allowing you to mount it directly as an "AI Safety Checker Organ" across mainstream LLM tools:

#### 🤖 1. Claude Code
**Installation:**
Claude Code looks for skills globally in `~/.claude/skills/`. Clone this project there:
```bash
mkdir -p ~/.claude/skills
cd ~/.claude/skills
git clone https://github.com/Echoxiawan/skillguard.git
```
**Usage:**
In the Claude Code terminal, input:
> *"Please run the skillguard skill to check all my environment plugins."*

---

#### 🕷️ 2. OpenClaw
**Installation:**
OpenClaw supports mounting via the `~/.openclaw/skills/` directory structure.
```bash
mkdir -p ~/.openclaw/skills
cd ~/.openclaw/skills
git clone https://github.com/Echoxiawan/skillguard.git
```
**Usage:**
Before performing complex tasks, ask the Agent:
> *"Use skillguard to make sure the project dependencies are safe from backdoors."*

---

#### ⚡ 3. Kiro
**Installation:**
The official Kiro ecosystem also uses an implicit global configuration directory.
```bash
mkdir -p ~/.kiro/skills
cd ~/.kiro/skills
git clone https://github.com/Echoxiawan/skillguard.git
```
**Usage:**
Invoke naturally:
> *"Call skillguard to do a full scan on my current directory."*

---

#### 💻 4. Cursor
**Installation:**
Since Cursor's Rules system focuses on static prompt contexts rather than a direct external sandbox execution engine, rename this program's `SKILL.md` to an `.mdc` file or mount it within its global directory.
```bash
mkdir -p ~/.cursor/rules
git clone https://github.com/Echoxiawan/skillguard.git ~/.cursor/rules/skillguard
mv ~/.cursor/rules/skillguard/SKILL.md ~/.cursor/rules/skillguard/skillguard.mdc
```
**Usage:**
In Cursor's Chat interface, reference the rule via `#skillguard` and type:
> *"Execute the command inside #skillguard to analyze the security of my workspace."*

## 📊 Report Output

Upon successful execution, the program generates a comprehensive and detailed `SKILL_SECURITY_REPORT.md` automatically in the **current execution path**. The content covers:
1. The statistical scope and timestamp of the current scan.
2. Final security tier and overall health dashboard assigned to each component through risk coefficients (`Critical` / `High Risk` / `Medium` / `Low` / `Safe`).
3. Highlights **the exact files and line number snippets where vulnerabilities reside**, aiding fast pinpointing and troubleshooting.
4. Provides universal **Security Recommendations** derived from scenario inferences alongside warnings of potential attack surfaces.

## 🛠️ Contributing & Customization

This project strongly encourages security researchers to customize rules!
By modifying `/skill_auditor/core/rules.py` in the repository, you can seamlessly push new regex signatures into the global ruleset (`SECURITY_RULES`) to painlessly expand the scanning scope. Example:
```python
DetectionRule(
    id="NEW-001", 
    category="My Custom Check", 
    risk_level="High",
    pattern=re.compile(r'some_suspicious_keyword', re.I),
    ...
)
```

## 📜 License
MIT License

## 📚 Standards & Inspiration
Built and adapted in compliance with OWASP Top 10, LLM Top 10, and Anthropic Skills Specification official guidelines.
