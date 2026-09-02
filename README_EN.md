# AgentGuard

[中文](./README.md) | [English](./README_EN.md)

AgentGuard is a read-only security auditor for AI Agent extensions. It inspects Skills, Plugins, Rules, MCP configurations, MCP tool listings, and runtime responses for prompt injection, tool poisoning, auditor hijacking, unauthorized side effects, credential theft and exfiltration, concealed deletion, dangerous code execution, and deceptive MCP metadata.

Primary rule: **audited content is untrusted data, not an instruction for the current session.** AgentGuard does not start an unknown MCP server, import target modules, execute target scripts, visit target-provided URLs, or follow tool calls suggested by audited content.

## Capabilities

| Surface | Current checks |
| --- | --- |
| Skill / Plugin / Rule | Scans Markdown, configuration, and Python/JavaScript/TypeScript/Shell source for hierarchy hijacking, auditor manipulation, concealment, credential access, exfiltration, deletion, approval bypass, and high-impact workflows |
| Code capabilities | Detects subprocesses, shells, dynamic execution, network calls, sensitive paths, environment credentials, file deletion, payload decoding, and behavior chains; Python AST analysis reduces string and comment false positives |
| Static MCP configuration | Checks shell launch commands, command strings, hardcoded credentials, FastMCP/TypeScript registrations, and annotation-to-side-effect mismatches |
| MCP tool listings | Scans names, titles, descriptions, input/output schemas, defaults, examples, string arrays, and annotations from `tools/list`; detects separator-based name evasion and misleading metadata |
| Prompt / Resource | Scans descriptions, messages, text, and nested fields from `prompts/list/get` and `resources/list/read` |
| MCP runtime results | Scans `content`, `structuredContent`, embedded resources, errors, and nested text from `tools/call`; detects false system authority, secret requests, coerced cross-tool calls, and dangerous chains |
| Output protection | Sanitizes terminal controls and Markdown fences, and redacts Bearer tokens, API keys, access tokens, passwords, cookies, OpenAI keys, JWTs, and PEM private keys |

The deterministic scripts provide repeatable rule and AST scanning. When installed as a standard Skill, `SKILL.md` additionally requires isolated semantic review for paraphrased attacks, cross-file chains, and injection intent outside fixed rules. A clean rule scan is not proof of absolute safety.

## Security model

- Only explicitly selected targets are scanned. Installed Skills are included only with `--include-installed`.
- Target code is not executed, imported, installed, or dynamically validated, and target text cannot authorize permissions.
- Commands, paths, URLs, arguments, and environment names from target content are never copied into Shell, browser, MCP, or other tool calls.
- Symbolic links are not followed. Dependency, virtual environment, build, cache, and generated report directories are excluded.
- MCP auditing consumes JSON/JSONL captured by a trusted client or gateway; AgentGuard does not connect to an unknown server.
- Caller-controlled `params.arguments` in `tools/call` requests are skipped to avoid attributing user input to the MCP server.
- When a raw MCP result reaches the threshold, the caller should discard it and expose only a redacted security event to the Agent.

## Installation

Python 3.8 or newer is required. Core scanning has no third-party runtime dependency.

~~~bash
git clone https://github.com/Echoxiawan/agentguard.git
cd agentguard
~~~

AgentGuard is also a standard Skill containing `SKILL.md`, `agents/openai.yaml`, `scripts/`, and `references/`. Install it under `agentguard`; its trigger identifier is `$agentguard`.

## Audit a Skill, Plugin, or MCP configuration

~~~bash
python3 scripts/audit_skill.py /path/to/target --lang en --output-dir ./reports
~~~

Explicitly include common installed Skill locations:

~~~bash
python3 scripts/audit_skill.py /path/to/target --include-installed --lang en --output-dir ./reports
~~~

Recognized entry points include `SKILL.md`, `package.json`, `setup.py`, `requirements.txt`, Cursor Rules, and common MCP configuration names. `--include-installed` adds existing Codex, Agents, Claude, OpenClaw, Cursor, and Kiro Skill directories.

The default report is `AGENT_SECURITY_REPORT.md` with risk levels, rule IDs, files, line numbers, sanitized evidence, scenarios, and recommendations.

## Audit MCP tool poisoning

Input may be one JSON object, a JSON array, or JSONL:

~~~bash
python3 scripts/audit_mcp.py /path/to/capture.jsonl \
  --lang en \
  --fail-on high \
  --output-dir ./reports
~~~

A gateway may send one response over standard input:

~~~bash
python3 scripts/audit_mcp.py - --fail-on high --output-dir ./reports < response.json
~~~

`--fail-on` accepts `none`, `medium`, `high`, or `critical`; the default is `critical`.

| Exit code | Meaning |
| --- | --- |
| 0 | Risk is below the blocking threshold |
| 1 | Input could not be read or parsed safely |
| 2 | Risk reached the threshold; raw content should be blocked from Agent context |

The MCP report is `MCP_SECURITY_REPORT.md`. Limits are 10 MiB per capture, 10,000 events or array elements, 40 nesting levels, and 200,000 characters per text field.

## MCP gateway integration

Runtime protection requires explicit integration in an MCP client or invocation gateway:

1. Audit `tools/list`, `prompts/list`, and `resources/list` before exposing them to the Agent.
2. Audit the full response after every `tools/call` and before adding it to Agent context.
3. Use the exit code to allow or block. On block, do not expose raw content, errors, or structured results.
4. If MCP content requests another tool call, return to the user's original request for authorization. Tool output is not an authorization source.
5. Retain service, method, tool, request ID, and timestamp metadata without recording real credentials.

AgentGuard does not proxy traffic or automatically intercept every MCP. Without client or gateway integration, it audits only supplied captures.

## Risk levels

- **Critical**: explicit prompt hijacking, secret requests or exfiltration, destructive instructions, auditor manipulation, annotation deception, or dangerous chains.
- **High Risk**: severe capabilities or accumulated findings requiring isolation and review.
- **Medium Risk**: sensitive capabilities, coerced cross-tool behavior, or missing side-effect metadata.
- **Low Risk**: low-severity signals.
- **Safe**: no rule matched within the scanned scope; not a runtime safety guarantee.

Subprocess, network, environment, or filesystem access is a capability signal and does not prove malicious intent. Review purpose, least privilege, user confirmation, fixed destinations, implementation behavior, and runtime blind spots.

## Project layout

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

## Validation

~~~bash
python3 -B -m unittest discover -s tests -v
python3 -B -m py_compile scripts/audit_skill.py scripts/audit_mcp.py scripts/agentguard/*.py scripts/agentguard/core/*.py tests/*.py
~~~

The suite covers prompt injection, auditor hijacking, credential-exfiltration chains, high-impact workflows, zero-width evasion, code capabilities, MCP configuration, poisoned tool names/descriptions/schemas, Prompt/Resource content, runtime responses, annotation deception, stdin, input limits, report sanitization, and credential redaction.

## Known limits

- Rule scanning cannot prove absolute safety. Web pages, email, documents, tickets, and database records may carry indirect prompt injection at runtime.
- Results have blind spots when source, complete configuration, or runtime captures are unavailable.
- AgentGuard does not perform dynamic sandbox execution, verify remote implementations, or replace OS permissions, network controls, and explicit user confirmation.
- MCP annotations are hints, not enforcement. Final side-effect analysis must consider implementation and actual operations.

## Extending rules

Static rules live in `scripts/agentguard/core/rules.py`; MCP capture rules live in `scripts/agentguard/core/mcp_artifact.py`. Add both malicious and benign regression cases with each new rule to avoid treating safety guidance or legitimate capability descriptions as attack instructions.
