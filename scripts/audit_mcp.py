#!/usr/bin/env python3
"""审计已捕获的 MCP JSON/JSONL，不启动或调用 MCP。"""

import argparse
import os
import sys

from agentguard.core.mcp_artifact import (
    MAX_CAPTURE_BYTES,
    McpArtifactAnalyzer,
    McpCaptureError,
    load_mcp_capture,
    parse_mcp_capture,
)
from agentguard.core.reporter import MarkdownReporter
from agentguard.core.scorer import RiskScorer


FAIL_LEVELS = {
    "none": 99,
    "medium": 2,
    "high": 3,
    "critical": 4,
}
REPORT_LEVELS = {
    "Safe": 0,
    "Low Risk": 1,
    "Medium Risk": 2,
    "High Risk": 3,
    "Critical": 4,
}


def main() -> int:
    parser = argparse.ArgumentParser(
        description="AgentGuard MCP tool-poisoning artifact auditor")
    parser.add_argument("capture", help="MCP JSON/JSONL 审计包路径；- 表示标准输入")
    parser.add_argument("--lang", choices=["zh", "en"], default="zh")
    parser.add_argument("--output-dir", default=".")
    parser.add_argument(
        "--fail-on", choices=["none", "medium", "high", "critical"],
        default="critical", help="达到该风险等级时返回退出码 2")
    args = parser.parse_args()

    source = os.path.abspath(args.capture)
    try:
        if args.capture == "-":
            raw = sys.stdin.buffer.read(MAX_CAPTURE_BYTES + 1)
            if len(raw) > MAX_CAPTURE_BYTES:
                raise McpCaptureError(f"标准输入超过 {MAX_CAPTURE_BYTES} 字节限制")
            try:
                capture = parse_mcp_capture(raw.decode("utf-8"))
            except UnicodeDecodeError as exc:
                raise McpCaptureError("标准输入不是合法 UTF-8") from exc
            source = "<stdin>"
        else:
            capture = load_mcp_capture(source)
        result = McpArtifactAnalyzer().analyze(capture, source)
    except McpCaptureError as exc:
        print(f"[!] MCP 审计包解析失败: {exc}", file=sys.stderr)
        return 1

    RiskScorer.calculate_risk(result)
    reporter = MarkdownReporter(lang=args.lang)
    report = reporter.generate_report(
        [result], os.path.abspath(args.output_dir),
        filename="MCP_SECURITY_REPORT.md",
        title="AgentGuard MCP Tool Poisoning Audit Report",
        subject_label="MCP Artifact",
        total_label="MCP Artifacts Scanned")
    print(f"[+] 已检查文本表面: {result.get('surface_count', 0)}")
    print(f"[+] 风险等级: {result['risk_level']}")
    print(f"[+] 报告: {report}")

    threshold = FAIL_LEVELS[args.fail_on]
    return 2 if REPORT_LEVELS[result["risk_level"]] >= threshold else 0


if __name__ == "__main__":
    raise SystemExit(main())
