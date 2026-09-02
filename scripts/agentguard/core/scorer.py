from typing import Any, Dict

RISK_WEIGHTS = {"Critical": 55, "High": 28, "Medium": 12, "Low": 4}
LEVEL_ORDER = {"Low": 1, "Medium": 2, "High": 3, "Critical": 4}
DIRECT_CRITICAL_RULES = {
    "MCP-001",  # 通过命令解释器启动
    "MCP-002",  # 执行命令字符串
    "MCP-004",  # 配置中硬编码凭据
    "MCP-006",  # 伪装成只读工具
    "MCP-007",  # 伪装成非破坏性工具
    "MCP-009",  # MCP 内容投毒 Agent
    "MCP-RUNTIME-001",  # MCP 清单或返回内容投毒
    "MCP-RUNTIME-003",  # MCP 索取凭据作为参数
    "MCP-RUNTIME-004",  # MCP 伪造高优先级身份
    "MCP-RUNTIME-006",  # 运行时清单伪装只读
    "MCP-RUNTIME-007",  # 运行时清单伪装非破坏性
}


class RiskScorer:
    @staticmethod
    def calculate_risk(skill_info: Dict[str, Any]) -> Dict[str, Any]:
        """重复命中折算计分，最高严重度决定最终评级下限。"""
        issues = skill_info.get("issues", [])
        counts: Dict[str, int] = {}
        score = 0
        for issue in issues:
            level = issue.get("risk_level", "Low")
            count = counts.get(level, 0)
            weight = RISK_WEIGHTS.get(level, 0)
            score += weight if count == 0 else max(2, weight // 4)
            counts[level] = count + 1

        score = min(100, score)
        max_level = max((issue.get("risk_level", "Low") for issue in issues),
                        key=lambda level: LEVEL_ORDER.get(level, 0), default=None)
        has_chain = any(issue.get("rule_id", "").startswith("CHAIN-") for issue in issues)
        has_critical_prompt = any(
            issue.get("risk_level") == "Critical" and issue.get("rule_id", "").startswith("PI-")
            for issue in issues)
        has_direct_critical = any(
            issue.get("rule_id") in DIRECT_CRITICAL_RULES for issue in issues)

        if not issues:
            risk_level = "Safe"
        elif has_chain or has_critical_prompt or has_direct_critical or score >= 85:
            risk_level = "Critical"
            score = max(score, 85)
        elif max_level == "Critical" or score >= 55:
            risk_level = "High Risk"
            score = max(score, 55)
        elif max_level == "High" or score >= 25:
            risk_level = "Medium Risk"
            score = max(score, 25)
        else:
            risk_level = "Low Risk"

        skill_info["risk_score"] = min(score, 100)
        skill_info["risk_level"] = risk_level
        return skill_info
