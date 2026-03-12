import os
from datetime import datetime
from typing import List, Dict, Any

class MarkdownReporter:
    def __init__(self, lang="zh"):
        self.lang = lang

    def generate_report(self, skills: List[Dict[str, Any]], output_dir: str):
        report_path = os.path.join(output_dir, "SKILL_SECURITY_REPORT.md")
        
        # 统计数据
        total = len(skills)
        risk_counts = {
            "Critical": 0, "High Risk": 0, "Medium Risk": 0, "Low Risk": 0, "Safe": 0
        }
        for s in skills:
            r = s.get("risk_level", "Safe")
            risk_counts[r] = risk_counts.get(r, 0) + 1
            
        env_name = os.getenv("ENV_NAME", "Local Directory")
        scan_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        # 生成报告头
        lines = [
            "# SkillGuard Security Audit Report\n",
            "## Scan Information\n",
            f"**Scan Time:** {scan_time}",
            f"**Environment:** {env_name}",
            f"**Total Skills Scanned:** {total}\n",
            "## Risk Overview\n",
            f"- **Critical:** {risk_counts['Critical']}",
            f"- **High Risk:** {risk_counts['High Risk']}",
            f"- **Medium Risk:** {risk_counts['Medium Risk']}",
            f"- **Low Risk:** {risk_counts['Low Risk']}",
            f"- **Safe:** {risk_counts['Safe']}\n",
            "## Skill Analysis\n"
        ]

        if total == 0:
            msg = "未发现任何 Skill。" if self.lang == "zh" else "No skills detected."
            lines.append(f"*{msg}*\n")

        for skill in skills:
            lines.extend(self._format_skill_section(skill))
            
        with open(report_path, "w", encoding="utf-8") as f:
            f.write("\n".join(lines))
            
        return report_path

    def _format_skill_section(self, skill: Dict[str, Any]) -> List[str]:
        name = skill.get("name", "Unknown")
        score = skill.get("risk_score", 0)
        level = skill.get("risk_level", "Safe")
        
        lines = [
            f"### Skill: {name}",
            f"**Risk Score:** {score}",
            f"**Risk Level:** {level}\n",
            "#### Detected Issues\n"
        ]
        
        issues = skill.get("issues", [])
        if not issues:
            msg = "未发现安全问题" if self.lang == "zh" else "No security issues detected"
            lines.append(f"- {msg}\n")
        else:
            for issue in issues:
                desc = issue.get("desc_zh" if self.lang == "zh" else "desc_en")
                file_name = os.path.basename(issue.get("file", "unknown"))
                line_no = issue.get("line", 0)
                snippet = issue.get("snippet", "")
                
                lines.append(f"- **[{issue['risk_level']}] {issue['category']}**: {desc}")
                lines.append(f"  - Location: `{file_name}:{line_no}`")
                lines.append(f"  - Snippet: `{snippet}`")
            lines.append("")

            # 为报告补充推断的攻击场景和建议
            scenarios = self._infer_attack_scenarios(issues)
            lines.append("#### Possible Attack Scenarios\n")
            for sc in scenarios:
                lines.append(f"- {sc}")
            lines.append("")

            recommendations = self._infer_recommendations(issues)
            lines.append("#### Security Recommendations\n")
            for rec in recommendations:
                lines.append(f"- {rec}")
            lines.append("\n---\n")
            
        return lines

    def _infer_attack_scenarios(self, issues: List[Dict[str, Any]]) -> List[str]:
        scenarios = set()
        for i in issues:
            cat = i.get("category")
            if cat == "Secret":
                scenarios.add("Data exfiltration / Unauthorized access via stolen credentials" if self.lang == "en" else "数据泄露 / 利用被盗凭证进行越权访问 (Data Exfiltration)")
            elif cat == "Network":
                scenarios.add("Unapproved external communication / Command and Control (C2)" if self.lang == "en" else "未经授权的外部网络通信 / C2 控制")
            elif cat == "Dynamic Execution" or cat == "Shell Execution":
                scenarios.add("Remote command execution (RCE) / Arbitrary code execution" if self.lang == "en" else "远程命令执行 (RCE) / 任意代码执行")
            elif cat == "File System":
                scenarios.add("System compromise via config alteration or secrets theft" if self.lang == "en" else "通过修改配置文件或窃取系统凭证攻陷系统")
            elif cat == "Prompt Security":
                scenarios.add("AI behavior manipulation / Jailbreak" if self.lang == "en" else "AI行为操纵 (AI Behavior manipulation) / 越狱破解 (Jailbreak)")
            elif cat == "Backdoor":
                scenarios.add("Persistent hidden backdoor logic" if self.lang == "en" else "隐蔽的持久化后门访问 (Hidden Backdoor)")
        return list(scenarios) if scenarios else ["Unknown impacts"]

    def _infer_recommendations(self, issues: List[Dict[str, Any]]) -> List[str]:
        recommendations = set()
        for i in issues:
            cat = i.get("category")
            if cat == "Secret":
                recommendations.add("Remove hardcoded secrets from source code and use environment variables." if self.lang == "en" else "去除源码中硬编码的密钥，转用环境变量存储配置 (Remove secrets)")
            elif cat == "Network":
                recommendations.add("Restrict network calls and audit endpoint destinations." if self.lang == "en" else "限制外部网络调用，审查通信目标的合法性 (Restrict network calls)")
            elif cat == "Dynamic Execution" or cat == "Shell Execution":
                recommendations.add("Avoid eval/exec and direct shell commands. Use safer libraries." if self.lang == "en" else "避免使用 eval/exec 和底层系统命令，使用更安全的标准库替代操作 (Audit execution logic)")
            elif cat == "File System":
                recommendations.add("Restrict file system access only to required directories." if self.lang == "en" else "对关键敏感目录设置严格的文件系统访问限制 (Restrict FS access)")
            elif cat == "Prompt Security":
                recommendations.add("Implement robust prompt filtering and output validation." if self.lang == "en" else "实施强有力的 Prompt 过滤与输出验证以防止注入 (Prompt Filtering)")
            elif cat == "Backdoor":
                recommendations.add("Review code for hidden payloads and obfuscation." if self.lang == "en" else "人工审查识别出的加密混淆或可疑的隐藏触发逻辑 (Code Review)")
        return list(recommendations) if recommendations else ["Review code logic manually."]
