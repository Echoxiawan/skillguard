from typing import Dict, Any

RISK_WEIGHTS = {
    "Critical": 40,
    "High": 25,
    "Medium": 10,
    "Low": 5
}

class RiskScorer:
    @staticmethod
    def calculate_risk(skill_info: Dict[str, Any]) -> Dict[str, Any]:
        """
        计算目标的风险评分系统：
        基于发现的漏洞数量、种类与各自的威胁等级。
        """
        score = 0
        issues = skill_info.get("issues", [])
        
        # 为了避免多次相同规则被重复计入全额分数，可以分组去重或降权计算
        # 这里使用简单累加并且封顶100分的方法
        for issue in issues:
            level = issue.get("risk_level", "Low")
            score += RISK_WEIGHTS.get(level, 0)
        
        score = min(100, score)
        skill_info["risk_score"] = score
        
        # 判定最终风险等级
        if score == 0:
            level = "Safe"
        elif score <= 20:
            level = "Low Risk"
        elif score <= 50:
            level = "Medium Risk"
        elif score <= 80:
            level = "High Risk"
        else:
            level = "Critical"
            
        skill_info["risk_level"] = level
        return skill_info
