import os
import ast
from typing import List, Dict, Any
from skill_auditor.core.rules import get_rules, CRITICAL, HIGH, MEDIUM, LOW

class SkillAnalyzer:
    def __init__(self):
        self.rules = get_rules()

    def analyze(self, skill_info: Dict[str, Any]) -> Dict[str, Any]:
        """
        对已发现的 Skill 执行包含静态代码分析、规则匹配与行为模式识别的安全扫描。
        """
        issues = []
        source_files = skill_info.get("source_files", [])
        
        for filepath in source_files:
            # 尝试读取文件内容
            try:
                with open(filepath, 'r', encoding='utf-8') as f:
                    lines = f.readlines()
            except Exception:
                continue
            
            # 使用 Regex 规则进行正则模式扫描
            for line_no, line in enumerate(lines, 1):
                for rule in self.rules:
                    if rule.pattern.search(line):
                        issues.append({
                            "rule_id": rule.id,
                            "category": rule.category,
                            "risk_level": rule.risk_level,
                            "desc_zh": rule.desc_zh,
                            "desc_en": rule.desc_en,
                            "file": filepath,
                            "line": line_no,
                            "snippet": line.strip()[:100]  # 限制截断长度防止报告过大
                        })
            
            # 专门针对 Python 文件的 AST 高级分析
            if filepath.endswith('.py'):
                try:
                    tree = ast.parse("".join(lines))
                    ast_issues = self._analyze_python_ast(tree, filepath)
                    issues.extend(ast_issues)
                except SyntaxError:
                    pass

        skill_info["issues"] = issues
        return skill_info

    def _analyze_python_ast(self, tree: ast.AST, filepath: str) -> List[Dict[str, Any]]:
        """
        利用 AST 结构额外检测隐藏后门与命令执行等复杂逻辑，
        补充正则无法完美覆盖的场景。
        """
        issues = []
        for node in ast.walk(tree):
            # 检查 eval, exec, __import__ 的调用
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
                if node.func.id in ['eval', 'exec', '__import__']:
                    issues.append({
                        "rule_id": "AST-DYN-01",
                        "category": "Dynamic Execution",
                        "risk_level": CRITICAL,
                        "desc_zh": f"AST扫描分析: 发现危险函数 {node.func.id}() 调用",
                        "desc_en": f"AST Analysis: Dangerous function {node.func.id}() invocation detected",
                        "file": filepath,
                        "line": getattr(node, 'lineno', 0),
                        "snippet": f"{node.func.id}(...)"
                    })
        return issues
