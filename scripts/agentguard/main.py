import os
import argparse

from .core.scanner import SkillScanner
from .core.analyzer import SkillAnalyzer
from .core.scorer import RiskScorer
from .core.reporter import MarkdownReporter


def safe_console_text(value):
    """移除目标元数据中的终端控制字符。"""
    return "".join(char for char in str(value)
                   if char in "\t\n" or ord(char) >= 0xA0 or 0x20 <= ord(char) < 0x7F)

def detect_language(text: str) -> str:
    """
    一个简单的语言检测：
    如果输入参数中包含中文字符，则认为是中文 (zh)
    否则默认英文 (en)
    由于本任务强制用户输入为中文则输出中文，所以可以通过此法判断或者直接从参数接收。
    """
    for char in text:
        if '\u4e00' <= char <= '\u9fff':
            return 'zh'
    return 'en'

def main():
    parser = argparse.ArgumentParser(description="AgentGuard Security Auditor")
    parser.add_argument("target_dir", nargs='?', default=".", help="Directory to scan for AI skills")
    parser.add_argument("--lang", choices=["zh", "en", "auto"], default="auto", help="Report language")
    parser.add_argument("--include-installed", action="store_true",
                        help="同时扫描本机常见的全局 Skill 目录")
    parser.add_argument("--output-dir", default=".", help="报告输出目录")
    
    args = parser.parse_args()
    target_dir = os.path.abspath(args.target_dir)

    print("[*] AgentGuard 安全审计启动")
    print(f"[*] 正在扫描目录: {target_dir}")

    # 1. Scanner 发现 Skill / 插件
    scanner = SkillScanner(target_dir, include_installed=args.include_installed)
    skills = scanner.discover_skills()
    print(f"[+] 发现技能 (Skills) 数量: {len(skills)}")

    # 如果自动判定语言（由输入目录名等参数大致判断，或者假设以全局中文为优先）
    report_lang = args.lang
    if report_lang == "auto":
        report_lang = "zh"  # 默认采用中文报告，满足用户中文交互需求

    # 2. Analyzer 进行核心代码安全分析
    analyzer = SkillAnalyzer()
    
    # 3. Scorer 计算风险分数
    scorer = RiskScorer()

    for skill in skills:
        print(f"[*] 正在分析: {safe_console_text(skill['name'])} "
              f"({safe_console_text(skill['path'])})")
        
        # 静态分析提取漏洞
        skill = analyzer.analyze(skill)
        
        # 计算风险分数与等级
        skill = scorer.calculate_risk(skill)

    # 4. Reporter 汇总并生成 Markdown 审计报告
    reporter = MarkdownReporter(lang=report_lang)
    report_path = reporter.generate_report(skills, os.path.abspath(args.output_dir))

    print(f"[+] 安全扫描完成！")
    print(f"[+] 详细报告已生成: {report_path}")

if __name__ == "__main__":
    main()
