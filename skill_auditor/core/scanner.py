import os
import json
from typing import Dict, List, Any

class SkillScanner:
    def __init__(self, root_dir: str):
        self.root_dir = os.path.abspath(root_dir)
        self.skills = []

    def discover_skills(self) -> List[Dict[str, Any]]:
        """
        自动发现当前系统环境（目标路径）下安装的所有 Skill / 插件
        支持扫描:
        - Claude config/MCP
        - Cursor .cursorrules
        - Kiro / OpenClaw 插件形式 (package.json 或 main.py 目录)
        - 独立的 Python/JS 模块包含特征文件
        - 自动侦测 ~/.claude/skills, ~/.openclaw/skills 等全局安装目录
        """
        discovered = []

        # 获取需要扫描的所有基础目录 (目标目录 + 全局内置的特征目录)
        scan_targets = [self.root_dir]
        
        home_dir = os.path.expanduser("~")
        global_skill_paths = [
            os.path.join(home_dir, ".claude", "skills"),
            os.path.join(home_dir, ".openclaw", "skills"),
            os.path.join(home_dir, ".cursor", "rules"), # Cursor Global Rules
            os.path.join(home_dir, ".kiro", "skills")
        ]
        
        for gp in global_skill_paths:
            if os.path.exists(gp) and gp not in scan_targets:
                scan_targets.append(gp)

        for base_dir in scan_targets:
            for root, dirs, files in os.walk(base_dir):
                skill_info = None

                # 1. 识别基于 Node/前端 的 Skill (package.json)
                if 'package.json' in files:
                    skill_info = self._parse_package_json(os.path.join(root, 'package.json'))
                
                # 2. 识别 Python 类型的 Skill (setup.py 或 requirements.txt)
                elif 'setup.py' in files or 'requirements.txt' in files:
                    skill_info = self._parse_python_project(root, files)
                
                # 3. 识别基于 Cursor Rules 的零散 Skill
                elif '.cursorrules' in files or 'cursor.yaml' in files:
                    skill_info = self._parse_cursor_rules(root)
                
                # 4. 识别 Anthropic / Claude Code 的标准 Skill (SKILL.md)
                elif 'SKILL.md' in files or 'skill.md' in (f.lower() for f in files):
                    skill_info = self._parse_anthropic_skill(root, files)
                
                if skill_info:
                    # 附加上入口代码与所有源码文件
                    skill_info['source_files'] = self._collect_source_files(root)
                    discovered.append(skill_info)
                    
                    # 为避免重复扫描子目录对应的同个项目，排除隐藏目录或如 node_modules
                    dirs[:] = [d for d in dirs if not d.startswith('.') and d not in ['node_modules', 'venv', 'env', '__pycache__']]

        # 依据路径对结果去重
        unique_skills = []
        seen_paths = set()
        for s in discovered:
            if s['path'] not in seen_paths:
                seen_paths.add(s['path'])
                unique_skills.append(s)

        self.skills = unique_skills
        return unique_skills

    def _parse_package_json(self, filepath: str) -> Dict[str, Any]:
        info = {
            "name": "Unknown",
            "description": "No description",
            "author": "Unknown",
            "version": "1.0.0",
            "path": os.path.dirname(filepath),
            "dependencies": [],
            "entry": None
        }
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                data = json.load(f)
                info["name"] = data.get("name", "Unknown Node Skill")
                info["description"] = data.get("description", "Node-based AI Skill")
                info["author"] = data.get("author", "Unknown")
                info["version"] = data.get("version", "1.0.0")
                deps = list(data.get("dependencies", {}).keys()) + list(data.get("devDependencies", {}).keys())
                info["dependencies"] = deps
                info["entry"] = data.get("main", "index.js")
        except Exception:
            pass
        return info

    def _parse_python_project(self, root: str, files: List[str]) -> Dict[str, Any]:
        info = {
            "name": os.path.basename(root),
            "description": "Python-based AI Skill",
            "author": "Unknown",
            "version": "1.0.0",
            "path": root,
            "dependencies": [],
            "entry": "main.py" if "main.py" in files else None
        }
        if "requirements.txt" in files:
            req_path = os.path.join(root, "requirements.txt")
            try:
                with open(req_path, 'r', encoding='utf-8') as f:
                    info["dependencies"] = [line.strip() for line in f if line.strip() and not line.startswith('#')]
            except:
                pass
        return info

    def _parse_cursor_rules(self, root: str) -> Dict[str, Any]:
        return {
            "name": f"Cursor-Rule-{os.path.basename(root)}",
            "description": "Cursor Rules Configuration Skill",
            "author": "Current User",
            "version": "local",
            "path": root,
            "dependencies": [],
            "entry": ".cursorrules"
        }

    def _parse_anthropic_skill(self, root: str, files: List[str]) -> Dict[str, Any]:
        info = {
            "name": os.path.basename(root),
            "description": "Anthropic AI Skill",
            "author": "Unknown",
            "version": "1.0.0",
            "path": root,
            "dependencies": [],
            "entry": "SKILL.md" if "SKILL.md" in files else "skill.md"
        }
        
        skill_file = os.path.join(root, info["entry"])
        try:
            import re
            with open(skill_file, 'r', encoding='utf-8') as f:
                content = f.read()
                
            # 尝试提取 YAML Frontmatter
            match = re.search(r'^---\s*(.*?)\s*---', content, re.DOTALL)
            if match:
                frontmatter = match.group(1)
                name_match = re.search(r'name:\s*(.+)', frontmatter)
                desc_match = re.search(r'description:\s*(.+)', frontmatter)
                
                if name_match:
                    info['name'] = name_match.group(1).strip()
                if desc_match:
                    info['description'] = desc_match.group(1).strip()
        except Exception:
            pass
            
        return info

    def _collect_source_files(self, root: str) -> List[str]:
        src_files = []
        EXTENSIONS = ['.py', '.js', '.ts', '.sh', '.bash', '.json', '.yaml', '.yml', '.md', '.txt', '.cursorrules']
        for r, ds, fs in os.walk(root):
            ds[:] = [d for d in ds if d not in ['node_modules', 'venv', 'env', '.git', '__pycache__']]
            for f in fs:
                if any(f.endswith(ext) for ext in EXTENSIONS):
                    src_files.append(os.path.join(r, f))
        return src_files
