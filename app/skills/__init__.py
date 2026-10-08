# app/skills/__init__.py
"""
技能库 —— 可复用的攻击手法单元

技能 = 一种漏洞的完整打法：触发条件 + 适用工具 + 步骤 + 验证 + 失败信号，
以 YAML frontmatter + Markdown 存储在 {项目根}/skills/**/*.md。

与「工具」的区别:
- 工具（tools/）是**能力**——能跑什么命令
- 技能（skills/）是**打法**——什么条件下、用哪些工具、按什么步骤打

⚠️ 命名说明: 本 Python 包（app/skills/）与技能文件目录（{项目根}/skills/）同名但不同物。
   前者是代码，后者是数据。由于本包有 __init__.py（常规包），而技能目录没有，
   按 PEP 420，路径扫描时会优先采用常规包，因此 import skills 不会歧义。

用法:
    from skills import SkillRegistry, match_skills, scenes_to_facts

    SkillRegistry.ensure_loaded()
    matched = match_skills(scenes=scene_out, facts=state["facts"], available_tools=tool_names)
"""

from skills.loader import (
    load_skills,
    reload_skills,
    parse_skill_file,
    parse_skill_text,
    SkillFormatError,
    DEFAULT_SKILLS_DIR,
)
from skills.registry import SkillRegistry
from skills.normalizer import scenes_to_facts
from skills.matcher import match_skills, match_for_state

__all__ = [
    # loader
    "load_skills", "reload_skills", "parse_skill_file", "parse_skill_text",
    "SkillFormatError", "DEFAULT_SKILLS_DIR",
    # registry
    "SkillRegistry",
    # normalizer
    "scenes_to_facts",
    # matcher
    "match_skills", "match_for_state",
]
