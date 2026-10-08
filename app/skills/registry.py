# app/skills/registry.py
"""
技能注册中心

对齐 app/tool_framework.py:671 的 ToolRegistry 模式（类方法 + 类级缓存 + 懒加载），
保持项目内两套「能力注册」机制风格一致。

用法:
    from skills import SkillRegistry

    SkillRegistry.ensure_loaded()
    SkillRegistry.all()             # 全部技能
    SkillRegistry.get("sqlmap")     # 按名取
    SkillRegistry.reload()          # 重新扫描（技能文件改动后）
"""

import logging
from pathlib import Path
from typing import Any, Dict, List, Optional

from skills.loader import load_skills, DEFAULT_SKILLS_DIR

logger = logging.getLogger(__name__)


class SkillRegistry:
    """技能注册中心（单例，类级缓存）"""

    _skills: Dict[str, Dict[str, Any]] = {}
    _loaded: bool = False
    _skills_dir: Optional[Path] = None

    # -------------------------------------------------------------------------
    # 加载
    # -------------------------------------------------------------------------

    @classmethod
    def ensure_loaded(cls, skills_dir: Optional[Path] = None) -> None:
        """首次访问时懒加载（避免 import 时就做磁盘 IO）"""
        if cls._loaded and skills_dir is None:
            return
        cls.reload(skills_dir)

    @classmethod
    def reload(cls, skills_dir: Optional[Path] = None) -> int:
        """
        重新扫描技能目录

        Returns:
            加载到的技能数量
        """
        if skills_dir is not None:
            cls._skills_dir = Path(skills_dir)
        skills = load_skills(cls._skills_dir or DEFAULT_SKILLS_DIR)
        cls._skills = {s["name"]: s for s in skills}
        cls._loaded = True
        return len(cls._skills)

    # -------------------------------------------------------------------------
    # 查询
    # -------------------------------------------------------------------------

    @classmethod
    def all(cls) -> List[Dict[str, Any]]:
        """全部技能"""
        cls.ensure_loaded()
        return list(cls._skills.values())

    @classmethod
    def get(cls, name: str) -> Optional[Dict[str, Any]]:
        """按名取技能（找不到返回 None）"""
        cls.ensure_loaded()
        return cls._skills.get(name)

    @classmethod
    def exists(cls, name: str) -> bool:
        cls.ensure_loaded()
        return name in cls._skills

    @classmethod
    def names(cls) -> List[str]:
        cls.ensure_loaded()
        return sorted(cls._skills.keys())

    @classmethod
    def by_scene(cls, scene: str) -> List[Dict[str, Any]]:
        """按场景过滤（triggers.scene）"""
        cls.ensure_loaded()
        if not scene:
            return cls.all()
        target = scene.strip().lower()
        return [
            s for s in cls._skills.values()
            if str((s.get("triggers") or {}).get("scene", "")).strip().lower() == target
        ]

    @classmethod
    def by_fact_kind(cls, kind: str) -> List[Dict[str, Any]]:
        """按 fact kind 过滤（triggers.fact_kinds）"""
        cls.ensure_loaded()
        return [
            s for s in cls._skills.values()
            if kind in ((s.get("triggers") or {}).get("fact_kinds") or [])
        ]

    @classmethod
    def count(cls) -> int:
        cls.ensure_loaded()
        return len(cls._skills)

    @classmethod
    def describe_all(cls) -> str:
        """渲染技能清单（供 prompt 注入，只含要点不含正文）"""
        cls.ensure_loaded()
        if not cls._skills:
            return ""
        lines = []
        for name in cls.names():
            skill = cls._skills[name]
            desc = (skill.get("description") or "")[:100]
            tools = ", ".join(skill.get("tools") or [])
            line = f"- {name}: {desc}"
            if tools:
                line += f" (工具: {tools})"
            lines.append(line)
        return "\n".join(lines)
