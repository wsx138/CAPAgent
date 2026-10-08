# app/skills/loader.py
"""
技能文件加载器

扫描 skills/**/*.md，解析 YAML frontmatter，产出技能 dict。

⚠️ **不依赖 python-frontmatter**。已核实 rag_builder/vector_store.py:7 依赖该包，
   但它既未写进 requirements.txt、本机也未安装，导致 RAG 建库脚本至今跑不起来。
   这里用 pyyaml（已在依赖中）自己切 frontmatter，约 10 行，零额外依赖。

技能文件格式:
    ---
    name: php-filter-chain
    description: PHP filter chain 盲注（无回显场景）
    triggers:
      tech_stack: [php]
      fact_kinds: [vuln]
      keywords: [文件包含, file_include]
      scene: web
    tools: [php-filter-chain, requests]
    cost: medium
    ---
    ## 适用条件
    ...

单文件解析失败只记录警告并跳过，不影响其余技能加载。
"""

import logging
import re
from pathlib import Path
from typing import Any, Dict, List, Optional

import yaml

logger = logging.getLogger(__name__)

# 项目根目录: app/skills/loader.py -> app/skills -> app -> 项目根
BASE_DIR = Path(__file__).resolve().parent.parent.parent
DEFAULT_SKILLS_DIR = BASE_DIR / "skills"

# frontmatter 匹配: 文件必须以 --- 开头，第二个 --- 之前是 YAML
_FRONTMATTER_RE = re.compile(r"^---\s*\n(.*?)\n---\s*\n?(.*)$", re.DOTALL)

# 合法的 cost 取值
_VALID_COSTS = frozenset({"low", "medium", "high"})


class SkillFormatError(ValueError):
    """技能文件格式错误"""


def parse_skill_text(text: str, *, source: str = "<string>") -> Dict[str, Any]:
    """
    解析单个技能文件的文本内容

    Args:
        text: 文件全文
        source: 来源标识（用于报错信息）

    Returns:
        技能 dict: {name, description, triggers, tools, cost, body, path}

    Raises:
        SkillFormatError: 缺少 frontmatter 或 YAML 非法
    """
    m = _FRONTMATTER_RE.match(text.lstrip())
    if not m:
        raise SkillFormatError(f"{source}: 缺少 YAML frontmatter（文件需以 --- 开头）")

    try:
        meta = yaml.safe_load(m.group(1)) or {}
    except yaml.YAMLError as e:
        raise SkillFormatError(f"{source}: frontmatter YAML 非法: {e}") from e

    if not isinstance(meta, dict):
        raise SkillFormatError(f"{source}: frontmatter 必须是键值对")

    name = str(meta.get("name") or "").strip()
    if not name:
        raise SkillFormatError(f"{source}: 缺少必填字段 name")

    triggers = meta.get("triggers") or {}
    if not isinstance(triggers, dict):
        triggers = {}

    tools = meta.get("tools") or []
    if isinstance(tools, str):
        tools = [tools]

    cost = str(meta.get("cost", "medium")).strip().lower()
    if cost not in _VALID_COSTS:
        cost = "medium"

    return {
        "name": name,
        "description": str(meta.get("description", "") or "").strip(),
        "triggers": triggers,
        "tools": [str(t).strip() for t in tools if str(t).strip()],
        "cost": cost,
        "body": m.group(2),
        "path": source,
    }


def parse_skill_file(path: Path) -> Dict[str, Any]:
    """解析单个技能文件"""
    text = path.read_text(encoding="utf-8", errors="replace")
    return parse_skill_text(text, source=str(path))


def load_skills(skills_dir: Optional[Path] = None) -> List[Dict[str, Any]]:
    """
    扫描目录下所有技能文件

    Args:
        skills_dir: 技能目录，默认 {项目根}/skills

    Returns:
        技能 dict 列表（解析失败的已跳过）
    """
    root = Path(skills_dir) if skills_dir else DEFAULT_SKILLS_DIR
    if not root.exists():
        logger.info("[Skills] 技能目录不存在，跳过加载: %s", root)
        return []

    skills: List[Dict[str, Any]] = []
    seen_names: Dict[str, str] = {}

    for path in sorted(root.rglob("*.md")):
        try:
            skill = parse_skill_file(path)
        except SkillFormatError as e:
            logger.warning("[Skills] 跳过无效技能文件: %s", e)
            continue
        except Exception as e:  # 读文件失败等
            logger.warning("[Skills] 读取失败 %s: %s", path, e)
            continue

        name = skill["name"]
        if name in seen_names:
            logger.warning(
                "[Skills] 技能名重复，后者被忽略: %s (%s 与 %s 冲突)",
                name, path, seen_names[name],
            )
            continue
        seen_names[name] = str(path)
        skills.append(skill)

    logger.info("[Skills] 已加载 %d 个技能 (来自 %s)", len(skills), root)
    return skills


def reload_skills(skills_dir: Optional[Path] = None) -> List[Dict[str, Any]]:
    """重新加载技能（供 SkillRegistry.reload 使用）"""
    return load_skills(skills_dir)
