# app/skills/matcher.py
"""
技能匹配

**规则优先**：技能规模是几十条，规则匹配比向量检索更准、可解释、零依赖、毫秒级。
向量检索（复用 rag_builder）仅作为「规则都匹配不上」时的可选兜底，且默认关闭
—— 因为 rag_builder 目前依赖缺失（python-frontmatter / chromadb 未安装）跑不起来。

打分构成（权重之和为 1.0）:
    scene(技术栈)  0.40  ← 最强信号：技术栈不对，手法必然失效
    fact_kinds     0.30  ← 黑板上有没有该手法需要的事实类型
    keywords       0.20  ← 描述/路径里的关键词
    tool_stack     0.10  ← 声明的工具可用性（本身也是硬门槛）
"""

import logging
from typing import Any, Dict, List, Optional, Set, Tuple

from skills.registry import SkillRegistry

logger = logging.getLogger(__name__)

# 权重
W_SCENE = 0.40
W_FACT_KINDS = 0.30
W_KEYWORDS = 0.20
W_TOOLS = 0.10

# 低于此分不返回
DEFAULT_MIN_SCORE = 0.25


def _norm(value: Any) -> str:
    return str(value or "").strip().lower()


def _fuzzy_hit(needle: str, haystack_text: str) -> bool:
    """
    模糊包含匹配

    'spring' 命中 'spring/5.3.0'；'tomcat' 命中 'apache tomcat/9.0.30'。
    双向包含，避免版本号/前缀导致的漏配。
    """
    n = _norm(needle)
    if not n:
        return False
    h = _norm(haystack_text)
    return n in h or h in n


def _scene_text(scenes: Dict[str, Any]) -> str:
    """把 SceneDetector 输出压成一段可匹配的文本"""
    if not isinstance(scenes, dict):
        return ""
    parts: List[str] = []
    for fw in scenes.get("framework") or []:
        if isinstance(fw, dict):
            parts.append(f"{fw.get('name', '')} {fw.get('version', '')}")
        else:
            parts.append(str(fw))
    svc = scenes.get("service_info")
    if isinstance(svc, dict):
        parts.append(str(svc.get("server", "")))
        parts.append(str(svc.get("x_powered_by", "")))
    for p in scenes.get("sensitive_paths") or []:
        parts.append(str(p))
    for dp in scenes.get("data_patterns") or []:
        if isinstance(dp, dict):
            parts.append(f"{dp.get('type', '')} {dp.get('hint', '')}")
    return " | ".join(x for x in parts if x.strip())


def _fact_kind_set(facts: Optional[List[Dict]]) -> Set[str]:
    return {
        str(f.get("kind", "")).lower()
        for f in (facts or [])
        if isinstance(f, dict) and f.get("kind")
    }


def match_skills(
    *,
    scenes: Optional[Dict[str, Any]] = None,
    facts: Optional[List[Dict]] = None,
    available_tools: Optional[Set[str]] = None,
    extra_text: str = "",
    top_k: int = 3,
    min_score: float = DEFAULT_MIN_SCORE,
) -> List[Tuple[Dict[str, Any], float]]:
    """
    按规则匹配技能

    Args:
        scenes: SceneDetector.detect() 的输出
        facts: 当前黑板的 facts（用于 fact_kinds 匹配）
        available_tools: 可用工具名集合（**硬门槛**）。传 None 表示不检查。
        extra_text: 额外参与关键词匹配的文本（如 URL、页面标题）
        top_k: 返回条数
        min_score: 最低分

    Returns:
        [(skill, score), ...] 按分数降序
    """
    skills = SkillRegistry.all()
    if not skills:
        return []

    scene_text = _scene_text(scenes or {})
    haystack = f"{scene_text} {extra_text}".strip()
    have_kinds = _fact_kind_set(facts)
    tools_lower = {_norm(t) for t in (available_tools or set())} if available_tools else None

    results: List[Tuple[Dict[str, Any], float]] = []

    for skill in skills:
        triggers = skill.get("triggers") or {}

        # ---- 硬门槛: 声明的工具一个都没有 -> 淘汰 ----
        skill_tools = [_norm(t) for t in (skill.get("tools") or [])]
        if tools_lower is not None and skill_tools:
            if not (set(skill_tools) & tools_lower):
                continue

        score = 0.0

        # ---- scene: 技术栈（最强信号）----
        scenes_declared = triggers.get("tech_stack") or []
        if scenes_declared:
            hit = sum(1 for s in scenes_declared if _fuzzy_hit(s, haystack))
            score += W_SCENE * (hit / len(scenes_declared))

        # ---- fact_kinds ----
        kinds_declared = [str(k).lower() for k in (triggers.get("fact_kinds") or [])]
        if kinds_declared:
            hit = len(have_kinds & set(kinds_declared))
            score += W_FACT_KINDS * (hit / len(kinds_declared))

        # ---- keywords ----
        kws = triggers.get("keywords") or []
        if kws:
            hit = sum(1 for k in kws if _norm(k) in _norm(haystack))
            score += W_KEYWORDS * (hit / len(kws))

        # ---- tools 可用性加成 ----
        if skill_tools and tools_lower is not None:
            if set(skill_tools) <= tools_lower:
                score += W_TOOLS
            else:
                score += W_TOOLS * 0.5

        if score >= min_score:
            results.append((skill, round(score, 4)))

    results.sort(key=lambda kv: kv[1], reverse=True)
    return results[:top_k]


def match_for_state(
    state: Dict[str, Any],
    *,
    available_tools: Optional[Set[str]] = None,
    top_k: int = 3,
) -> List[Dict[str, Any]]:
    """
    便捷入口: 直接按 CTFState 匹配技能

    从 state 里取 page_features（recon 产出）与 facts。
    返回技能 dict 列表，每个额外带上 `_score` 字段便于调试。
    """
    if not isinstance(state, dict):
        return []

    page_features = state.get("page_features") or {}
    scenes = page_features if isinstance(page_features, dict) else {}
    facts = state.get("facts") or []
    extra = str(state.get("current_url", "") or "")

    matched = match_skills(
        scenes=scenes,
        facts=facts,
        available_tools=available_tools,
        extra_text=extra,
        top_k=top_k,
    )

    out = []
    for skill, score in matched:
        item = dict(skill)
        item["_score"] = score
        # 正文不注入 prompt，这里显式剔除以免误用
        item.pop("body", None)
        out.append(item)
    return out
