# app/board/board.py
"""
黑板读写接口

本模块**不持有状态**——所有函数都是对 state 里 facts/intents 列表的纯操作。
这样天然契合 LangGraph 的 reducer 模式（节点返回增量，框架负责合并）。

核心函数:

- make_fact / make_intent: 工厂，负责构造 id
- render_known_facts:     **Phase 2 迁移的关键**。把 facts 投影成字符串，
                          开启黑板时替代旧的 known_facts 字段；未开启时回退读旧字段。
                          这个设计保证「任一时刻只有一个真相源」，且可逐字节回退。
- format_*_for_prompt:    注入 LLM 用的紧凑文本
"""

import hashlib
import json
from typing import Any, Dict, List, Optional

from board.models import Fact, Intent, FactKind, IntentStatus, default_value_score

# 注入 prompt 时的条数上限（防止 facts 累积后撑爆上下文）
PROMPT_FACTS_TOP_N = 40
PROMPT_INTENTS_TOP_N = 10


# =============================================================================
# 工厂函数
# =============================================================================

def make_fact_id(kind: str, key: str) -> str:
    """
    构造语义化的 Fact id

    语义化便于人读日志，也天然幂等：同一目标同一特征重复发现会得到同一 id，
    由 upsert_facts_reducer 自动合并，不会产生重复项。

    Args:
        kind: FactKind 之一
        key: 该 kind 下的唯一键，如 'php:7.4'、'admin:admin123'、'/search'
    """
    return f"{kind}:{key}"


def make_fact(kind: str, key: str, description: str, **kwargs) -> Dict[str, Any]:
    """构造一个 Fact dict（直接可放进 state）"""
    fact = Fact(
        id=make_fact_id(kind, key),
        kind=kind,
        description=description,
        **kwargs,
    )
    return fact.to_dict()


def make_intent_id(sources: List[str], description: str) -> str:
    """
    构造幂等的 Intent id

    用「来源 + 描述」的哈希而非自增计数器：同一探索方向被重复提出时会得到同一 id，
    reducer 自动合并，避免同一条意图在图上堆积多份。
    """
    raw = f"{sorted(sources or [])}|{description.strip().lower()}"
    return "i_" + hashlib.md5(raw.encode("utf-8")).hexdigest()[:10]


def make_intent(description: str, sources: Optional[List[str]] = None, **kwargs) -> Dict[str, Any]:
    """构造一个 Intent dict（直接可放进 state）"""
    sources = sources or []
    intent = Intent(
        id=make_intent_id(sources, description),
        description=description,
        sources=sources,
        **kwargs,
    )
    return intent.to_dict()


# =============================================================================
# 查询辅助
# =============================================================================

def get_facts(state: Dict[str, Any]) -> List[Dict]:
    """安全取 facts 列表"""
    facts = state.get("facts") or []
    return [f for f in facts if isinstance(f, dict)]


def get_intents(state: Dict[str, Any]) -> List[Dict]:
    """安全取 intents 列表"""
    intents = state.get("intents") or []
    return [i for i in intents if isinstance(i, dict)]


def get_facts_by_kind(state: Dict[str, Any], *kinds: str) -> List[Dict]:
    """按 kind 过滤 facts"""
    wanted = set(kinds)
    return [f for f in get_facts(state) if f.get("kind") in wanted]


def get_pending_intents(state: Dict[str, Any]) -> List[Dict]:
    """取待认领的 intents（按优先级降序）"""
    pending = [i for i in get_intents(state) if i.get("status") == IntentStatus.PENDING]
    pending.sort(key=lambda i: i.get("priority", 0.0), reverse=True)
    return pending


def count_open_intents(state: Dict[str, Any]) -> int:
    """未终结的 intent 数量（pending + in_progress）"""
    return sum(
        1 for i in get_intents(state)
        if i.get("status") in (IntentStatus.PENDING, IntentStatus.IN_PROGRESS)
    )


def has_deadend(state: Dict[str, Any], keyword: str) -> bool:
    """检查某个方向是否已被证伪（attacker 可用于跳过重复尝试）"""
    if not keyword:
        return False
    kw = keyword.lower()
    return any(
        kw in (f.get("description") or "").lower()
        for f in get_facts_by_kind(state, FactKind.DEADEND)
    )


# =============================================================================
# 投影 / 渲染
# =============================================================================

def render_known_facts(state: Dict[str, Any]) -> str:
    """
    **Phase 2 迁移的关键函数**

    把黑板 facts 投影成旧的 known_facts 字符串格式。规则:

    - facts 非空 → 按价值分取 top-N 渲染
    - facts 为空 → **回退读旧 known_facts 字段**（黑板关闭时即此分支）

    因此调用方（attacker/verifier 的 prompt 注入点）只需从
        state.get("known_facts", "")
    改成
        render_known_facts(state)
    即可完成迁移，且 prompt 构建函数一行都不用动（参数名仍叫 known_facts），
    黑板关闭时逐字节等于改造前的行为。
    """
    facts = get_facts(state)
    if not facts:
        return state.get("known_facts", "") or ""

    top = sorted(facts, key=lambda f: f.get("value_score", 0.0), reverse=True)[:PROMPT_FACTS_TOP_N]

    lines = []
    for f in top:
        kind = f.get("kind", "?")
        desc = (f.get("description") or "").strip()
        conf = f.get("confidence", 1.0)
        # 低置信度标注出来，避免 LLM 当既成事实
        mark = "" if conf >= 0.8 else f" (置信度{conf:.1f})"
        lines.append(f"- [{kind}] {desc}{mark}")
    return "\n".join(lines)


def format_intents_for_prompt(state: Dict[str, Any]) -> str:
    """
    把未完成的 intents 渲染成紧凑文本，供 attacker 选择方向

    只输出 description 和关联技能名，不输出内部 id（对 LLM 无意义）。
    """
    open_intents = [
        i for i in get_intents(state)
        if i.get("status") in (IntentStatus.PENDING, IntentStatus.IN_PROGRESS)
    ]
    if not open_intents:
        return ""
    open_intents.sort(key=lambda i: i.get("priority", 0.0), reverse=True)

    lines = []
    for i in open_intents[:PROMPT_INTENTS_TOP_N]:
        desc = (i.get("description") or "").strip()
        skill = i.get("skill")
        suffix = f"  [技能: {skill}]" if skill else ""
        lines.append(f"- {desc}{suffix}")
    return "\n".join(lines)


def render_skills_for_prompt(skills: Optional[List[Dict]]) -> str:
    """
    把匹配到的技能渲染成紧凑文本

    ⚠️ 只输出 name + description + tools（≤300 字），**Markdown 正文不注入**。
    原因: 技能正文含具体步骤，整篇塞进 prompt 会盖掉 attacker_prompt 里
    "优先 recommended_tools"的强约束，并可能诱导 LLM 绕过 failed_payloads 黑名单
    重复发送已知失败的 payload。正文供人阅读和映射到工具参数。
    """
    if not skills:
        return ""
    lines = []
    for sk in skills[:5]:
        name = sk.get("name", "")
        desc = (sk.get("description") or "")[:120]
        tools = ", ".join(sk.get("tools") or [])
        line = f"- {name}: {desc}"
        if tools:
            line += f" (可用工具: {tools})"
        lines.append(line[:300])
    return "\n".join(lines)


def board_summary(state: Dict[str, Any]) -> str:
    """
    黑板统计摘要（供日志和 board_node 使用）

    这是派生视图，每轮全量重算，在 state 里不带 reducer（LastValue 语义正好）。
    """
    facts = get_facts(state)
    by_kind: Dict[str, int] = {}
    for f in facts:
        k = f.get("kind", "?")
        by_kind[k] = by_kind.get(k, 0) + 1

    intents = get_intents(state)
    by_status: Dict[str, int] = {}
    for i in intents:
        s = i.get("status", "?")
        by_status[s] = by_status.get(s, 0) + 1

    parts = [f"facts={len(facts)}"]
    if by_kind:
        parts.append("(" + ", ".join(f"{k}:{v}" for k, v in sorted(by_kind.items())) + ")")
    parts.append(f"intents={len(intents)}")
    if by_status:
        parts.append("(" + ", ".join(f"{k}:{v}" for k, v in sorted(by_status.items())) + ")")
    return " ".join(parts)


def dump_board(state: Dict[str, Any]) -> Dict[str, Any]:
    """导出黑板全量（供 Web API / 调试）"""
    return {
        "facts": get_facts(state),
        "intents": get_intents(state),
        "summary": board_summary(state),
    }
