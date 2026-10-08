# app/board/__init__.py
"""
黑板（Blackboard）—— 借鉴 Cairn 的事实-意图图，并做结构化增强

本包提供三个原语与配套的读写/分析能力:
- Fact:   已确认的客观发现（结构化，可查询、可匹配技能）
- Intent: 已声明未执行的探索方向（带优先级与技能引用）
- BoardHint: 人工注入的判断

⚠️ 本文件**必须存在**。LangGraph 的 checkpoint 反序列化通过
`importlib.import_module("board.models")` 定位类型，缺少 __init__.py 会导致反序列化失败。
"""

from board.models import (
    Fact,
    Intent,
    BoardHint,
    FactKind,
    IntentStatus,
    INTENT_STATUS_ORDER,
    HIGH_VALUE_KINDS,
    default_value_score,
)
from board.reducers import (
    upsert_facts_reducer,
    upsert_intents_reducer,
    MAX_FACTS,
    MAX_INTENTS,
)
from board.board import (
    make_fact,
    make_fact_id,
    make_intent,
    make_intent_id,
    get_facts,
    get_intents,
    get_facts_by_kind,
    get_pending_intents,
    count_open_intents,
    has_deadend,
    render_known_facts,
    format_intents_for_prompt,
    render_skills_for_prompt,
    board_summary,
    dump_board,
)
from board.extractors import (
    facts_from_verifier,
    facts_from_candidates,
    facts_from_credentials,
    facts_from_deadend,
)
from board.analyzer import (
    analyze,
    score_intents,
    find_uncovered_facts,
    has_uncovered_hub,
    rank_facts_by_centrality,
    suggest_intents,
    NETWORKX_AVAILABLE,
)

__all__ = [
    # models
    "Fact", "Intent", "BoardHint",
    "FactKind", "IntentStatus", "INTENT_STATUS_ORDER", "HIGH_VALUE_KINDS",
    "default_value_score",
    # reducers
    "upsert_facts_reducer", "upsert_intents_reducer", "MAX_FACTS", "MAX_INTENTS",
    # board api
    "make_fact", "make_fact_id", "make_intent", "make_intent_id",
    "get_facts", "get_intents", "get_facts_by_kind", "get_pending_intents",
    "count_open_intents", "has_deadend",
    "render_known_facts", "format_intents_for_prompt", "render_skills_for_prompt",
    "board_summary", "dump_board",
    # extractors
    "facts_from_verifier", "facts_from_candidates",
    "facts_from_credentials", "facts_from_deadend",
    # analyzer
    "analyze", "score_intents", "find_uncovered_facts", "has_uncovered_hub",
    "rank_facts_by_centrality", "suggest_intents", "NETWORKX_AVAILABLE",
]
