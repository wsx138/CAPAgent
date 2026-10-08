# app/board/analyzer.py
"""
黑板图分析

在 fact-intent 图上做分析，用于**不依赖 LLM** 地决定「下一步该探索什么」。
这是相比 Cairn 的一处改进——Cairn 的 intent 只能按 created_at 取最新
（dispatcher/scheduler/loop.py:316），这里用图结构算优先级。

图结构: 二部图
    fact ──引用──> intent ──产出──> fact
- 边的方向: fact -> intent 表示「该意图是基于这条事实提出的」
- 枢纽 fact = 被多个 intent 引用 / 自身价值高的 fact（如一个凭据能打开多个入口）

⚠️ networkx 在 requirements.txt 中**未声明**（app/topology/ 也在用它）。
   因此这里做降级处理: 缺 networkx 时退回等价的加权排序，黑板功能不受影响。
"""

from typing import Any, Dict, List, Optional, Tuple

from board.board import get_facts, get_intents, count_open_intents
from board.models import FactKind, IntentStatus

try:
    import networkx as nx
    NETWORKX_AVAILABLE = True
except ImportError:  # pragma: no cover - 环境缺依赖时的降级路径
    nx = None
    NETWORKX_AVAILABLE = False


# 高价值阈值: 超过它的事实视为「枢纽」，值得优先探索
HUB_VALUE_THRESHOLD = 0.75

# 哪些 kind 的事实天然应该触发探索（发现它们却不去用 = 浪费）
_ACTIONABLE_KINDS = frozenset({
    FactKind.CREDENTIAL,
    FactKind.VULN,
    FactKind.ACCESS,
})


# =============================================================================
# 图构建
# =============================================================================

def build_board_graph(facts: List[Dict], intents: List[Dict]):
    """
    构建 fact-intent 二部图（需要 networkx）

    Returns:
        nx.DiGraph，或 None（networkx 不可用时）
    """
    if not NETWORKX_AVAILABLE:
        return None

    g = nx.DiGraph()
    fact_ids = set()
    for f in facts:
        fid = f.get("id")
        if not fid:
            continue
        fact_ids.add(fid)
        g.add_node(fid, kind="fact", value_score=float(f.get("value_score", 0.0) or 0.0))

    for i in intents:
        iid = i.get("id")
        if not iid:
            continue
        g.add_node(iid, kind="intent", priority=float(i.get("priority", 0.0) or 0.0))
        for src in (i.get("sources") or []):
            if src in fact_ids:
                g.add_edge(src, iid)

    return g


def rank_facts_by_centrality(facts: List[Dict], intents: List[Dict]) -> List[Tuple[str, float]]:
    """
    给 fact 排序，用于决定「哪条事实最值得跟进」

    评分 = 0.6 * 图中心性 + 0.4 * 自身价值分
    无 networkx 时退化为纯价值分排序。

    Returns:
        [(fact_id, score), ...] 降序
    """
    if not facts:
        return []

    value_by_id = {
        f["id"]: float(f.get("value_score", 0.0) or 0.0)
        for f in facts if f.get("id")
    }
    if not value_by_id:
        return []

    if not NETWORKX_AVAILABLE:
        ranked = sorted(value_by_id.items(), key=lambda kv: kv[1], reverse=True)
        return [(fid, round(score, 4)) for fid, score in ranked]

    g = build_board_graph(facts, intents)
    if g is None or g.number_of_nodes() == 0:
        return [(fid, round(s, 4)) for fid, s in
                sorted(value_by_id.items(), key=lambda kv: kv[1], reverse=True)]

    fact_nodes = [n for n, d in g.nodes(data=True) if d.get("kind") == "fact"]
    try:
        centrality = nx.pagerank(g) if fact_nodes else {}
    except Exception:
        centrality = {}

    # 归一化中心性到 0-1
    max_c = max((centrality.get(n, 0.0) for n in fact_nodes), default=0.0) or 1.0

    scored: List[Tuple[str, float]] = []
    for fid in fact_nodes:
        c = centrality.get(fid, 0.0) / max_c
        v = value_by_id.get(fid, 0.0)
        scored.append((fid, round(0.6 * c + 0.4 * v, 4)))

    scored.sort(key=lambda kv: kv[1], reverse=True)
    return scored


# =============================================================================
# 未覆盖枢纽检测
# =============================================================================

def find_uncovered_facts(state: Dict[str, Any],
                         threshold: float = HUB_VALUE_THRESHOLD) -> List[Dict]:
    """
    找出「高价值但没有任何 intent 在跟进」的事实

    这类事实是黑洞板的漏洞: 已经拿到了凭据/确认了漏洞，却没有任何探索方向去利用它。
    """
    facts = get_facts(state)
    if not facts:
        return []

    # 已被 intent 引用的 fact id
    covered = set()
    for i in get_intents(state):
        if i.get("status") in (IntentStatus.DONE, IntentStatus.ABANDONED):
            continue
        for src in (i.get("sources") or []):
            covered.add(src)

    uncovered = []
    for f in facts:
        fid = f.get("id")
        if not fid or fid in covered:
            continue
        value = float(f.get("value_score", 0.0) or 0.0)
        if value >= threshold and f.get("kind") in _ACTIONABLE_KINDS:
            uncovered.append(f)

    uncovered.sort(key=lambda f: f.get("value_score", 0.0), reverse=True)
    return uncovered


def has_uncovered_hub(state: Dict[str, Any]) -> bool:
    """是否存在未被跟进的高价值事实（router_bridge 用它决定是否转 explorer 补信息）"""
    return bool(find_uncovered_facts(state))


# =============================================================================
# Intent 优先级
# =============================================================================

def score_intents(state: Dict[str, Any]) -> List[Dict]:
    """
    重新计算所有 intent 的优先级（纯计算，无 LLM）

    评分构成:
      + 基础分: 来源 fact 的价值分（越高越值得做）
      + 技能加成: 有匹配技能的意图更可能成功
      + 成本惩罚: cost=high 的降权（比赛时间有限）
      + 状态惩罚: in_progress 保持不动（粘性，避免抖动）

    Returns:
        更新 priority 后的 intents 列表（不修改入参）
    """
    facts = get_facts(state)
    value_by_id = {
        f["id"]: float(f.get("value_score", 0.0) or 0.0)
        for f in facts if f.get("id")
    }

    out: List[Dict] = []
    for i in get_intents(state):
        item = dict(i)
        status = item.get("status", IntentStatus.PENDING)

        # 已终结的不再算分
        if status in (IntentStatus.DONE, IntentStatus.FAILED, IntentStatus.ABANDONED):
            item["priority"] = 0.0
            out.append(item)
            continue

        # 来源 fact 的最高价值分作为基础
        sources = item.get("sources") or []
        base = max((value_by_id.get(s, 0.0) for s in sources), default=0.3)

        score = base
        if item.get("skill"):
            score += 0.15          # 有可执行手法，成功率高
        if item.get("cost") == "high":
            score -= 0.15          # 高成本降权
        elif item.get("cost") == "low":
            score += 0.05

        item["priority"] = round(min(1.0, max(0.0, score)), 4)
        out.append(item)

    out.sort(key=lambda i: i.get("priority", 0.0), reverse=True)
    return out


# =============================================================================
# 规则驱动的 Intent 生成（省 LLM 调用）
# =============================================================================

def suggest_intents(state: Dict[str, Any], max_n: int = 3) -> List[Dict[str, Any]]:
    """
    基于黑板规则生成候选 intent（**不调用 LLM**）

    只在「有高价值事实但没人跟进」时产出。返回的是 intent dict 列表，
    由调用方决定是否写入 state。

    这是相比 Cairn 的一处改进: Cairn 每次态势变化都要跑一次 reason LLM 任务，
    这里用规则先兜住大部分显而易见的方向，把 LLM 留给真正需要推理的情况。
    """
    from board.board import make_intent

    uncovered = find_uncovered_facts(state)
    if not uncovered:
        return []

    out: List[Dict[str, Any]] = []
    for f in uncovered[:max_n]:
        kind = f.get("kind")
        desc = (f.get("description") or "").strip()
        if not desc:
            continue

        if kind == FactKind.CREDENTIAL:
            direction = f"利用凭据尝试横向/登录: {desc}"
            skill = None
        elif kind == FactKind.VULN:
            direction = f"验证并利用疑似漏洞: {desc}"
            skill = None
        elif kind == FactKind.ACCESS:
            direction = f"基于已获得的访问能力继续推进: {desc}"
            skill = None
        else:
            direction = f"跟进高价值发现: {desc}"
            skill = None

        out.append(make_intent(
            direction,
            sources=[f.get("id")],
            skill=skill,
            cost="medium",
        ))

    return out


def analyze(state: Dict[str, Any]) -> Dict[str, Any]:
    """
    一次性分析入口（board_node 调用）

    Returns:
        {
            "intents": 重新算分后的 intents,
            "uncovered": 未跟进的高价值事实,
            "new_intents": 规则建议的新意图（调用方决定是否采用）,
            "graph_available": networkx 是否可用,
        }
    """
    scored = score_intents(state)
    uncovered = find_uncovered_facts(state)
    suggested = suggest_intents(state)

    # 去掉与现有 intent 重复的建议（make_intent 的 id 幂等，这里做显式过滤便于观测）
    existing_ids = {i.get("id") for i in get_intents(state)}
    fresh = [s for s in suggested if s.get("id") not in existing_ids]

    return {
        "intents": scored,
        "uncovered": uncovered,
        "new_intents": fresh,
        "graph_available": NETWORKX_AVAILABLE,
        "open_intents": count_open_intents(state),
    }
