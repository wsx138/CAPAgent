# app/board/reducers.py
"""
黑板状态的规约器

⚠️ 两条硬约束（实测验证，见实施计划）:

1. **禁止复用 app/state_types/reducers.py 的 dedupe_list_reducer / base.py 的 list(set(x+y))**。
   它们用 set() 做去重，要求元素可哈希；一旦黑板通道里混入不可哈希对象（dict 本身可哈希
   但里面嵌套 list 就不行）就会 TypeError 打挂整张图。黑板一律走**按 id 的幂等 upsert**。

2. **节点看不见本 superstep 合并后的 state**。节点返回 {"facts": [...]} 时，它读到的
   state["facts"] 是上一轮的值。所以派生计算（intents）必须放在下一个 superstep 的
   board_node 里，不能在同一次返回里"读回合并结果再算"。

设计原则: 不可变（不修改入参）、幂等（同 id 重复写入不产生重复项）、可预测。
"""

from typing import Any, Dict, List

from board.models import (
    FactKind,
    HIGH_VALUE_KINDS,
    IntentStatus,
    INTENT_STATUS_ORDER,
)

# 容量上限: 防止 facts 无上限累积导致 MemorySaver 每步全量序列化变慢
MAX_FACTS = 200
MAX_INTENTS = 50

# 永不因截断而丢弃的 kind（数量天然稀少，且丢失代价高）
_PROTECTED_KINDS = frozenset(HIGH_VALUE_KINDS | {FactKind.DEADEND})


def _is_present(value: Any) -> bool:
    """
    判断一个值是否"有内容"（用于覆盖合并时跳过空值）

    注意不能用 `v not in (None, "", [], {})` —— 该写法依赖 == 比较，
    False == 0 在某些容器里会造成误判。这里显式判断。
    """
    if value is None:
        return False
    if isinstance(value, (str, list, dict, tuple, set)) and len(value) == 0:
        return False
    return True


def _upsert(x: List[Dict], y: List[Dict], id_field: str = "id") -> Dict[str, Dict]:
    """
    按 id 合并两个列表，返回 {id: item} 映射

    - 新条目直接加入
    - 已存在时: 新值中的非空字段覆盖旧值; confidence 取两者最大值（多次观察到同一事实=更强信心）
    - 不修改任何入参
    """
    by_id: Dict[str, Dict] = {}
    for item in (x or []):
        if isinstance(item, dict) and item.get(id_field):
            by_id[item[id_field]] = dict(item)

    for item in (y or []):
        if not isinstance(item, dict) or not item.get(id_field):
            continue
        key = item[id_field]
        old = by_id.get(key)
        if old is None:
            by_id[key] = dict(item)
            continue

        merged = dict(old)
        for field, value in item.items():
            if _is_present(value):
                merged[field] = value
            elif field not in merged:
                merged[field] = value

        # 置信度取最大，避免"再次确认"反而降低置信度
        old_conf = old.get("confidence")
        new_conf = item.get("confidence")
        if isinstance(old_conf, (int, float)) and isinstance(new_conf, (int, float)):
            merged["confidence"] = max(old_conf, new_conf)

        by_id[key] = merged

    return by_id


def _trim_facts(facts: List[Dict], cap: int = MAX_FACTS) -> List[Dict]:
    """
    按价值分截断，但保护高价值 kind

    不能简单按 value_score 排序取前 N: deadend 的价值分天然低（0.2），却直接决定
    "不要重复尝试哪些方向"，丢了代价很高。所以先保保护类，再按分数补足。
    """
    if len(facts) <= cap:
        return sorted(facts, key=lambda f: f.get("value_score", 0.0), reverse=True)

    protected = [f for f in facts if f.get("kind") in _PROTECTED_KINDS]
    protected_ids = {id(f) for f in protected}
    rest = [f for f in facts if id(f) not in protected_ids]
    rest.sort(key=lambda f: f.get("value_score", 0.0), reverse=True)

    room = max(0, cap - len(protected))
    keep = protected + rest[:room]
    return sorted(keep, key=lambda f: f.get("value_score", 0.0), reverse=True)


def upsert_facts_reducer(x: List[Dict], y: List[Dict]) -> List[Dict]:
    """
    Fact 通道规约器

    Args:
        x: 现有 facts（LangGraph 传入的当前值）
        y: 新增 facts（节点返回的增量）

    Returns:
        按 id 幂等合并、按价值分排序、带上限的 facts 列表
    """
    merged = _upsert(x, y)
    return _trim_facts(list(merged.values()))


def upsert_intents_reducer(x: List[Dict], y: List[Dict]) -> List[Dict]:
    """
    Intent 通道规约器

    与 facts 的区别: **status 只允许前进，不允许回退**。
    如果无条件 last-write-wins，一个已 done 的 intent 会被后续轮次的旧快照改回 pending，
    导致重复执行同一条探索方向。

    排序: 未完成的在前（按优先级降序），已终结的在后。
    """
    merged = _upsert(x, y)

    # 状态只前进
    for key, item in merged.items():
        new_status = item.get("status", IntentStatus.PENDING)
        for old_item in (x or []):
            if not isinstance(old_item, dict) or old_item.get("id") != key:
                continue
            old_status = old_item.get("status", IntentStatus.PENDING)
            if INTENT_STATUS_ORDER.get(new_status, 0) < INTENT_STATUS_ORDER.get(old_status, 0):
                item["status"] = old_status
            break

    items = list(merged.values())
    items.sort(key=lambda i: (
        INTENT_STATUS_ORDER.get(i.get("status", IntentStatus.PENDING), 0),
        -i.get("priority", 0.0),
    ))
    return items[:MAX_INTENTS]
