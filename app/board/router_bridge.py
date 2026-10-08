# app/board/router_bridge.py
"""
黑板路由桥接（Phase 3）

供 app/router.py 的 route_mode 在「即将返回 exploit」时调用，用黑板上的
事实-意图状态覆盖下一步节点。

设计约束（都为了「不破坏现有流程」）:

1. **只允许返回 "attacker" / "explorer"** —— 这两个 key 本就存在于
   ctf_agent_graph.py 的 _mode_manager_routes 里，因此**图结构零改动**。
2. **只在 next_node == "exploit" 时被调用** —— explore/innovate/end 的语义
   （探索轮次上限、失败分阈值、唯一超时终止）继续由 mode_manager_node 独占，
   黑板不介入，避免和「唯一正常结束 = 时间超时」这条铁律冲突。
3. **节流 + 粘性** —— RouteGuard（app/router.py）的规则「同一节点 >10 次」和
   「A→B→A 连续 3 次」会把频繁抖动判成死循环并强制改回 exploit。所以:
     - 节流: 每 BOARD_OVERRIDE_COOLDOWN 步最多覆盖一次
     - 粘性: 只对 pending 状态的 intent 返回 attacker，已认领的（in_progress）
       不再触发，避免 attacker↔explorer 来回跳
"""

import logging
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

# 触发 attacker 的意图优先级门槛
_ATTACKER_PRIORITY_THRESHOLD = 0.6

# explorer 补信息的探索轮次上限（超过就不再为「补信息」而探索）
_MAX_EXPLORE_ROUNDS_FOR_INFO = 3


def _get_config():
    """延迟导入 config，避免与 state_v2 的导入顺序形成环"""
    try:
        from config import config
        return config
    except ImportError:  # pragma: no cover
        return None


def board_route_decision(state: Dict[str, Any]) -> Optional[str]:
    """
    黑板路由决策

    Args:
        state: 当前 CTFState

    Returns:
        "attacker" / "explorer" 表示覆盖；None 表示不覆盖（沿用原路由结果）
    """
    if not isinstance(state, dict):
        return None

    cfg = _get_config()
    if cfg is None or not getattr(cfg, "ENABLE_BOARD_ROUTING", False):
        return None

    cooldown = int(getattr(cfg, "BOARD_OVERRIDE_COOLDOWN", 6) or 6)
    if cooldown < 1:
        cooldown = 1

    # ---- 节流: 每 cooldown 步最多覆盖一次，防止 RouteGuard 判死循环 ----
    try:
        steps = int(state.get("execution_steps", 0) or 0)
    except (TypeError, ValueError):
        steps = 0
    if steps % cooldown != 0:
        return None

    intents: List[Dict] = [i for i in (state.get("intents") or []) if isinstance(i, dict)]

    # ---- 规则 1: 有高优先级、待认领、且带明确手法的意图 -> 打 ----
    ready = []
    for i in intents:
        if i.get("status") != "pending":
            continue
        try:
            prio = float(i.get("priority", 0) or 0)
        except (TypeError, ValueError):
            prio = 0.0
        if prio >= _ATTACKER_PRIORITY_THRESHOLD:
            ready.append(i)

    if ready:
        return "attacker"

    # ---- 规则 2: 有高价值事实没人跟进、且还没探够 -> 补信息 ----
    try:
        rounds = int(state.get("exploration_rounds", 0) or 0)
    except (TypeError, ValueError):
        rounds = 0

    if rounds < _MAX_EXPLORE_ROUNDS_FOR_INFO:
        try:
            from board.analyzer import has_uncovered_hub
            if has_uncovered_hub(state):
                return "explorer"
        except Exception as e:  # 黑板故障不影响路由
            logger.debug("[Board] 未覆盖枢纽检测失败: %s", e)

    return None
