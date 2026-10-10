# app/memory_bridge.py
"""
长期记忆桥接层（黑板 ↔ memory_manager）

## 为什么要这一层，而不是直接让节点调用 memory_manager

项目里其实有**两套记忆**，它们此前互不相干：

| | 黑板（app/board/） | memory_manager |
|---|---|---|
| 作用域 | **单任务** | **跨任务** |
| 载体 | LangGraph state | 6 个 JSON/MD 文件 |
| 结构化 | 是（12 种 kind） | 否（自由文本/JSON） |
| 参与决策 | 是 | 此前完全不参与 |

**关键设计决策：不做「运行中双写」。**

如果让节点同时往黑板和 memory_manager 写同一件事，就会产生两个会漂移的
真相源（这正是我在 verifier 写入上避免的坑）。所以按**作用域**划分职责：

    ┌──────────── 任务开始 ────────────┐
    │  长期记忆 ──载入──> 黑板初始事实   │   ← load_prior_knowledge()
    └──────────────────────────────────┘
              │
              ▼   运行中：只有黑板参与决策（单一真相源）
    ┌──────────── 任务进行 ────────────┐
    │        黑板（唯一工作记忆）        │
    └──────────────────────────────────┘
              │
              ▼
    ┌──────────── 任务结束 ────────────┐
    │  黑板事实 ──归档──> 长期记忆      │   ← archive_board()
    └──────────────────────────────────┘

这样两者互补而非重叠：黑板负责「这次怎么打」，长期记忆负责「上次打到哪」。
"""

import logging
from typing import Any, Dict, List, Optional

from board.board import make_fact
from board.models import FactKind

logger = logging.getLogger(__name__)


def _get_memory():
    """延迟导入 memory_manager（避免启动时的循环依赖与磁盘 IO）"""
    try:
        from memory.memory_manager import get_memory_manager
        return get_memory_manager()
    except Exception as e:
        logger.debug("[MemoryBridge] memory_manager 不可用: %s", e)
        return None


def _host_of(url: str) -> str:
    """从 URL 提取 host（用于按目标检索历史记忆）"""
    if not url:
        return ""
    try:
        from urllib.parse import urlparse
        p = urlparse(url if "://" in url else f"http://{url}")
        return p.hostname or ""
    except Exception:
        return ""


# =============================================================================
# 载入：长期记忆 → 黑板
# =============================================================================

def load_prior_knowledge(target_url: str, max_facts: int = 20) -> List[Dict[str, Any]]:
    """
    载入该目标的历史发现，转成黑板事实

    用于**任务开始时**给 agent 一个"上次打到哪"的起点。
    这些事实的 confidence 会被压低（0.5）—— 情报可能已经过时，
    不应与本次新发现等价对待。

    Args:
        target_url: 目标 URL
        max_facts:  最多载入多少条

    Returns:
        黑板 fact 列表（可直接放进 state["facts"]）
    """
    mm = _get_memory()
    if mm is None:
        return []

    host = _host_of(target_url)
    if not host:
        return []

    facts: List[Dict[str, Any]] = []

    try:
        # 1. 该目标的历史凭据（只记「有凭据」这个事实，不落明文到黑板）
        creds = mm.get_credentials(host) or []
        for cred in creds[:5]:
            user = str(cred.get("username", "") or "").strip()
            if not user:
                continue
            facts.append(make_fact(
                FactKind.CREDENTIAL,
                f"prior:{user}@{host}",
                f"[历史] 该目标曾获得凭据 {user}@{host}",
                evidence="memory/credentials.json",
                confidence=0.5,          # 历史情报，可能已失效
                source="memory_bridge",
                url=target_url,
            ))

        # 2. 已知事实 —— **必须按目标过滤**
        #    known_facts.md 是全局文件，不做过滤的话 A 目标的历史会串到 B 目标，
        #    造成"凭空多出无关情报"的污染。
        known = ""
        try:
            known = (mm.get_known_facts() or "").strip()
        except Exception:
            known = ""
        if known:
            relevant = [ln for ln in known.splitlines() if host in ln]
            if relevant:
                facts.append(make_fact(
                    FactKind.NOTE,
                    f"prior:known_facts:{host}",
                    f"[历史] 已知事实摘要: {' | '.join(relevant)[:400]}",
                    evidence="memory/known_facts.md",
                    confidence=0.5,
                    source="memory_bridge",
                    url=target_url,
                ))

    except Exception as e:
        logger.debug("[MemoryBridge] 载入历史记忆失败: %s", e)

    if facts:
        logger.info("[MemoryBridge] 为目标 %s 载入 %d 条历史记忆", host, len(facts))
    return facts[:max_facts]


# =============================================================================
# 归档：黑板 → 长期记忆
# =============================================================================

def archive_board(state: Dict[str, Any], target_url: str = "") -> Dict[str, int]:
    """
    任务结束时把黑板事实归档到长期记忆

    归档内容（只记客观结论，不含明文敏感数据）:
      - 关键事实（凭据/访问/漏洞）→ known_facts.md
      - flag → attack_history.json
      - 已证伪方向 → failed_attempts.json（供下次跳过）

    Returns:
        {"facts": N, "credentials": N, "attacks": N, "deadends": N}
    """
    mm = _get_memory()
    stats = {"facts": 0, "credentials": 0, "attacks": 0, "deadends": 0}
    if mm is None:
        return stats

    url = target_url or state.get("target_url", "") or ""
    host = _host_of(url)
    facts = [f for f in (state.get("facts") or []) if isinstance(f, dict)]

    for f in facts:
        kind = f.get("kind")
        desc = str(f.get("description", "") or "").strip()
        if not desc:
            continue
        try:
            if kind == FactKind.FLAG:
                mm.save_attack_result({
                    "type": "flag",
                    "target": url,
                    "content": desc[:500],
                    "success": True,
                    "source": "board_archive",
                })
                stats["attacks"] += 1

            elif kind == FactKind.DEADEND:
                # 已证伪方向 —— 下次直接跳过，避免重复踩坑
                mm.save_failed_attempt({
                    "tool": "board_deadend",
                    "target": host or url,
                    "payload": desc[:200],
                    "reason": "已在历史任务中证伪",
                })
                stats["deadends"] += 1

            elif kind in (FactKind.CREDENTIAL, FactKind.ACCESS, FactKind.VULN):
                # 内容前加 host 标记 —— 载入侧据此按目标过滤，
                # 否则相邻目标的历史会互相污染
                mm.save_known_fact(kind, f"[{host}] {desc[:380]}", source="board_archive")
                stats["facts"] += 1

                if kind == FactKind.CREDENTIAL:
                    stats["credentials"] += 1
                    # 同时写入 credentials.json —— 否则载入侧（get_credentials）
                    # 读不到，跨任务复用凭据的闭环就断了。
                    # 注意: 黑板 fact 里**不含明文密码**（设计如此），
                    # 这里只落 username/host，password 留空由后续任务补全。
                    import re as _re
                    m = _re.search(r"([^\s@]+)\s*@\s*([^\s@]+)", desc)
                    if m:
                        mm.save_credential({
                            "host": m.group(2),
                            "username": m.group(1),
                            "password": "",              # 刻意不落明文
                            "cred_type": "unknown",
                            "source": "board_archive",
                            "note": "仅记录凭据存在，明文需在后续任务中获取",
                        })

        except Exception as e:
            logger.debug("[MemoryBridge] 归档单条事实失败(%s): %s", kind, e)

    if any(stats.values()):
        logger.info("[MemoryBridge] 归档完成: %s", stats)
    return stats


def is_known_deadend(tool: str, target: str, payload: str = "") -> bool:
    """
    查询某个尝试是否在历史任务中已证伪

    供 attacker 在发 payload 前查一次，跳过已知无效的尝试。
    """
    mm = _get_memory()
    if mm is None:
        return False
    try:
        return bool(mm.is_failed_before(tool, target, payload))
    except Exception:
        return False


__all__ = ["load_prior_knowledge", "archive_board", "is_known_deadend"]
