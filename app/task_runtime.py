# app/task_runtime.py
"""
任务运行时上下文

解决三个此前的结构性问题：

1. **进度回调从未生效** —— web/api.py 注册的 `ctf_app._node_callbacks[task_id]`
   从未被任何节点消费，导致 UI 拿不到运行中的中间状态。
2. **取消是摆设** —— `/api/task/<id>/cancel` 只把字典里的 status 改成
   "cancelled"，而真正执行任务的 `app.invoke()` 根本不检查这个标志。
3. **任务与执行线程无关联** —— 节点不知道自己属于哪个 task，无法上报状态。

设计：以 task_id 为键的注册表 + 线程局部变量记录"当前线程正在跑哪个任务"。
节点执行时通过 `notify_node()` 上报；执行体通过 `check_cancelled()` 响应取消。

线程安全：每个任务跑在独立线程里，用 threading.local 记录当前 task_id，
因此并发的多个任务不会互相串扰。
"""

import logging
import threading
import time
from typing import Any, Callable, Dict, Optional

logger = logging.getLogger(__name__)


class TaskCancelled(Exception):
    """任务被取消（由节点在检查点抛出，用于中断 LangGraph 执行）"""


# task_id -> 节点回调（签名: (task_id, node_name, state) -> None）
_callbacks: Dict[str, Callable[[str, str, Optional[Dict]], None]] = {}

# task_id -> 取消标志
_cancel_flags: Dict[str, bool] = {}

# task_id -> 取消原因
_cancel_reasons: Dict[str, str] = {}

# 每个线程当前正在执行的任务（并发任务互不干扰）
_local = threading.local()

# 注册表读写锁（多线程任务并发时会同时增删）
_lock = threading.RLock()


# =============================================================================
# 任务与线程的关联
# =============================================================================

def bind_current_task(task_id: str) -> None:
    """把当前线程绑定到某个任务（任务开始时调用）"""
    _local.task_id = task_id


def current_task_id() -> Optional[str]:
    """取当前线程正在执行的任务 id"""
    return getattr(_local, "task_id", None)


def unbind_current_task() -> None:
    """解绑（任务结束时调用，避免线程复用时串扰）"""
    _local.task_id = None


# =============================================================================
# 回调注册（进度上报）
# =============================================================================

def register_callback(task_id: str,
                      callback: Callable[[str, str, Optional[Dict]], None]) -> None:
    """
    注册节点回调

    callback(task_id, node_name, state) 会在每个节点**执行前**被调用。
    """
    with _lock:
        _callbacks[task_id] = callback


def unregister_callback(task_id: str) -> None:
    with _lock:
        _callbacks.pop(task_id, None)


def notify_node(node_name: str, state: Optional[Dict[str, Any]] = None) -> None:
    """
    节点执行前上报（由 wrap_node 调用）

    回调异常绝不能影响主流程——UI 挂了不该让渗透任务挂掉。
    """
    task_id = current_task_id()
    if not task_id:
        return
    with _lock:
        cb = _callbacks.get(task_id)
    if cb is None:
        return
    try:
        cb(task_id, node_name, state)
    except Exception as e:
        logger.debug("[Runtime] 节点回调失败(已忽略) task=%s node=%s: %s",
                     task_id, node_name, e)


# =============================================================================
# 取消
# =============================================================================

def request_cancel(task_id: str, reason: str = "user_requested") -> bool:
    """
    请求取消任务

    Returns:
        True 表示此前未取消（本次是新请求）；False 表示已在取消中
    """
    with _lock:
        if _cancel_flags.get(task_id):
            return False
        _cancel_flags[task_id] = True
        _cancel_reasons[task_id] = reason
    logger.info("[Runtime] 任务取消请求已登记 task=%s reason=%s", task_id, reason)
    return True


def is_cancelled(task_id: Optional[str] = None) -> bool:
    """判断任务是否已被取消（不传则判断当前线程绑定的任务）"""
    tid = task_id or current_task_id()
    if not tid:
        return False
    with _lock:
        return bool(_cancel_flags.get(tid))


def cancel_reason(task_id: Optional[str] = None) -> str:
    tid = task_id or current_task_id()
    if not tid:
        return ""
    with _lock:
        return _cancel_reasons.get(tid, "")


def check_cancelled() -> None:
    """
    在节点边界检查取消标志，若已取消则抛出 TaskCancelled 中断执行

    由 wrap_node 在每个节点执行前调用。这是「取消能真正生效」的关键——
    原先只改字典标志，而 app.invoke() 阻塞执行、从不检查，取消形同虚设。
    """
    if is_cancelled():
        tid = current_task_id()
        raise TaskCancelled(f"任务 {tid} 已被取消: {cancel_reason()}")


def clear_task(task_id: str) -> None:
    """清理任务的所有运行时状态（任务结束时调用，防止内存泄漏）"""
    with _lock:
        _callbacks.pop(task_id, None)
        _cancel_flags.pop(task_id, None)
        _cancel_reasons.pop(task_id, None)
        _hint_queues.pop(task_id, None)


# =============================================================================
# 人工提示（HINT）注入
#
# 背景: state 里本来就有 hint_history 字段，attacker/verifier 也会读它
# （把 source=="human" 的最新提示当强约束注入 prompt），**但没有任何写入入口** ——
# 字段结构完整、读取逻辑通顺，只是永远为空。
#
# 难点: LangGraph 的 state 在 app.invoke() 执行期间无法从外部修改。
# 所以采用「事件队列 + 节点边界合并」:
#
#   Web API ──inject_hint──> 队列 ──wrap_node 出队──> 合并进节点返回值
#
# 这样不打断当前执行，hint 会在**下一个节点**生效（延迟不超过一个节点）。
# =============================================================================

# task_id -> 待注入的 hint 列表
_hint_queues: Dict[str, list] = {}


def inject_hint(task_id: str, content: str, level: int = 2,
                source: str = "human") -> bool:
    """
    注入一条人工提示

    Args:
        task_id: 目标任务（必须正在运行，否则无人消费）
        content: 提示内容
        level:   级别 1-3（越高越强）
        source:  来源，默认 human

    Returns:
        是否成功入队
    """
    text = (content or "").strip()
    if not text:
        return False

    hint = {
        "level": max(1, min(3, int(level) if str(level).isdigit() else 2)),
        "content": text[:1000],
        "source": source,
        "timestamp": time.time(),
    }
    with _lock:
        _hint_queues.setdefault(task_id, []).append(hint)
        size = len(_hint_queues[task_id])
    logger.info("[Runtime] 已注入提示 task=%s level=%s 队列长度=%d", task_id, hint["level"], size)
    return True


def drain_hints(task_id: Optional[str] = None) -> list:
    """
    取出并清空该任务的待注入提示

    由 wrap_node 在每个节点边界调用，把取到的提示合并进节点返回值，
    从而真正写进 state["hint_history"]。
    """
    tid = task_id or current_task_id()
    if not tid:
        return []
    with _lock:
        return _hint_queues.pop(tid, [])


def pending_hint_count(task_id: str) -> int:
    """待消费的提示数量（供接口回显）"""
    with _lock:
        return len(_hint_queues.get(task_id, []))


def active_tasks() -> list:
    """当前登记过的任务 id（用于诊断）"""
    with _lock:
        return sorted(set(_callbacks) | set(_cancel_flags))
