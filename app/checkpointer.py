# app/checkpointer.py
"""
LangGraph 检查点（checkpoint）持久化管理

**这是断点续传的核心**。LangGraph 的 checkpointer 会在每个节点执行后保存
状态快照；只要它落在磁盘上，进程重启后就能从最后一步继续。

原实现用的是 `MemorySaver()`——纯内存，进程一退全丢，因此断点续传无从谈起。

策略：优先 SQLite 持久化；若缺 `langgraph-checkpoint-sqlite` 包，则降级为
内存模式并**明确告警**（不能让"缺个可选包"变成"启动失败"）。
"""

import logging
import os
import sqlite3
import time
from pathlib import Path
from typing import Optional, Tuple

logger = logging.getLogger(__name__)

# 项目根
BASE_DIR = Path(__file__).resolve().parent.parent
DEFAULT_DB_PATH = BASE_DIR / "data" / "checkpoints.db"

# SQLite checkpointer 可用性
try:
    from langgraph.checkpoint.sqlite import SqliteSaver
    SQLITE_CHECKPOINTER_AVAILABLE = True
except ImportError:  # pragma: no cover - 取决于环境
    SqliteSaver = None  # type: ignore
    SQLITE_CHECKPOINTER_AVAILABLE = False

from langgraph.checkpoint.memory import MemorySaver


def create_checkpointer(db_path: Optional[str] = None) -> Tuple[object, bool]:
    """
    创建 checkpointer

    Args:
        db_path: SQLite 文件路径；None 表示用默认 data/checkpoints.db

    Returns:
        (checkpointer, is_persistent)
        is_persistent=True 表示状态会落盘，支持断点续传
    """
    if not SQLITE_CHECKPOINTER_AVAILABLE:
        logger.warning(
            "[Checkpoint] 未安装 langgraph-checkpoint-sqlite，降级为内存模式——"
            "**进程重启后无法恢复任务**。安装后可启用断点续传: "
            "pip install langgraph-checkpoint-sqlite"
        )
        return MemorySaver(), False

    path = Path(db_path) if db_path else DEFAULT_DB_PATH
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        # check_same_thread=False: 任务跑在独立线程里，且有并发任务
        # timeout=30: 并发写入时等待锁而不是立即报 database is locked
        conn = sqlite3.connect(str(path), check_same_thread=False, timeout=30)
        # WAL 模式提升并发读写表现
        conn.execute("PRAGMA journal_mode=WAL")
        saver = SqliteSaver(conn)
        logger.info("[Checkpoint] 已启用 SQLite 持久化: %s", path)
        return saver, True
    except Exception as e:
        logger.error(
            "[Checkpoint] 初始化 SQLite checkpointer 失败(%s)，降级为内存模式", e
        )
        return MemorySaver(), False


def checkpoint_status() -> dict:
    """检查点能力状态（供 Web API / 健康检查使用）"""
    return {
        "sqlite_backend_available": SQLITE_CHECKPOINTER_AVAILABLE,
        "db_path": str(DEFAULT_DB_PATH),
        "resumable": SQLITE_CHECKPOINTER_AVAILABLE,
    }


# =============================================================================
# 检查点清理
#
# 检查点会随任务无限增长（每个 superstep 一行，长任务可达数百行）。
# 这里按「任务最后更新时间」清理陈旧数据。
#
# 时间来源复用 task_persistence 的 tasks.updated_at —— 它是准确的业务时间，
# 比从 checkpoint_id 解析可靠（LangGraph 的 UUID 时钟序列不是标准 UUIDv6 语义）。
# =============================================================================

# 终态：这些状态的任务不再需要检查点（保留一段时间供追溯即可）
_FINAL_STATUSES = ("completed", "failed", "error", "cancelled")


def cleanup_checkpoints(max_age_days: int = 7,
                        db_path: Optional[str] = None,
                        dry_run: bool = False) -> dict:
    """
    清理陈旧的检查点

    规则:
      - 只清理**已终结**（completed/failed/error/cancelled）的任务
      - 且其最后更新时间早于 max_age_days 天
      - **正在运行 / 可恢复的任务永远保护**（不会被误删）

    Args:
        max_age_days: 保留天数，超过则清理
        db_path:      检查点库路径，默认 data/checkpoints.db
        dry_run:      True 只统计不删除

    Returns:
        {"scanned": int, "deleted": int, "kept": int, "errors": [...]}
    """
    result = {"scanned": 0, "deleted": 0, "kept": 0, "errors": [], "dry_run": dry_run}

    if not SQLITE_CHECKPOINTER_AVAILABLE:
        result["errors"].append("未启用 SQLite checkpointer，无需清理")
        return result

    # 1. 从 task_persistence 取「可安全清理」的任务（终态 + 够旧）
    try:
        from task_persistence import get_task_persistence
        persistence = get_task_persistence()
        all_tasks = persistence.get_all_tasks(limit=10000)
    except Exception as e:
        result["errors"].append(f"读取任务记录失败: {e}")
        return result

    cutoff = time.time() - max_age_days * 86400
    stale_threads = []
    running_ids = set()

    with persistence._lock:  # 复用其锁，保证读取一致
        for rec in all_tasks:
            result["scanned"] += 1
            if rec.status not in _FINAL_STATUSES:
                # 未终结 —— 可能正在跑，也可能可恢复，都必须保护
                running_ids.add(rec.task_id)
                result["kept"] += 1
                continue
            if rec.updated_at and rec.updated_at < cutoff:
                stale_threads.append(rec.task_id)
            else:
                result["kept"] += 1

    if not stale_threads:
        return result

    if dry_run:
        result["deleted"] = len(stale_threads)
        result["would_delete"] = stale_threads
        return result

    # 2. 逐个删除对应 thread 的检查点
    path = Path(db_path) if db_path else DEFAULT_DB_PATH
    try:
        conn = sqlite3.connect(str(path), check_same_thread=False, timeout=30)
        saver = SqliteSaver(conn)
        for tid in stale_threads:
            thread_id = f"ctf_task_{tid}"
            try:
                saver.delete_thread(thread_id)
                result["deleted"] += 1
                logger.info("[Checkpoint] 已清理陈旧检查点 thread=%s", thread_id)
            except Exception as e:
                result["errors"].append(f"{thread_id}: {e}")
        conn.close()
    except Exception as e:
        result["errors"].append(f"打开检查点库失败: {e}")

    return result
