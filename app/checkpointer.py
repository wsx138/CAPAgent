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
