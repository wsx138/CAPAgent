# tests/test_resume.py
"""
断点续传测试

覆盖三块:
1. task_runtime —— 取消机制（原先是摆设）
2. checkpointer —— 持久化能力与降级
3. **端到端** —— 检查点能否跨"进程"存活（用真实 LangGraph 图验证）
"""

import os
import sqlite3
import sys
import threading

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'app'))


# =============================================================================
# 1. 运行时上下文（取消 + 进度上报）
# =============================================================================

class TestTaskRuntime:
    def teardown_method(self):
        from task_runtime import clear_task, unbind_current_task
        for tid in ("t_a", "t_b", "t_c"):
            clear_task(tid)
        unbind_current_task()

    def test_cancel_flag_flow(self):
        from task_runtime import (bind_current_task, request_cancel, is_cancelled,
                                  check_cancelled, TaskCancelled)
        bind_current_task("t_a")
        assert is_cancelled() is False
        assert request_cancel("t_a", "test") is True
        assert is_cancelled() is True
        with pytest.raises(TaskCancelled):
            check_cancelled()

    def test_duplicate_cancel_returns_false(self):
        from task_runtime import request_cancel
        assert request_cancel("t_a") is True
        assert request_cancel("t_a") is False, "重复取消应返回 False（已在取消中）"

    def test_clear_task_resets_state(self):
        from task_runtime import (bind_current_task, request_cancel, is_cancelled,
                                  clear_task)
        bind_current_task("t_a")
        request_cancel("t_a")
        clear_task("t_a")
        assert is_cancelled("t_a") is False, "清理后不应残留取消标志"

    def test_callback_invoked(self):
        from task_runtime import (bind_current_task, register_callback, notify_node,
                                  unregister_callback)
        seen = []
        bind_current_task("t_b")
        register_callback("t_b", lambda tid, node, state: seen.append((tid, node)))
        notify_node("recon", {"x": 1})
        assert seen == [("t_b", "recon")]
        unregister_callback("t_b")

    def test_callback_exception_does_not_propagate(self):
        """UI 回调出错绝不能拖垮渗透任务"""
        from task_runtime import (bind_current_task, register_callback, notify_node,
                                  unregister_callback)
        def boom(tid, node, state):
            raise RuntimeError("UI 崩了")
        bind_current_task("t_c")
        register_callback("t_c", boom)
        notify_node("recon")          # 不应抛异常
        unregister_callback("t_c")

    def test_tasks_are_isolated_per_thread(self):
        """并发任务不能互相串扰——每个线程绑定自己的 task_id"""
        from task_runtime import (bind_current_task, request_cancel, is_cancelled,
                                  unbind_current_task, clear_task)
        results = {}

        def worker(tid, cancel_it):
            bind_current_task(tid)
            if cancel_it:
                request_cancel(tid)
            results[tid] = is_cancelled()
            unbind_current_task()

        t1 = threading.Thread(target=worker, args=("t_a", True))
        t2 = threading.Thread(target=worker, args=("t_b", False))
        t1.start(); t2.start(); t1.join(); t2.join()

        assert results["t_a"] is True
        assert results["t_b"] is False, "一个任务被取消不应影响另一个"
        clear_task("t_a"); clear_task("t_b")


# =============================================================================
# 2. Checkpointer
# =============================================================================

class TestCheckpointer:
    def test_creates_persistent_checkpointer(self, tmp_path):
        from checkpointer import create_checkpointer
        cp, persistent = create_checkpointer(str(tmp_path / "cp.db"))
        assert persistent is True, "装了 sqlite 后端时应为持久化模式"
        assert (tmp_path / "cp.db").exists(), "数据库文件应被创建"

    def test_falls_back_to_memory_when_no_backend(self, monkeypatch):
        """缺包时必须降级而不是崩溃"""
        import checkpointer as ck
        from langgraph.checkpoint.memory import MemorySaver
        monkeypatch.setattr(ck, "SQLITE_CHECKPOINTER_AVAILABLE", False)
        cp, persistent = ck.create_checkpointer()
        assert persistent is False, "降级后不应声称支持断点续传"
        # 注: 新版 langgraph 里 MemorySaver 是 InMemorySaver 的别名，
        # 用 isinstance 判断比比较类名更稳
        assert isinstance(cp, MemorySaver)
        assert "Sqlite" not in type(cp).__name__

    def test_status_reports_capability(self):
        from checkpointer import checkpoint_status
        s = checkpoint_status()
        assert "sqlite_backend_available" in s
        assert "resumable" in s


# =============================================================================
# 3. 端到端：检查点跨"进程"存活（这是断点续传的核心验证）
# =============================================================================

def _build_simple_graph():
    """构造一个最小 LangGraph 图：a -> b -> END"""
    from typing import Annotated, TypedDict
    import operator
    from langgraph.graph import StateGraph, END

    class S(TypedDict):
        steps: Annotated[int, operator.add]
        trail: Annotated[list, operator.add]

    def node_a(s): return {"steps": 1, "trail": ["a"]}
    def node_b(s): return {"steps": 1, "trail": ["b"]}

    g = StateGraph(S)
    g.add_node("a", node_a)
    g.add_node("b", node_b)
    g.set_entry_point("a")
    g.add_edge("a", "b")
    g.add_edge("b", END)
    return g


class TestEndToEndResume:
    def test_checkpoint_survives_new_connection(self, tmp_path):
        """
        **核心验证**：用同一个 db 重新建 checkpointer（模拟进程重启），
        上一次执行的状态必须还在。
        """
        from checkpointer import create_checkpointer

        db = str(tmp_path / "cp.db")
        g = _build_simple_graph()

        # 第一次执行
        cp1, ok1 = create_checkpointer(db)
        app1 = g.compile(checkpointer=cp1)
        cfg = {"configurable": {"thread_id": "ctf_task_t_demo"}}
        r1 = app1.invoke({"steps": 0, "trail": []}, config=cfg)
        assert r1["steps"] == 2 and r1["trail"] == ["a", "b"]

        # 关闭连接，模拟进程退出
        try:
            cp1.conn.close()
        except Exception:
            pass

        # 第二次：全新 checkpointer，同一个 db
        cp2, ok2 = create_checkpointer(db)
        assert ok2 is True
        app2 = g.compile(checkpointer=cp2)

        state = app2.get_state(cfg)
        assert state is not None, "应能读到检查点"
        assert state.values["steps"] == 2, "状态必须从磁盘恢复"
        assert state.values["trail"] == ["a", "b"]

    def test_different_thread_ids_are_isolated(self, tmp_path):
        """不同 task_id 必须互不干扰（否则并发任务会串状态）"""
        from checkpointer import create_checkpointer

        db = str(tmp_path / "cp2.db")
        g = _build_simple_graph()
        cp, _ = create_checkpointer(db)
        app = g.compile(checkpointer=cp)

        cfg_a = {"configurable": {"thread_id": "ctf_task_A"}}
        cfg_b = {"configurable": {"thread_id": "ctf_task_B"}}
        app.invoke({"steps": 0, "trail": []}, config=cfg_a)

        st_b = app.get_state(cfg_b)
        # B 从未执行过，不应有状态
        assert not st_b.values, "未执行过的 thread 不应有状态"


# =============================================================================
# 4. Web 层：resume / resumable / cancel 接口
# =============================================================================

class TestTaskAPI:
    @pytest.fixture(autouse=True)
    def _setup(self):
        import sys as _s, os as _o
        _s.path.insert(0, _o.path.abspath(_o.path.join(_o.path.dirname(__file__), '..', 'web')))
        yield

    def _client(self):
        import api as W
        if not W.app.blueprints:
            W.app.register_blueprint(W.bp)
        return W, W.app.test_client()

    def test_resume_rejects_unknown_task(self):
        W, c = self._client()
        r = c.post('/fisher_ctf_agent/api/task/nope/resume')
        assert r.status_code == 404

    def test_resume_rejects_running_task(self):
        W, c = self._client()
        W.tasks['t_run'] = {'status': 'running', 'target_url': 'http://x/'}
        r = c.post('/fisher_ctf_agent/api/task/t_run/resume')
        assert r.status_code == 409

    def test_resume_requires_target(self):
        W, c = self._client()
        W.tasks['t_notarget'] = {'status': 'completed'}
        r = c.post('/fisher_ctf_agent/api/task/t_notarget/resume')
        assert r.status_code == 400, "缺少目标 URL 应拒绝"

    def test_resumable_endpoint(self):
        W, c = self._client()
        r = c.get('/fisher_ctf_agent/api/tasks/resumable')
        assert r.status_code == 200
        data = r.get_json()
        assert "resumable" in data and "checkpoint_persistent" in data

    def test_cancel_registers_runtime_flag(self):
        """取消必须真正登记到运行时，而不是只改字典"""
        from task_runtime import is_cancelled, clear_task
        W, c = self._client()
        W.tasks['t_cancel'] = {'status': 'running'}
        r = c.post('/fisher_ctf_agent/api/task/t_cancel/cancel')
        assert r.status_code == 200
        body = r.get_json()
        assert body["status"] == "cancelling"
        assert is_cancelled('t_cancel') is True, "取消必须真正生效"
        clear_task('t_cancel')


# =============================================================================
# 5. 检查点清理策略
# =============================================================================

class TestCheckpointCleanup:
    """清理必须「只删该删的」——运行中/可恢复的任务永远保护"""

    def _setup(self, tmp_path, monkeypatch, statuses):
        """
        构造若干任务记录 + 对应检查点，返回 (cleanup_fn, manager)
        statuses: [(task_id, status, age_days), ...]
        """
        import time as _t
        from task_persistence import TaskPersistenceManager
        import checkpointer as ck

        db = str(tmp_path / "tasks.db")
        pm = TaskPersistenceManager(db_path=db)
        now = _t.time()

        for tid, status, age_days in statuses:
            pm.create_task(tid, f"http://{tid}/", "web_ctf")
            pm.update_task(tid, status=status)
            # 手工把 updated_at 改老，模拟"很久以前完成的任务"
            conn = sqlite3.connect(db)
            conn.execute("UPDATE tasks SET updated_at=? WHERE task_id=?",
                         (now - age_days * 86400, tid))
            conn.commit()
            conn.close()

        # 让 cleanup 用这个 manager
        monkeypatch.setattr(ck, "SQLITE_CHECKPOINTER_AVAILABLE", True)
        monkeypatch.setattr("task_persistence.get_task_persistence", lambda: pm)

        # 造出真实的检查点，验证删除确实作用于检查点库
        cp_db = str(tmp_path / "cp.db")
        cp, _ = ck.create_checkpointer(cp_db)
        from typing import Annotated, TypedDict
        import operator
        from langgraph.graph import StateGraph, END

        class S(TypedDict):
            n: Annotated[int, operator.add]

        def only(s): return {"n": 1}
        g = StateGraph(S)
        g.add_node("only", only)
        g.set_entry_point("only"); g.add_edge("only", END)
        app = g.compile(checkpointer=cp)
        for tid, _, _ in statuses:
            app.invoke({"n": 0}, config={"configurable": {"thread_id": f"ctf_task_{tid}"}})

        def count_threads():
            conn = sqlite3.connect(cp_db)
            rows = conn.execute("SELECT DISTINCT thread_id FROM checkpoints").fetchall()
            conn.close()
            return {r[0] for r in rows}

        return ck.cleanup_checkpoints, count_threads, cp_db

    def test_removes_old_finished_keeps_running(self, tmp_path, monkeypatch):
        cleanup, count, cp_db = self._setup(tmp_path, monkeypatch, [
            ("old_done", "completed", 30),     # 该删
            ("recent_done", "completed", 1),   # 保留（太新）
            ("still_running", "running", 30),  # 保留（未终结，必须保护）
            ("resumable", "pending", 30),      # 保留（可恢复，必须保护）
        ])
        before = count()
        assert len(before) == 4

        res = cleanup(max_age_days=7, db_path=cp_db)

        after = count()
        assert res["deleted"] == 1, f"应只删 1 个，实际 {res['deleted']}"
        assert "ctf_task_old_done" not in after, "陈旧已完成任务应被清理"
        assert "ctf_task_still_running" in after, "**运行中的任务绝不能被清理**"
        assert "ctf_task_resumable" in after, "**可恢复的任务绝不能被清理**"
        assert "ctf_task_recent_done" in after, "未超期的应保留"

    def test_dry_run_does_not_delete(self, tmp_path, monkeypatch):
        cleanup, count, cp_db = self._setup(tmp_path, monkeypatch, [
            ("old_done", "completed", 30),
        ])
        before = count()
        res = cleanup(max_age_days=7, db_path=cp_db, dry_run=True)
        assert res["dry_run"] is True
        assert res["deleted"] == 1
        assert count() == before, "dry_run 不得真的删除"

    def test_nothing_to_clean(self, tmp_path, monkeypatch):
        cleanup, count, cp_db = self._setup(tmp_path, monkeypatch, [
            ("fresh", "completed", 0),
        ])
        res = cleanup(max_age_days=7, db_path=cp_db)
        assert res["deleted"] == 0
        assert res["errors"] == []

    def test_failed_and_cancelled_are_also_cleanable(self, tmp_path, monkeypatch):
        """终态不只 completed——failed/cancelled 同样可清理"""
        cleanup, count, cp_db = self._setup(tmp_path, monkeypatch, [
            ("f", "failed", 30),
            ("c", "cancelled", 30),
        ])
        res = cleanup(max_age_days=7, db_path=cp_db)
        assert res["deleted"] == 2
