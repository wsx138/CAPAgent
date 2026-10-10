# tests/test_hint.py
"""
人工提示（HINT）注入测试

背景: state 里本来就有 hint_history 字段、attacker/verifier 也会读它，
**但没有任何写入入口** —— 结构完整、逻辑通顺，只是永远为空。
本模块补上了「事件队列 + 节点边界合并」的注入通道。

验证重点:
- 注入 → 出队 的链路
- 多任务之间队列隔离（并发时不能串）
- hint_history 的 reducer 上限（原为 operator.add 无上限）
- API 边界
"""

import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'app'))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'web'))


@pytest.fixture(autouse=True)
def _cleanup():
    yield
    from task_runtime import clear_task
    for tid in ("t_a", "t_b", "t_empty"):
        clear_task(tid)


class TestInjectDrain:
    def test_inject_then_drain(self):
        from task_runtime import (bind_current_task, inject_hint, drain_hints,
                                  pending_hint_count)
        bind_current_task("t_a")
        assert inject_hint("t_a", "试试 filter chain", level=3) is True
        assert pending_hint_count("t_a") == 1

        hints = drain_hints()
        assert len(hints) == 1
        assert hints[0]["content"] == "试试 filter chain"
        assert hints[0]["level"] == 3
        assert hints[0]["source"] == "human"
        assert pending_hint_count("t_a") == 0, "出队后队列应清空"

    def test_drain_is_destructive(self):
        """drain 必须清空 —— 否则同一条提示会被反复注入"""
        from task_runtime import bind_current_task, inject_hint, drain_hints
        bind_current_task("t_a")
        inject_hint("t_a", "once")
        assert len(drain_hints()) == 1
        assert drain_hints() == [], "第二次 drain 应为空"

    def test_empty_content_rejected(self):
        from task_runtime import inject_hint
        assert inject_hint("t_a", "") is False
        assert inject_hint("t_a", "   ") is False
        assert inject_hint("t_a", None) is False

    def test_level_clamped(self):
        from task_runtime import bind_current_task, inject_hint, drain_hints
        bind_current_task("t_a")
        for given, expect in [(1, 1), (3, 3), (0, 1), (99, 3), ("bad", 2)]:
            inject_hint("t_a", f"lvl{given}", level=given)
        levels = [h["level"] for h in drain_hints()]
        assert levels == [1, 3, 1, 3, 2], f"级别应被夹到 1-3，实际 {levels}"

    def test_long_content_truncated(self):
        from task_runtime import bind_current_task, inject_hint, drain_hints
        bind_current_task("t_a")
        inject_hint("t_a", "x" * 5000)
        assert len(drain_hints()[0]["content"]) <= 1000

    def test_multiple_hints_kept_in_order(self):
        from task_runtime import bind_current_task, inject_hint, drain_hints
        bind_current_task("t_a")
        for i in range(3):
            inject_hint("t_a", f"hint{i}")
        assert [h["content"] for h in drain_hints()] == ["hint0", "hint1", "hint2"]


class TestIsolation:
    def test_queues_are_per_task(self):
        """并发任务之间不能串 —— A 的提示不能被 B 消费"""
        from task_runtime import bind_current_task, inject_hint, drain_hints
        inject_hint("t_a", "给 A 的")
        inject_hint("t_b", "给 B 的")

        bind_current_task("t_a")
        a_hints = drain_hints()
        bind_current_task("t_b")
        b_hints = drain_hints()

        assert [h["content"] for h in a_hints] == ["给 A 的"]
        assert [h["content"] for h in b_hints] == ["给 B 的"]

    def test_drain_without_binding_returns_empty(self):
        from task_runtime import drain_hints, unbind_current_task
        unbind_current_task()
        assert drain_hints() == []

    def test_clear_task_drops_queue(self):
        from task_runtime import (inject_hint, clear_task, pending_hint_count)
        inject_hint("t_a", "will be dropped")
        clear_task("t_a")
        assert pending_hint_count("t_a") == 0


class TestReducerCap:
    def test_hint_history_capped_at_20(self):
        """
        hint_history 原为 operator.add（无上限）—— 一旦接入注入就会无限增长。
        现改为带上限的 reducer。
        """
        from state_v2 import _cap_20_reducer
        merged = _cap_20_reducer([{"i": i} for i in range(15)],
                                 [{"i": i} for i in range(15, 30)])
        assert len(merged) == 20, "应被截断到 20 条"
        assert merged[-1]["i"] == 29, "保留的应是最近的"

    def test_reducer_handles_none(self):
        from state_v2 import _cap_20_reducer
        assert _cap_20_reducer(None, [{"i": 1}]) == [{"i": 1}]
        assert _cap_20_reducer([{"i": 1}], None) == [{"i": 1}]


class TestHintAPI:
    @pytest.fixture(autouse=True)
    def _client(self):
        import api as W
        if not W.app.blueprints:
            W.app.register_blueprint(W.bp)
        self.W = W
        self.c = W.app.test_client()

    def test_unknown_task_404(self):
        r = self.c.post('/fisher_ctf_agent/api/task/nope/hint',
                        json={"content": "x"})
        assert r.status_code == 404

    def test_empty_content_400(self):
        self.W.tasks['t_empty'] = {'status': 'running'}
        r = self.c.post('/fisher_ctf_agent/api/task/t_empty/hint',
                        json={"content": "  "})
        assert r.status_code == 400

    def test_successful_injection(self):
        from task_runtime import pending_hint_count, clear_task
        self.W.tasks['t_empty'] = {'status': 'running'}
        r = self.c.post('/fisher_ctf_agent/api/task/t_empty/hint',
                        json={"content": "试试 phpggc", "level": 3})
        assert r.status_code == 200
        body = r.get_json()
        assert body["status"] == "queued"
        assert body["pending"] == 1
        assert pending_hint_count('t_empty') == 1
        clear_task('t_empty')
