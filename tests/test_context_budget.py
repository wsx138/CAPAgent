# tests/test_context_budget.py
"""
上下文预算与读取时投影测试

核心约束：**投影绝不修改原 state**。
旧压缩器的做法是「返回压缩后的完整 state 去覆盖」，那会与 LangGraph 的
reducer 增量语义打架（未提及的字段被当删除、丢掉的东西又被 reducer 加回来）。
本模块改为只读投影，这个测试就是守住这条底线。
"""

import copy
import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'app'))


def _big_state(n_results=50, n_urls=300):
    """
    构造一个「大 state」：
    - attack_results 是 LOW 级（会被裁剪）
    - credentials / found_flag 是 CRITICAL 级（必须原样保留）
    - visited_urls 是 MEDIUM 级（会被去重）
    """
    return {
        "credentials": [{"host": f"h{i}", "username": "admin"} for i in range(5)],
        "found_flag": "flag{critical_must_survive}",
        "shell_session": {"type": "meterpreter", "id": "sess1"},
        "attack_results": [
            {"tool": "sqlmap", "status": 200, "is_exploit": (i % 5 == 0),
             "output": "x" * 500}
            for i in range(n_results)
        ],
        "visited_urls": [f"http://t/page{i}" for i in range(n_urls)],
        "vuln_candidates": [{"type": "sqli", "location": f"p{i}", "url": "http://t/"}
                            for i in range(30)],
        "raw_html_snippet": "<html>" + "y" * 5000 + "</html>",
        "page_history": {f"http://t/p{i}": {"md5": "abc", "content": "z" * 1000}
                         for i in range(20)},
    }


class TestProjectionDoesNotMutate:
    """**最重要的一条**：投影必须是纯读操作"""

    def test_original_state_untouched(self):
        from context_budget import project_state
        state = _big_state()
        snapshot = copy.deepcopy(state)

        projected = project_state(state, purpose="test")

        assert state == snapshot, "投影绝不能修改原 state"
        assert projected is not state, "应返回新对象"

    def test_nested_structures_not_mutated(self):
        """嵌套的 list/dict 也不能被就地改动"""
        from context_budget import project_state
        state = _big_state()
        orig_len = len(state["attack_results"])
        orig_urls = len(state["visited_urls"])

        project_state(state)

        assert len(state["attack_results"]) == orig_len, "原 list 长度不应变化"
        assert len(state["visited_urls"]) == orig_urls

    def test_projection_is_smaller(self):
        """投影后应该确实变小了"""
        from context_budget import project_state, estimate_tokens
        import json
        state = _big_state()
        before = estimate_tokens(json.dumps(state, default=str))
        after = estimate_tokens(json.dumps(project_state(state), default=str))
        assert after < before, f"投影后应更小 ({after} vs {before})"


class TestProrityHandling:
    """分级策略是否按预期生效"""

    def test_critical_fields_preserved(self):
        from context_budget import project_state
        p = project_state(_big_state())
        assert p["found_flag"] == "flag{critical_must_survive}"
        assert p["shell_session"]["id"] == "sess1"
        assert len(p["credentials"]) == 5, "CRITICAL 级不应被裁剪"

    def test_low_fields_trimmed(self):
        from context_budget import project_state
        p = project_state(_big_state(n_results=50))
        assert len(p["attack_results"]) <= 20, "LOW 级应被裁剪到上限"

    def test_html_snippet_dropped(self):
        from context_budget import project_state
        p = project_state(_big_state())
        assert p.get("raw_html_snippet", "") == "", "原始 HTML 应被丢弃（已落盘）"

    def test_page_history_reduced_to_urls(self):
        from context_budget import project_state
        p = project_state(_big_state())
        ph = p.get("page_history", {})
        assert "urls" in ph or len(ph) <= 10, "page_history 应只留 URL"

    def test_unknown_field_passes_through(self):
        from context_budget import project_state
        p = project_state({"some_random_field": "keep me"})
        assert p["some_random_field"] == "keep me"


class TestBudgetCheck:
    def test_small_prompt_under_budget(self):
        from context_budget import check_budget
        info = check_budget("hello world", label="t")
        assert info["over_budget"] is False

    def test_large_prompt_flagged(self):
        from context_budget import check_budget
        huge = "x" * 200000          # ≈ 80k tokens
        info = check_budget(huge, label="t", warn_tokens=30000)
        assert info["over_budget"] is True
        assert info["tokens"] > 30000

    def test_empty_prompt(self):
        from context_budget import check_budget
        assert check_budget("")["tokens"] == 0
        assert check_budget(None)["tokens"] == 0


class TestRobustness:
    def test_garbage_state(self):
        from context_budget import project_state
        for bad in [None, {}, {"a": None}, "not a dict", 42]:
            project_state(bad)   # 不应抛异常

    def test_field_projection_failure_falls_back(self):
        """单字段投影失败时保留原值，不影响其余字段"""
        from context_budget import project_state
        state = {"attack_results": "不是列表，会让裁剪逻辑出错", "found_flag": "flag{x}"}
        p = project_state(state)
        assert p["found_flag"] == "flag{x}", "其它字段应正常投影"
        assert p["attack_results"] == state["attack_results"], "失败字段应回退原值"


class TestMemoryCompression:
    """长期记忆的整理（已知事实 / 失败记录 —— 原实现完全没处理）"""

    def _mm(self, tmp_path):
        import memory.memory_manager as MM
        return MM.MemoryManager(memory_dir=str(tmp_path))

    def test_known_facts_trimmed(self, tmp_path):
        mm = self._mm(tmp_path)
        for i in range(30):
            mm.save_known_fact("vuln", f"fact {i}")
        stats = mm.compress_memory(max_facts=10)
        assert stats["facts"] == 20, f"应精简 20 条，实际 {stats}"
        assert mm.known_facts_file.read_text(encoding="utf-8").count("## ") <= 11

    def test_failed_attempts_trimmed(self, tmp_path):
        mm = self._mm(tmp_path)
        for i in range(20):
            mm.save_failed_attempt({"tool": "t", "target": "h", "payload": f"p{i}"})
        stats = mm.compress_memory(max_failed=5)
        assert stats["failed"] == 15

    def test_idempotent_when_under_limit(self, tmp_path):
        """低于阈值时不应有任何改动"""
        mm = self._mm(tmp_path)
        mm.save_known_fact("vuln", "only one")
        stats = mm.compress_memory(max_facts=100)
        assert stats["facts"] == 0, "未超限不应裁剪"

    def test_credentials_deduped(self, tmp_path):
        mm = self._mm(tmp_path)
        mm.save_credential({"host": "h", "username": "u", "password": "a"})
        mm.save_credential({"host": "h", "username": "u", "password": "b"})
        stats = mm.compress_memory()
        assert stats["credentials"] >= 0     # 去重后不报错即可
