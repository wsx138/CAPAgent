# tests/test_memory_bridge.py
"""
长期记忆桥接测试

验证「跨任务记忆」的完整闭环：
    黑板事实 ──归档──> 长期记忆 ──载入──> 下次任务的黑板

重点:
- 归档四类事实（flag/凭据/漏洞/死路）各自落对文件
- 载入能跨任务读回（凭据通道必须打通，否则闭环断裂）
- 敏感的明文密码**不进黑板也不落盘**（刻意设计）
- 停用 memory_manager 时优雅降级，不影响主流程
"""

import os
import sys
import tempfile

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'app'))


@pytest.fixture
def bridge(tmp_path, monkeypatch):
    """用临时目录构造隔离的 memory_manager，并注入桥接层"""
    import memory.memory_manager as MM
    import memory_bridge as MB

    mm = MM.MemoryManager(memory_dir=str(tmp_path))
    monkeypatch.setattr(MB, "_get_memory", lambda: mm)
    return MB, mm, tmp_path


def _state(facts, url="http://t.example/"):
    return {"target_url": url, "facts": facts}


class TestArchive:
    def test_archives_all_fact_kinds(self, bridge):
        MB, mm, tmp = bridge
        from board import make_fact
        from board.models import FactKind

        stats = MB.archive_board(_state([
            make_fact(FactKind.FLAG, "f1", "flag{abc}", confidence=1.0),
            make_fact(FactKind.CREDENTIAL, "a@h", "凭据 admin@h"),
            make_fact(FactKind.VULN, "v1", "已确认 SQL 注入"),
            make_fact(FactKind.DEADEND, "d1", "LFI 无效"),
        ]))
        assert stats["attacks"] == 1, "flag 应进攻击历史"
        assert stats["deadends"] == 1, "死路应进失败记录"
        assert stats["credentials"] == 1
        assert stats["facts"] == 2, "凭据+漏洞应进已知事实"

    def test_writes_real_files(self, bridge):
        MB, mm, tmp = bridge
        from board import make_fact
        from board.models import FactKind

        MB.archive_board(_state([make_fact(FactKind.FLAG, "f1", "flag{x}")]))
        for name in ("attack_history.json", "known_facts.md"):
            assert (tmp / name).exists(), f"{name} 应该被创建"
            assert (tmp / name).stat().st_size > 0, f"{name} 不应为空"

    def test_no_plaintext_password_in_board_or_disk(self, bridge):
        """
        明文密码既不该出现在黑板 fact 里，也不该落盘。
        这是刻意的最小化敏感数据设计。
        """
        MB, mm, tmp = bridge
        from board import make_fact
        from board.models import FactKind

        MB.archive_board(_state([
            make_fact(FactKind.CREDENTIAL, "admin@h", "凭据 admin@h"),
        ]))
        creds = mm.get_credentials("h")
        assert creds, "凭据记录应存在"
        assert creds[0].get("password", "") == "", "不得落明文密码"

    def test_tolerates_empty_and_broken_facts(self, bridge):
        MB, mm, tmp = bridge
        for bad in ({}, {"facts": None}, {"facts": [None, 1, "x"]},
                    {"facts": [{"kind": "vuln", "description": ""}]}):
            MB.archive_board(bad)   # 不应抛异常


class TestLoad:
    def test_round_trip_credential_channel(self, bridge):
        """
        **闭环验证**：归档的凭据必须能被载入侧读到。
        这条通道一旦断裂，跨任务凭据复用就失效。
        """
        MB, mm, tmp = bridge
        from board import make_fact
        from board.models import FactKind

        MB.archive_board(_state([
            make_fact(FactKind.CREDENTIAL, "admin@t.example", "凭据 admin@t.example"),
        ]))
        prior = MB.load_prior_knowledge("http://t.example/")
        kinds = {f["kind"] for f in prior}
        assert "credential" in kinds, "凭据通道必须打通"
        assert any("admin" in f["description"] for f in prior)

    def test_returns_empty_for_unknown_target(self, bridge):
        MB, mm, tmp = bridge
        assert MB.load_prior_knowledge("http://never-seen.example/") == []

    def test_loaded_facts_are_low_confidence(self, bridge):
        """历史情报可能过时，置信度应压低，不与本次新发现等价"""
        MB, mm, tmp = bridge
        from board import make_fact
        from board.models import FactKind
        MB.archive_board(_state([make_fact(FactKind.CREDENTIAL, "a@h", "凭据 a@h")]))
        prior = MB.load_prior_knowledge("http://t.example/")
        assert prior
        assert all(f["confidence"] <= 0.5 for f in prior), "历史事实应低置信度"

    def test_garbage_url_is_safe(self, bridge):
        MB, mm, tmp = bridge
        for url in ("", "not a url", "://", "http://"):
            MB.load_prior_knowledge(url)   # 不应抛异常


class TestDeadendQuery:
    def test_known_deadend_detected(self, bridge):
        MB, mm, tmp = bridge
        from board import make_fact
        from board.models import FactKind
        MB.archive_board(_state([make_fact(FactKind.DEADEND, "d", "LFI 无效")]))
        # 归档时 target 取的是 URL 的 host（t.example），查询要用同一个 key
        assert MB.is_known_deadend("board_deadend", "t.example", "LFI 无效") is True

    def test_unknown_attempt_not_flagged(self, bridge):
        MB, mm, tmp = bridge
        assert MB.is_known_deadend("sqlmap", "x", "never tried") is False


class TestGracefulDegradation:
    def test_works_without_memory_manager(self, monkeypatch):
        """memory_manager 不可用时，桥接层必须静默降级而非崩"""
        import memory_bridge as MB
        monkeypatch.setattr(MB, "_get_memory", lambda: None)
        assert MB.load_prior_knowledge("http://x/") == []
        assert MB.archive_board({"facts": []}) == {
            "facts": 0, "credentials": 0, "attacks": 0, "deadends": 0}
        assert MB.is_known_deadend("t", "x", "p") is False
