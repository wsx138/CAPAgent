# tests/test_board.py
"""
黑板模块测试

测试内容:
- 规约器: 幂等 upsert、去重、超限截断、状态不回退、不可哈希安全
- 投影: render_known_facts 的回退路径（Phase 2 迁移的关键）
- 抽取: 脏数据丢弃、置信度门槛
- 分析: 未覆盖枢纽检测、intent 优先级
"""

import pytest
import sys
import os

# 添加 app 目录到路径
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'app'))


def _fact(fid="f1", kind="vuln", desc="test", **kw):
    from board import make_fact
    f = make_fact(kind, fid, desc, **kw)
    f["id"] = fid  # 覆盖成测试指定的 id，便于断言
    return f


def _intent(iid="i1", sources=None, status="pending", **kw):
    from board import make_intent
    i = make_intent("test dir", sources=sources or [], **kw)
    i["id"] = iid
    i["status"] = status
    return i


class TestReducers:
    """规约器测试"""

    def test_facts_upsert_dedupes_by_id(self):
        """同一 id 重复写入应合并为一条，而不是产生重复项"""
        from board import upsert_facts_reducer
        a = _fact("f1", "vuln", "old")
        b = _fact("f1", "vuln", "new")
        out = upsert_facts_reducer([a], [b])
        assert len(out) == 1
        assert out[0]["description"] == "new"

    def test_facts_confidence_takes_max(self):
        """重复观察到同一事实应增强置信度，不能被覆盖降低"""
        from board import upsert_facts_reducer
        a = _fact("f1", confidence=0.9)
        b = _fact("f1", confidence=0.4)
        out = upsert_facts_reducer([a], [b])
        assert out[0]["confidence"] == 0.9

    def test_facts_reducer_no_unhashable_crash(self):
        """
        回归测试: 不得复用 set() 做去重

        app/state_types/reducers.py:103 的 dedupe_list_reducer 用 list(set(x+y))，
        元素不可哈希时抛 TypeError。dict 本身可哈希，所以这里显式构造
        含嵌套 list 的 fact（真实场景中 context/evidence 可能就是列表）来验证不崩。
        """
        from board import upsert_facts_reducer
        a = _fact("f1")
        a["nested"] = [1, 2, 3]          # 含不可哈希值
        b = _fact("f2")
        b["nested"] = [{"deep": 1}]
        out = upsert_facts_reducer([a], [b])   # 不应抛异常
        assert len(out) == 2

    def test_facts_trim_keeps_protected_kinds(self):
        """截断时必须保住高价值/死路事实（deadend 价值分低但丢失代价高）"""
        from board import upsert_facts_reducer, MAX_FACTS
        from board.models import FactKind
        # 塞满低价值事实
        noise = [_fact(f"n{i}", "tech", f"noise{i}") for i in range(MAX_FACTS + 20)]
        key_facts = [
            _fact("cred1", FactKind.CREDENTIAL, "admin:pass"),
            _fact("dead1", FactKind.DEADEND, "LFI 无效"),
            _fact("flag1", FactKind.FLAG, "flag{x}"),
        ]
        out = upsert_facts_reducer(noise, key_facts)
        assert len(out) <= MAX_FACTS
        ids = {f["id"] for f in out}
        assert {"cred1", "dead1", "flag1"} <= ids, "保护类事实不应被截断丢弃"

    def test_intents_status_never_goes_backwards(self):
        """已 done 的 intent 不能被旧快照改回 pending（否则会重复执行）"""
        from board import upsert_intents_reducer
        done = _intent("i1", status="done")
        stale = _intent("i1", status="pending")
        out = upsert_intents_reducer([done], [stale])
        assert out[0]["status"] == "done"

    def test_intents_sorted_unfinished_first(self):
        """未完成的 intent 排在已终结的前面"""
        from board import upsert_intents_reducer
        a = _intent("i1", status="done", priority=0.9)
        b = _intent("i2", status="pending", priority=0.1)
        out = upsert_intents_reducer([], [a, b])
        assert out[0]["id"] == "i2"

    def test_reducers_handle_none_input(self):
        """reducer 必须容忍 None（LangGraph 首次合并时可能传入）"""
        from board import upsert_facts_reducer, upsert_intents_reducer
        assert upsert_facts_reducer(None, [_fact()]) is not None
        assert upsert_facts_reducer([_fact()], None) is not None
        assert upsert_intents_reducer(None, [_intent()]) is not None
        assert upsert_facts_reducer(None, None) == []


class TestRenderKnownFacts:
    """投影函数测试 —— Phase 2 迁移的关键"""

    def test_fallback_when_board_disabled(self):
        """
        黑板未启用（facts 为空）时必须回退读旧字段

        这是「逐字节回退」保证: ENABLE_BOARD=false 时行为与改造前完全一致。
        """
        from board import render_known_facts
        state = {"known_facts": "A; B"}
        assert render_known_facts(state) == "A; B"

    def test_uses_facts_when_present(self):
        """facts 非空时走黑板，且带 kind 标注"""
        from board import render_known_facts
        state = {"known_facts": "旧值", "facts": [_fact("f1", "credential", "admin:admin123")]}
        out = render_known_facts(state)
        assert "admin:admin123" in out
        assert "[credential]" in out
        assert "旧值" not in out

    def test_empty_state_returns_empty_string(self):
        from board import render_known_facts
        assert render_known_facts({}) == ""

    def test_large_facts_capped_in_prompt(self):
        """facts 很多时只注入 top-N，防止 prompt 膨胀"""
        from board import render_known_facts
        facts = [_fact(f"f{i}", "tech", f"tech{i}", confidence=0.9) for i in range(200)]
        out = render_known_facts({"facts": facts})
        assert len(out.splitlines()) <= 40


class TestExtractors:
    """抽取器测试"""

    def test_verifier_extracts_flag_credential_vuln(self):
        from board import facts_from_verifier
        res = {
            "found_flag": True, "potential_flag": "flag{abc}",
            "is_exploit_successful": True, "exploit_evidence": "SQLi confirmed",
            "new_facts": [{"kind": "credential", "key": "admin", "description": "admin:123"}],
        }
        out = facts_from_verifier(res, current_url="http://t/", round_no=1)
        kinds = {f["kind"] for f in out}
        assert {"flag", "credential", "vuln"} == kinds

    def test_verifier_drops_invalid_llm_items(self):
        """LLM 输出的脏数据必须被丢弃，不能污染黑板"""
        from board import facts_from_verifier
        out = facts_from_verifier({"new_facts": [
            {"kind": "not_a_real_kind", "description": "x"},   # kind 非法
            {"kind": "tech", "description": ""},               # 空描述
            {"kind": "tech", "description": "PHP/7.4"},        # 合法
            "not a dict", 123, None,
        ]})
        assert len(out) == 1
        assert out[0]["description"] == "PHP/7.4"

    def test_verifier_captures_flag_without_explicit_field(self):
        """LLM 忘了把 flag 放进 new_facts 时，仍应从证据里兜住"""
        from board import facts_from_verifier
        out = facts_from_verifier({
            "is_exploit_successful": True,
            "exploit_evidence": "output: flag{leaked_from_evidence}",
        })
        assert any(f["kind"] == "flag" for f in out)

    def test_candidates_respect_confidence_threshold(self):
        from board import facts_from_candidates
        out = facts_from_candidates([
            {"type": "sqli", "location": "param:id", "confidence": 0.9},
            {"type": "xss", "location": "param:q", "confidence": 0.2},
        ], min_confidence=0.6)
        assert len(out) == 1
        assert out[0]["kind"] == "vuln"

    def test_extractors_survive_garbage_input(self):
        """抽取器在任意脏输入下都不得抛异常"""
        from board import facts_from_verifier, facts_from_candidates, facts_from_credentials
        for bad in [None, {}, {"new_facts": "notalist"}, {"new_facts": [None, 1, "x"]}, 42]:
            facts_from_verifier(bad)
        facts_from_candidates(None)
        facts_from_candidates([None, "x", 123])
        facts_from_credentials(None)
        facts_from_credentials([None, {"nouser": 1}])


class TestAnalyzer:
    """图分析测试"""

    def test_find_uncovered_high_value_fact(self):
        from board import find_uncovered_facts, upsert_facts_reducer, make_fact
        from board.models import FactKind
        facts = upsert_facts_reducer([], [
            make_fact(FactKind.CREDENTIAL, "admin", "获得凭据 admin@host"),
            make_fact(FactKind.TECH, "php", "PHP/7.4"),
        ])
        uncovered = find_uncovered_facts({"facts": facts, "intents": []})
        kinds = {f["kind"] for f in uncovered}
        assert FactKind.CREDENTIAL in kinds
        assert FactKind.TECH not in kinds, "普通技术栈不应算作待跟进枢纽"

    def test_covered_fact_not_reported(self):
        """已被 intent 引用的事实不再算「未覆盖」"""
        from board import find_uncovered_facts, make_fact, make_intent
        from board.models import FactKind
        cred = make_fact(FactKind.CREDENTIAL, "admin", "凭据 admin@host")
        intent = make_intent("用凭据登录", sources=[cred["id"]])
        out = find_uncovered_facts({"facts": [cred], "intents": [intent]})
        assert out == []

    def test_flag_is_not_a_pending_direction(self):
        """flag 是终点不是待探索方向，不应出现在未覆盖列表"""
        from board import find_uncovered_facts, make_fact
        from board.models import FactKind
        flag = make_fact(FactKind.FLAG, "f", "flag{x}", confidence=1.0)
        assert find_uncovered_facts({"facts": [flag], "intents": []}) == []

    def test_score_intents_prefers_high_value_source(self):
        from board import score_intents, make_fact, make_intent
        from board.models import FactKind
        cred = make_fact(FactKind.CREDENTIAL, "admin", "凭据")
        tech = make_fact(FactKind.TECH, "php", "PHP")
        intents = [
            make_intent("用凭据", sources=[cred["id"]]),
            make_intent("看技术栈", sources=[tech["id"]]),
        ]
        scored = score_intents({"facts": [cred, tech], "intents": intents})
        assert scored[0]["description"] == "用凭据"

    def test_high_cost_intent_penalized(self):
        from board import score_intents, make_intent
        a = make_intent("d1", cost="low")
        b = make_intent("d2", cost="high")
        scored = score_intents({"facts": [], "intents": [a, b]})
        by_desc = {i["description"]: i["priority"] for i in scored}
        assert by_desc["d1"] > by_desc["d2"]

    def test_analyze_survives_malformed_state(self):
        from board import analyze
        for bad in [{}, {"facts": "bad"}, {"facts": None, "intents": None}, {"facts": [None]}]:
            analyze(bad)
