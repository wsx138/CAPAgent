# tests/test_router_bridge.py
"""
黑板路由桥接测试

测试内容:
- 开关: ENABLE_BOARD_ROUTING=false 时必须完全不干预
- 节流: 覆盖频率受 BOARD_OVERRIDE_COOLDOWN 约束（防 RouteGuard 判死循环）
- 粘性: 已认领(in_progress)的意图不再触发 attacker
- 等价: route_mode 关闭态逐字节等价于改造前
- 健壮: 脏输入不抛异常
"""

import pytest
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'app'))


@pytest.fixture(autouse=True)
def _restore_config():
    """每个测试前后恢复 config 开关，避免测试间串扰"""
    import config as cfgmod
    c = cfgmod.config
    saved = (getattr(c, "ENABLE_BOARD_ROUTING", False),
             getattr(c, "BOARD_OVERRIDE_COOLDOWN", 6))
    yield
    c.ENABLE_BOARD_ROUTING, c.BOARD_OVERRIDE_COOLDOWN = saved


def _base_state(**kw):
    from board import make_intent
    state = {
        "execution_steps": 0,
        "current_mode": "exploit",
        "current_url": "http://x/",
        "visited_urls": ["http://x/"],
        "intents": [make_intent("验证 SQLi", sources=["vuln:sqli:x"], priority=0.9)],
        "facts": [],
    }
    state.update(kw)
    return state


class TestSwitch:
    """开关行为"""

    def test_disabled_never_overrides(self):
        import config as cfgmod
        from board.router_bridge import board_route_decision
        cfgmod.config.ENABLE_BOARD_ROUTING = False
        assert board_route_decision(_base_state()) is None

    def test_enabled_with_ready_intent_attacks(self):
        import config as cfgmod
        from board.router_bridge import board_route_decision
        cfgmod.config.ENABLE_BOARD_ROUTING = True
        assert board_route_decision(_base_state()) == "attacker"


class TestThrottle:
    """节流: 防止高频覆盖被 RouteGuard 判成死循环"""

    def test_override_rate_bounded(self):
        import config as cfgmod
        from board.router_bridge import board_route_decision
        cfgmod.config.ENABLE_BOARD_ROUTING = True
        cfgmod.config.BOARD_OVERRIDE_COOLDOWN = 6

        overrides = [s for s in range(10)
                     if board_route_decision(_base_state(execution_steps=s))]
        # cooldown=6 时，0..9 内只有 steps % 6 == 0（即 0 和 6）允许覆盖
        assert len(overrides) <= 2, f"节流失效，覆盖 {len(overrides)} 次"

    def test_cooldown_one_allows_every_step(self):
        import config as cfgmod
        from board.router_bridge import board_route_decision
        cfgmod.config.ENABLE_BOARD_ROUTING = True
        cfgmod.config.BOARD_OVERRIDE_COOLDOWN = 1
        assert board_route_decision(_base_state(execution_steps=3)) == "attacker"


class TestStickiness:
    """粘性: 意图被认领后不再重复触发"""

    def test_claimed_intent_not_retriggered(self):
        import config as cfgmod
        from board.router_bridge import board_route_decision
        from board import make_intent
        cfgmod.config.ENABLE_BOARD_ROUTING = True

        state = _base_state(intents=[
            make_intent("验证 SQLi", sources=["vuln:sqli:x"],
                        priority=0.9, status="in_progress")
        ])
        assert board_route_decision(state) != "attacker"

    def test_low_priority_intent_ignored(self):
        import config as cfgmod
        from board.router_bridge import board_route_decision
        from board import make_intent
        cfgmod.config.ENABLE_BOARD_ROUTING = True
        state = _base_state(intents=[make_intent("弱方向", sources=[], priority=0.2)])
        assert board_route_decision(state) is None


class TestRouterEquivalence:
    """route_mode 关闭态等价性"""

    def test_disabled_returns_current_mode(self):
        import config as cfgmod
        from router import route_mode
        cfgmod.config.ENABLE_BOARD_ROUTING = False
        assert route_mode(_base_state(), "mode_manager") == "exploit"

    def test_disabled_explore_innovate_unaffected(self):
        import config as cfgmod
        from router import route_mode
        cfgmod.config.ENABLE_BOARD_ROUTING = False
        for mode in ("explore", "innovate"):
            assert route_mode(_base_state(current_mode=mode), "mode_manager") == mode

    def test_enabled_but_no_intent_keeps_original(self):
        import config as cfgmod
        from router import route_mode
        cfgmod.config.ENABLE_BOARD_ROUTING = True
        assert route_mode(_base_state(intents=[]), "mode_manager") == "exploit"


class TestRobustness:
    """脏输入"""

    def test_garbage_state(self):
        import config as cfgmod
        from board.router_bridge import board_route_decision
        cfgmod.config.ENABLE_BOARD_ROUTING = True
        for bad in [{}, None, {"intents": "bad"}, {"intents": [None, 1]},
                    {"execution_steps": "x"}, {"intents": [{"status": "pending", "priority": "y"}]}]:
            board_route_decision(bad)  # 不应抛异常
