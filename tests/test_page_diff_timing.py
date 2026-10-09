# tests/test_page_diff_timing.py
"""
差分分析的时间盲注检测测试

背景: 原实现只对比响应内容的 MD5。时间盲注（如 `AND sleep(5)`）的响应内容
与基线【完全相同】，只有耗时变化——因此会被判为"无变化"，进而累积失败分、
提前放弃该方向。本测试覆盖修复后的行为。
"""

import hashlib
import pytest
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'app'))


def _manager():
    from topology.page_diff import PageDiffManager
    return PageDiffManager(task_id="test_timing")


def _md5(b: bytes) -> str:
    return hashlib.md5(b).hexdigest()


SAME_BODY = b"<html>same response body</html>"


def _history(duration=None, md5=None):
    h = {"last_md5": md5 or _md5(SAME_BODY), "last_file": "/nonexistent/baseline.html"}
    if duration is not None:
        h["last_duration"] = duration
    return {"http://t/index.php?id=1": h}


URL = "http://t/index.php?id=1"


class TestTimeBasedBlindDetection:
    """时间盲注应被识别为成功，而不是判为失败"""

    def test_slow_response_same_content_is_detected(self):
        """内容一致但耗时从 0.2s 涨到 5.2s -> 疑似时间盲注"""
        mgr = _manager()
        res = mgr.compare_and_analyze(
            URL, SAME_BODY, _history(duration=0.2), duration=5.2
        )
        assert res["changed"] is False, "内容确实没变"
        assert res["is_exploit"] is True, "但应判为疑似成功"
        assert res.get("time_anomaly") is True
        assert res["confidence"] < 0.8, "网络抖动可能假阳性，置信度不应过高"

    def test_normal_variation_not_flagged(self):
        """正常抖动（0.2s -> 0.4s）不应误报"""
        mgr = _manager()
        res = mgr.compare_and_analyze(
            URL, SAME_BODY, _history(duration=0.2), duration=0.4
        )
        assert res["changed"] is False
        assert res.get("is_exploit") is not True
        assert res.get("time_anomaly") is not True

    def test_borderline_below_threshold(self):
        """刚好低于阈值（3倍+2秒）不应触发"""
        mgr = _manager()
        # 基线 1.0s，阈值 = 1.0*3+2 = 5.0s
        res = mgr.compare_and_analyze(
            URL, SAME_BODY, _history(duration=1.0), duration=4.9
        )
        assert res.get("time_anomaly") is not True

    def test_slow_absolute_but_normal_relative_not_flagged(self):
        """慢站点（基线本就 4s）不应因为绝对耗时大而误报"""
        mgr = _manager()
        res = mgr.compare_and_analyze(
            URL, SAME_BODY, _history(duration=4.0), duration=5.0
        )
        assert res.get("time_anomaly") is not True, "应相对基线比较，而非固定阈值"


class TestBackwardCompatibility:
    """不传 duration 时必须完全保持原行为"""

    def test_no_duration_keeps_original_behaviour(self):
        mgr = _manager()
        res = mgr.compare_and_analyze(URL, SAME_BODY, _history())
        assert res["changed"] is False
        assert res["reason"] == "MD5一致"
        assert res.get("time_anomaly") is not True

    def test_no_baseline_duration(self):
        """历史里没有耗时记录时，不应报错也不应误报"""
        mgr = _manager()
        res = mgr.compare_and_analyze(URL, SAME_BODY, _history(), duration=99.0)
        assert res["changed"] is False
        assert res.get("time_anomaly") is not True

    def test_dirty_duration_values(self):
        """耗时字段是脏数据时不应抛异常"""
        mgr = _manager()
        for bad in ("abc", None, object()):
            h = _history()
            h[URL]["last_duration"] = bad
            mgr.compare_and_analyze(URL, SAME_BODY, h, duration=10.0)  # 不应抛异常

    def test_content_change_still_uses_original_path(self):
        """内容变化时仍走原有逻辑（不涉及时间判断）"""
        mgr = _manager()
        changed_body = b"<html>DIFFERENT response body</html>"
        res = mgr.compare_and_analyze(
            URL, changed_body, _history(duration=0.2), duration=0.3
        )
        assert res["changed"] is True, "内容变了就该走变化分支"

    def test_static_resource_ignored(self):
        mgr = _manager()
        res = mgr.compare_and_analyze("http://t/style.css", SAME_BODY, {}, duration=9.0)
        assert res["changed"] is False


class TestDurationIsRecorded:
    """save_page 应记录耗时作为下次的基线"""

    def test_duration_persisted(self, tmp_path):
        from topology.page_diff import PageDiffManager
        mgr = PageDiffManager(task_id="test_persist")
        # 让缓存写到临时目录，避免污染
        mgr.cache_dir = str(tmp_path)
        history = {}
        mgr.save_page(URL, SAME_BODY, history, duration=1.23)
        assert history[URL].get("last_duration") == pytest.approx(1.23)

    def test_duration_absent_when_not_given(self, tmp_path):
        from topology.page_diff import PageDiffManager
        mgr = PageDiffManager(task_id="test_persist2")
        mgr.cache_dir = str(tmp_path)
        history = {}
        mgr.save_page(URL, SAME_BODY, history)
        assert "last_duration" not in history[URL]
