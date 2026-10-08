# tests/test_skills.py
"""
技能库测试

测试内容:
- 加载器: frontmatter 解析、格式校验、坏文件隔离
- 注册中心: 加载、查询、过滤
- 归一化: SceneDetector 输出 -> 黑板事实
- 匹配器: 硬门槛、场景加权、脏输入健壮
"""

import pytest
import sys
import os
from pathlib import Path

# 添加 app 目录到路径
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'app'))


VALID_SKILL = """---
name: test-skill
description: 测试技能
triggers:
  tech_stack: [php]
  fact_kinds: [vuln]
  keywords: [test]
  scene: web
tools: [sqlmap]
cost: high
---
## 适用条件
测试正文
"""


class TestLoader:
    """加载器测试"""

    def test_parse_valid_skill(self):
        from skills.loader import parse_skill_text
        sk = parse_skill_text(VALID_SKILL)
        assert sk["name"] == "test-skill"
        assert sk["triggers"]["tech_stack"] == ["php"]
        assert sk["tools"] == ["sqlmap"]
        assert sk["cost"] == "high"
        assert sk["body"].strip().startswith("## 适用条件")

    def test_missing_frontmatter_raises(self):
        from skills.loader import parse_skill_text, SkillFormatError
        with pytest.raises(SkillFormatError):
            parse_skill_text("just markdown, no frontmatter")

    def test_missing_name_raises(self):
        from skills.loader import parse_skill_text, SkillFormatError
        with pytest.raises(SkillFormatError):
            parse_skill_text("---\ndescription: no name here\n---\nbody")

    def test_invalid_yaml_raises(self):
        """
        回归测试: YAML flow sequence 中的特殊字符

        实战中踩到过: keywords 写成 `[SSTI, {{]` 里的 `{{` 在 flow context 中
        是非法起始字符，yaml.safe_load 会抛错。必须转成 SkillFormatError，
        由加载器隔离掉该文件而不是让整个加载失败。
        """
        from skills.loader import parse_skill_text, SkillFormatError
        bad = "---\nname: x\nkeywords: [a, {{, b]\n---\nbody"
        with pytest.raises(SkillFormatError):
            parse_skill_text(bad)

    def test_quoted_special_chars_ok(self):
        """加引号后特殊字符可正常解析"""
        from skills.loader import parse_skill_text
        ok = '---\nname: x\ntriggers:\n  keywords: [a, "{{", b]\n---\nbody'
        sk = parse_skill_text(ok)
        assert "{{" in sk["triggers"]["keywords"]

    def test_invalid_cost_falls_back(self):
        """非法 cost 值应回退为 medium，而不是报错"""
        from skills.loader import parse_skill_text
        sk = parse_skill_text("---\nname: x\ncost: bogus\n---\nbody")
        assert sk["cost"] == "medium"

    def test_bad_file_isolated_in_directory(self, tmp_path: Path):
        """坏文件被跳过，不影响同目录好文件加载"""
        from skills.loader import load_skills
        (tmp_path / "a.md").write_text(VALID_SKILL, encoding="utf-8")
        (tmp_path / "b.md").write_text("no frontmatter", encoding="utf-8")
        (tmp_path / "c.md").write_text("---\nname: y\n---\nbody", encoding="utf-8")
        skills = load_skills(tmp_path)
        names = {s["name"] for s in skills}
        assert names == {"test-skill", "y"}

    def test_duplicate_name_keeps_first(self, tmp_path: Path):
        """同名技能只保留第一个，避免注册表被覆盖"""
        from skills.loader import load_skills
        (tmp_path / "a.md").write_text(VALID_SKILL, encoding="utf-8")
        (tmp_path / "b.md").write_text(
            VALID_SKILL.replace("测试技能", "另一个"), encoding="utf-8")
        skills = load_skills(tmp_path)
        assert len(skills) == 1

    def test_missing_directory_returns_empty(self, tmp_path: Path):
        from skills.loader import load_skills
        assert load_skills(tmp_path / "nonexistent") == []


class TestRegistry:
    """注册中心测试"""

    def test_loads_real_skills(self):
        """真实技能目录应至少加载到首批技能"""
        from skills import SkillRegistry
        n = SkillRegistry.reload()
        assert n >= 5
        assert "php-filter-chain" in SkillRegistry.names()

    def test_get_by_name(self):
        from skills import SkillRegistry
        SkillRegistry.reload()
        sk = SkillRegistry.get("php-filter-chain")
        assert sk is not None
        assert sk["triggers"]["scene"] == "web"

    def test_get_missing_returns_none(self):
        from skills import SkillRegistry
        SkillRegistry.reload()
        assert SkillRegistry.get("no-such-skill") is None

    def test_by_scene_filter(self):
        from skills import SkillRegistry
        SkillRegistry.reload()
        web_skills = SkillRegistry.by_scene("web")
        assert len(web_skills) >= 5
        assert SkillRegistry.by_scene("nonexistent") == []

    def test_describe_all_excludes_body(self):
        """清单渲染只含要点，不含 Markdown 正文"""
        from skills import SkillRegistry
        SkillRegistry.reload()
        text = SkillRegistry.describe_all()
        assert "php-filter-chain" in text
        assert "## 适用条件" not in text


class TestNormalizer:
    """归一化测试"""

    def test_scenes_to_facts_basic(self):
        from skills import scenes_to_facts
        scenes = {
            "framework": [{"name": "PHP", "version": "7.4", "source": "X-Powered-By"}],
            "service_info": {"server": "Apache/2.4.41", "port": "80"},
            "sensitive_paths": ["/admin"],
            "input_vectors": [{"type": "GET", "method": "GET", "name": "id"}],
            "data_patterns": [{"type": "JWT", "hint": "疑似 JWT"}],
        }
        facts = scenes_to_facts(scenes, url="http://t/", round_no=1)
        kinds = {f["kind"] for f in facts}
        assert {"tech", "service", "path", "input_point", "data_pattern"} <= kinds

    def test_hints_not_imported(self):
        """
        SceneDetector 的 hints 是正则产物，噪声极大（"可能存在Base64编码数据"
        这类几乎人人命中），不应进黑板稀释真正有用的信息。
        """
        from skills import scenes_to_facts
        facts = scenes_to_facts({"hints": ["可能存在Base64编码数据", "疑似弱口令"]})
        assert facts == []

    def test_stable_ids_for_dedup(self):
        """同一特征重复侦察应产出相同 id，由 reducer 自动合并"""
        from skills import scenes_to_facts
        scenes = {"framework": [{"name": "PHP", "version": "7.4"}]}
        a = scenes_to_facts(scenes, url="http://t/")
        b = scenes_to_facts(scenes, url="http://t/")
        assert [f["id"] for f in a] == [f["id"] for f in b]

    def test_garbage_input(self):
        from skills import scenes_to_facts
        for bad in [None, {}, {"framework": "bad"}, {"service_info": None},
                    {"input_vectors": [None, 1]}]:
            scenes_to_facts(bad)


class TestMatcher:
    """匹配器测试"""

    PHP_SCENES = {
        "framework": [{"name": "PHP", "version": "7.4"}],
        "sensitive_paths": ["/index.php?page="],
    }

    def test_php_scene_prefers_php_skill(self):
        from skills import match_skills, SkillRegistry
        from board import make_fact
        from board.models import FactKind
        SkillRegistry.reload()
        facts = [make_fact(FactKind.VULN, "lfi", "疑似 LFI")]
        res = match_skills(
            scenes=self.PHP_SCENES, facts=facts,
            available_tools={"php-filter-chain", "sqlmap"},
            extra_text="/index.php?page=",
        )
        assert res
        assert res[0][0]["name"] == "php-filter-chain"

    def test_tool_hard_gate_excludes(self):
        """声明的工具全都不可用时，技能必须被淘汰"""
        from skills import match_skills, SkillRegistry
        from board import make_fact
        from board.models import FactKind
        SkillRegistry.reload()
        facts = [make_fact(FactKind.VULN, "lfi", "疑似 LFI")]
        res = match_skills(
            scenes=self.PHP_SCENES, facts=facts,
            available_tools={"sqlmap"},           # 没有 php-filter-chain
            extra_text="/index.php?page=",
        )
        assert "php-filter-chain" not in [s["name"] for s, _ in res]

    def test_no_tool_constraint_when_unknown(self):
        """available_tools=None 表示不检查，不应淘汰一切"""
        from skills import match_skills, SkillRegistry
        SkillRegistry.reload()
        res = match_skills(scenes=self.PHP_SCENES, facts=[], available_tools=None)
        assert len(res) >= 1

    def test_unrelated_scene_yields_low_or_none(self):
        from skills import match_skills, SkillRegistry
        SkillRegistry.reload()
        res = match_skills(scenes={"framework": [{"name": "Ruby"}]}, facts=[],
                           available_tools={"php-filter-chain"})
        assert len(res) == 0

    def test_matcher_garbage_input(self):
        from skills import match_skills
        for bad in [None, {}, {"framework": None}]:
            match_skills(scenes=bad, facts=[None, "x"], available_tools=None)

    def test_match_for_state_strips_body(self):
        """返回给节点的技能不应带 Markdown 正文（正文不进 LLM）"""
        from skills import match_for_state, SkillRegistry
        from board import make_fact
        from board.models import FactKind
        SkillRegistry.reload()
        state = {
            "page_features": self.PHP_SCENES,
            "facts": [make_fact(FactKind.VULN, "lfi", "疑似 LFI")],
            "current_url": "http://t/index.php?page=",
        }
        out = match_for_state(state, available_tools={"php-filter-chain"})
        assert out
        assert "body" not in out[0]
        assert "_score" in out[0]
