# app/skills/normalizer.py
"""
场景特征 → 黑板事实 的归一化

app/scene_detector.py 的 SceneDetector.detect() 用正则产出结构化特征，
本模块把它们物化为黑板 Fact，作为技能匹配的输入。

为什么需要这一层:
- SceneDetector 的输出是「原始特征」，缺一层归一化，且 fact_kinds 触发器没有数据源
- 归一化后同一条事实有稳定 id（如 tech:php:7.4），重复侦察自动合并

设计取舍:
- **不把 hints 转成事实**。SceneDetector 的 hints 是正则产物，噪声极大
  （"可能存在Base64编码数据"这类几乎人人命中），进黑板会稀释真正有用的信息。
- service_info 里的 server 字段单独抽出（如 "Apache/2.4.41"），它常带版本号，
  是技能匹配和 CVE 关联的关键输入。
"""

from typing import Any, Dict, List

from board.board import make_fact
from board.models import FactKind


def _clean(value: Any) -> str:
    """安全转字符串并去空白"""
    if value is None:
        return ""
    return str(value).strip()


def scenes_to_facts(
    scenes: Dict[str, Any],
    *,
    url: str = "",
    round_no: int = 0,
    source: str = "recon",
) -> List[Dict[str, Any]]:
    """
    把 SceneDetector 的输出物化为黑板 facts

    Args:
        scenes: SceneDetector.detect() 的返回值
        url: 归属 URL
        round_no: 当前轮次
        source: 产出节点名

    Returns:
        facts 列表（输入非法时返回空列表，不抛异常）
    """
    if not isinstance(scenes, dict):
        return []

    facts: List[Dict[str, Any]] = []
    common = dict(source=source, url=url, round_no=round_no)

    # 1. 框架/技术栈 —— [{name, version, source}]
    for fw in _as_list(scenes.get("framework")):
        if isinstance(fw, dict):
            name = _clean(fw.get("name"))
            version = _clean(fw.get("version"))
            origin = _clean(fw.get("source"))
        else:
            name, version, origin = _clean(fw), "", ""
        if not name:
            continue
        label = f"{name}/{version}" if version else name
        facts.append(make_fact(
            FactKind.TECH,
            f"{name.lower()}:{version}".rstrip(":"),
            label,
            evidence=origin,
            confidence=0.85,
            **common,
        ))

    # 2. 服务信息 —— {server, x_powered_by, port}
    svc = scenes.get("service_info")
    if isinstance(svc, dict):
        server = _clean(svc.get("server"))
        powered = _clean(svc.get("x_powered_by"))
        port = _clean(svc.get("port"))
        for label in (server, powered):
            if label:
                facts.append(make_fact(
                    FactKind.SERVICE,
                    label.lower().replace(" ", "_"),
                    label,
                    confidence=0.8,
                    **common,
                ))
        if port:
            facts.append(make_fact(
                FactKind.SERVICE, f"port:{port}", f"开放端口 {port}",
                confidence=0.9, **common,
            ))

    # 3. 可控输入点 —— [{type, method, name, hint}]
    for iv in _as_list(scenes.get("input_vectors")):
        if not isinstance(iv, dict):
            continue
        name = _clean(iv.get("name"))
        method = _clean(iv.get("method"))
        itype = _clean(iv.get("type"))
        if not name and not itype:
            continue
        facts.append(make_fact(
            FactKind.INPUT_POINT,
            f"{method}:{name}" if name else f"{method}:{itype}",
            f"{itype or '输入点'} {name}".strip(),
            evidence=_clean(iv.get("hint")),
            confidence=0.75,
            **common,
        ))

    # 4. 敏感路径 —— [str]
    for p in _as_list(scenes.get("sensitive_paths")):
        path = _clean(p)
        if not path:
            continue
        facts.append(make_fact(
            FactKind.PATH, path, f"敏感路径 {path}",
            confidence=0.8, **common,
        ))

    # 5. 数据特征 —— [{type, hint}]
    for dp in _as_list(scenes.get("data_patterns")):
        if not isinstance(dp, dict):
            continue
        dtype = _clean(dp.get("type"))
        if not dtype:
            continue
        facts.append(make_fact(
            FactKind.DATA_PATTERN,
            f"{dtype}:{url}",
            f"{dtype}: {_clean(dp.get('hint'))}".rstrip(": "),
            confidence=0.7,
            **common,
        ))

    return facts


def _as_list(value: Any) -> List[Any]:
    """安全转列表"""
    if isinstance(value, list):
        return value
    if value:
        return [value]
    return []
