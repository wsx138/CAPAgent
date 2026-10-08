# app/board/extractors.py
"""
各节点的「事实抽取器」

全部是**纯函数、无 LLM 调用、不读全局状态**。节点在自己的返回 dict 里调用它们，
产出增量 facts 交给 upsert_facts_reducer 合并。

抽取原则:
- 只抽取**客观、可验证**的结论。不做推测（推测属于 intent，不属于 fact）。
- 输入格式不可控（LLM 输出、工具回包），因此每个函数都必须**不抛异常**：
  解析失败时返回空列表，绝不阻断主流程。
- id 由 make_fact_id 按 kind + key 构造，天然幂等，同一事实重复发现自动合并。
"""

import re
from typing import Any, Dict, List, Optional

from board.board import make_fact
from board.models import FactKind

# 允许 LLM 直接产出的 kind（白名单，防止脏数据进图）
_ALLOWED_LLM_KINDS = frozenset({
    FactKind.VULN, FactKind.CREDENTIAL, FactKind.ACCESS,
    FactKind.TECH, FactKind.SERVICE, FactKind.PATH,
    FactKind.INPUT_POINT, FactKind.DATA_PATTERN,
    FactKind.ASSET, FactKind.DEADEND,
})

# 从文本里识别 flag 的正则（与 ctf_agent_graph.py:2451 的预捕获保持一致的口径）
_FLAG_RE = re.compile(
    r"((?:flag|ctf|nssctf|hgame|dasctf|moectf|isctf|buuctf|攻防世界)\{[a-zA-Z0-9_\-@!#$%^&*]{1,128}\})",
    re.IGNORECASE,
)

# 从文本里识别凭据形态（保守：必须是 user:pass 且长度合理）
_CRED_RE = re.compile(r"\b([a-zA-Z0-9_.\-]{2,32})\s*[:/]\s*([^\s:/]{4,64})\b")


# =============================================================================
# verifier
# =============================================================================

def facts_from_verifier(
    result: Dict[str, Any],
    *,
    current_url: str = "",
    round_no: int = 0,
    evidence: str = "",
) -> List[Dict[str, Any]]:
    """
    从 verifier 的 LLM 输出抽取 facts

    Args:
        result: verifier 解析后的 JSON（LLM 原始输出）
        current_url: 当前 URL
        round_no: 当前轮次
        evidence: 攻击证据（exploit_evidence 字段）

    Returns:
        facts 列表（可能为空）
    """
    if not isinstance(result, dict):
        return []

    facts: List[Dict[str, Any]] = []
    common = dict(source="verifier", url=current_url, round_no=round_no)

    # 1. LLM 显式给出的结构化事实（verifier prompt 的 new_facts 字段）
    for raw in _as_list(result.get("new_facts")):
        fact = _fact_from_llm_item(raw, evidence=evidence, **common)
        if fact:
            facts.append(fact)

    # 2. flag —— 最高价值，用两条独立路径捕获，任何一条命中即记录
    #    路径 A: LLM 明确判定 found_flag（最可信）
    #    路径 B: 证据文本里出现 flag 形态（兜底）
    #
    #    为什么需要路径 B: LLM 可能漏判 found_flag（误报为失败），而 CTF 里漏掉 flag
    #    的代价极高。make_fact 的 id 幂等，重复捕获不会产生冗余项，所以宁可多扫一遍。
    #    同时这也修了既有缺陷: ctf_agent_graph.py:2549-2558 的 found_flag 提前 return
    #    路径原本根本不写 known_facts，导致命中 flag 那轮的情报整体丢失。
    flag_value = ""
    if result.get("found_flag"):
        flag_value = (result.get("potential_flag") or "").strip()
    if not flag_value:
        haystack = " ".join(str(result.get(k, "")) for k in
                            ("exploit_evidence", "updated_known_facts", "failure_analysis"))
        m = _FLAG_RE.search(haystack)
        if m:
            flag_value = m.group(1)
    if flag_value:
        facts.append(make_fact(
            FactKind.FLAG,
            flag_value,
            f"获得 flag: {flag_value}",
            evidence=evidence,
            confidence=1.0,
            **common,
        ))

    # 3. 已确认可利用的漏洞
    if result.get("is_exploit_successful"):
        desc = (result.get("exploit_evidence") or "").strip()[:300]
        if desc:
            facts.append(make_fact(
                FactKind.VULN,
                f"{current_url}:{_short_hash(desc)}",
                f"已确认漏洞: {desc}",
                evidence=evidence,
                confidence=0.85,
                **common,
            ))

    # 4. 兜底: LLM 给了自由文本情报（updated_known_facts）但没给结构化事实时，
    #    转成一条 note fact。因为写入侧是「二选一」（黑板开则不写字符串字段），
    #    没有这个兜底，这段情报会直接丢失。
    if not facts:
        note = str(result.get("updated_known_facts", "") or "").strip()
        if note:
            facts.append(make_fact(
                FactKind.NOTE,
                _short_hash(note),
                note[:300],
                evidence=evidence,
                confidence=0.6,
                **common,
            ))

    return facts


# =============================================================================
# analyst
# =============================================================================

def facts_from_candidates(
    candidates: List[Dict[str, Any]],
    *,
    current_url: str = "",
    round_no: int = 0,
    min_confidence: float = 0.6,
) -> List[Dict[str, Any]]:
    """
    从 analyst 的 vuln_candidates 抽取「疑似漏洞」facts

    只收置信度达标的候选，避免把猜测当事实。低置信度的候选仍留在
    state['vuln_candidates'] 里供后续流程使用，只是不进黑板。
    """
    facts: List[Dict[str, Any]] = []
    for cand in _as_list(candidates):
        if not isinstance(cand, dict):
            continue
        try:
            conf = float(cand.get("confidence", 0.0) or 0.0)
        except (TypeError, ValueError):
            continue
        if conf < min_confidence:
            continue

        vtype = str(cand.get("type", "") or "").strip()
        location = str(cand.get("location", "") or "").strip()
        url = str(cand.get("url", "") or current_url).strip()
        if not vtype:
            continue

        facts.append(make_fact(
            FactKind.VULN,
            f"{vtype}:{location}:{url}",
            f"疑似 {vtype} @ {location or url}",
            evidence=str(cand.get("context", ""))[:300],
            confidence=conf,
            source="analyst",
            url=url,
            round_no=round_no,
        ))
    return facts


# =============================================================================
# 通用: 凭据 / 死路
# =============================================================================

def facts_from_credentials(
    credentials: List[Dict[str, Any]],
    *,
    url: str = "",
    round_no: int = 0,
) -> List[Dict[str, Any]]:
    """
    从 credentials 抽取凭据 facts（内网模块使用）

    ⚠️ 注意: 凭据是敏感信息，描述里**不落明文密码**，只落用户名与来源，
    明文由 memory/credentials.json 单独管理。
    """
    facts: List[Dict[str, Any]] = []
    for cred in _as_list(credentials):
        if not isinstance(cred, dict):
            continue
        user = str(cred.get("username", "") or cred.get("user", "") or "").strip()
        host = str(cred.get("host", "") or cred.get("target", "") or url).strip()
        if not user:
            continue
        facts.append(make_fact(
            FactKind.CREDENTIAL,
            f"{user}@{host}",
            f"获得凭据: {user} @ {host}",
            evidence=str(cred.get("source", ""))[:200],
            confidence=0.9,
            source="credential_manager",
            url=host,
            round_no=round_no,
        ))
    return facts


def facts_from_deadend(
    description: str,
    *,
    current_url: str = "",
    round_no: int = 0,
    source: str = "",
) -> List[Dict[str, Any]]:
    """
    记录一个已证伪的方向

    这类事实价值分低（0.2）但**极为重要**——它直接告诉后续轮次「别再试这条路」，
    且 reducers 的截断逻辑专门保护它不被丢弃。
    """
    desc = (description or "").strip()
    if not desc:
        return []
    return [make_fact(
        FactKind.DEADEND,
        desc[:120],
        f"已证伪: {desc[:200]}",
        confidence=0.8,
        source=source or "unknown",
        url=current_url,
        round_no=round_no,
    )]


# =============================================================================
# 内部辅助
# =============================================================================

def _as_list(value: Any) -> List[Any]:
    """把任意输入安全地转成列表"""
    if isinstance(value, list):
        return value
    if isinstance(value, dict):
        return [value]
    return []


def _short_hash(text: str) -> str:
    """取文本的短哈希，用于构造稳定的 fact key"""
    import hashlib
    return hashlib.md5(text.encode("utf-8", errors="ignore")).hexdigest()[:8]


def _fact_from_llm_item(
    raw: Any,
    *,
    evidence: str = "",
    **common,
) -> Optional[Dict[str, Any]]:
    """
    把 LLM 输出的单条 new_facts 转成 fact dict

    严格校验: kind 必须在白名单内、description 非空。任何不合规的条目直接丢弃
    （宁可不记，也不让脏数据污染黑板）。
    """
    if not isinstance(raw, dict):
        return None

    kind = str(raw.get("kind", "") or "").strip().lower()
    description = str(raw.get("description", "") or "").strip()
    if kind not in _ALLOWED_LLM_KINDS or not description:
        return None

    try:
        confidence = float(raw.get("confidence", 0.8))
    except (TypeError, ValueError):
        confidence = 0.8
    confidence = min(1.0, max(0.0, confidence))

    # key 优先用 LLM 给的 key，否则退化为描述哈希（保证同一条事实幂等）
    key = str(raw.get("key", "") or "").strip() or _short_hash(f"{kind}|{description}")

    return make_fact(
        kind,
        key,
        description[:300],
        evidence=str(raw.get("evidence", "") or evidence)[:300],
        confidence=confidence,
        **common,
    )
