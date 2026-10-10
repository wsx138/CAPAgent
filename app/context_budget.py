# app/context_budget.py
"""
上下文预算与「读取时投影」

## 为什么不用现成的压缩器

`app/context_compressor.py` 写得很完整（按信息价值分级），但从未接通，原因是
它的用法与 LangGraph 的语义**天然冲突**：

    压缩器:  返回「压缩后的完整 state」→ 调用方拿它覆盖 state
    LangGraph: 节点返回的是**增量**，由 reducer 合并

如果直接拿压缩结果去覆盖，会把增量语义破坏掉（未提及的字段会被当作删除）。
更麻烦的是压缩会**丢字段**，而 reducer 的追加语义又会把丢掉的东西加回来 ——
两者会持续打架。

所以本模块换一个思路：**只投影、不改写**。

    project_state(state) → 返回浅拷贝（供构造 prompt 用）
                          ↑ 原 state 一个字节都不动

这与黑板的 `render_known_facts`（读取时投影 top-40）是同一哲学，
区别是黑板覆盖 `facts` 通道，本模块覆盖其余字段（原先靠散装截断的那部分）。
"""

import logging
from typing import Any, Dict, Optional

logger = logging.getLogger(__name__)

# 与项目其它地方保持一致的估算系数（中文约 1.5 字符/token、英文约 4，
# 取保守值 2.5）
CHARS_PER_TOKEN = 2.5

# 单次 prompt 的估算 token 警戒线
# 对应 config.MAX_CONTEXT_TOKENS 的默认值
DEFAULT_WARN_TOKENS = 30000


def estimate_tokens(text: str) -> int:
    """按字符数估算 token（不依赖 tiktoken）"""
    if not text:
        return 0
    return int(len(str(text)) / CHARS_PER_TOKEN)


def project_state(state: Dict[str, Any], *, purpose: str = "generic") -> Dict[str, Any]:
    """
    读取时投影：返回一个用于构造 prompt 的**浅拷贝**

    ⚠️ **不修改原 state**。这是与旧压缩器的根本区别，也是它安全的原因。

    裁剪规则完全复用 context_compressor 的 FIELD_PRIORITY 分级:
      CRITICAL → 原样保留（凭据/flag/shell）
      HIGH     → 去重 + 限量
      MEDIUM   → 去重 + 截断
      LOW      → 只留成功 + 统计

    Args:
        state:   原状态（不会被修改）
        purpose: 投影用途标签，仅用于日志定位

    Returns:
        投影后的浅拷贝字典
    """
    if not isinstance(state, dict):
        return {}

    try:
        from context_compressor import FIELD_PRIORITY, Priority, get_compressor
    except ImportError:
        # 压缩器模块不可用时退化为原样返回（不影响功能）
        return dict(state)

    comp = get_compressor()
    out: Dict[str, Any] = {}

    for key, value in state.items():
        priority = FIELD_PRIORITY.get(key, Priority.MEDIUM)
        try:
            if priority == Priority.CRITICAL:
                out[key] = value                      # 原样，绝不裁剪
            elif priority == Priority.HIGH:
                out[key] = comp._compress_high(key, value)
            elif priority == Priority.MEDIUM:
                out[key] = comp._compress_medium(key, value)
            else:
                out[key] = comp._compress_low(key, value)
        except Exception as e:
            # 单个字段投影失败不能让整个 prompt 构造失败
            logger.debug("[Budget] 字段 %s 投影失败，保留原值: %s", key, e)
            out[key] = value

    return out


def check_budget(prompt: str, *, label: str = "",
                 warn_tokens: int = DEFAULT_WARN_TOKENS) -> Dict[str, Any]:
    """
    检查 prompt 的 token 预算，超警戒线时告警

    项目此前**没有任何事前预算控制**——token_stats 只做事后统计，
    等发现超限时请求已经失败了。

    Args:
        prompt:      待检查的 prompt 全文
        label:       用途标签（如 "attacker"/"verifier"），用于日志定位
        warn_tokens: 警戒线

    Returns:
        {"tokens": int, "chars": int, "over_budget": bool}
    """
    chars = len(prompt) if prompt else 0
    tokens = estimate_tokens(prompt)
    over = tokens > warn_tokens

    if over:
        logger.warning(
            "[Budget] prompt 超出预算: %s = %d tokens (>%d)，字符数 %d。"
            "若模型上下文较小可能触发超限错误。",
            label or "unknown", tokens, warn_tokens, chars,
        )

    return {"tokens": tokens, "chars": chars, "over_budget": over}


def project_and_check(state: Dict[str, Any], prompt_builder,
                      *, label: str = "", warn_tokens: int = DEFAULT_WARN_TOKENS):
    """
    便捷组合：先投影 state，再构造 prompt，最后检查预算

    Args:
        state:         原状态
        prompt_builder: 接收投影后 state 的函数，返回 prompt 字符串
        label:         用途标签

    Returns:
        (prompt, projected_state, budget_info)
    """
    projected = project_state(state, purpose=label)
    prompt = prompt_builder(projected)
    info = check_budget(prompt, label=label, warn_tokens=warn_tokens)
    return prompt, projected, info


__all__ = ["project_state", "check_budget", "project_and_check",
           "estimate_tokens", "CHARS_PER_TOKEN", "DEFAULT_WARN_TOKENS"]
