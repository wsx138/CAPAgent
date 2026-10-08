# app/board/models.py
"""
黑板数据模型

三个原语（借鉴 Cairn 的 Blackboard Architecture，并做结构化增强）:

- Fact:      已确认的客观发现。相比 Cairn 的纯文本 Fact，增加了 kind（可查询、
             可匹配技能）、evidence（长内容外置）、confidence、value_score。
- Intent:    已声明但未执行的探索方向。相比 Cairn（无优先级、只能按 created_at
             取最新），增加了 priority（由图分析计算）、skill（引用的技能）。
- BoardHint: 人工注入的判断。

设计约束（见实施计划）:
- state 里只存纯 dict；dataclass 仅作为内部使用者的友好包装，提供 to_dict/from_dict。
  原因: 项目所有状态结构（VulnerabilityCandidate/AttackAction/PageFeatures）均为
  TypedDict，现有 reducer 全部基于 dict 操作（reducers.py:89 的 c.get(...)）。
- 不用 pydantic: 项目里 pydantic 只用于图分析内部（app/topology/models.py），从不进 state。
- 本类**故意不叫 Hint**，避免与 app/state_types/web.py:95 已有的 Hint TypedDict 撞名。
"""

from dataclasses import dataclass, field, asdict
from typing import Any, Dict, List, Optional
import time


# =============================================================================
# Fact 类型（kind）取值
# =============================================================================

class FactKind:
    """Fact 的类别。决定该事实能匹配哪些技能、以及在 prompt 里如何分组。"""
    TECH = "tech"                 # 技术栈/框架/中间件
    SERVICE = "service"           # 服务/端口/协议
    INPUT_POINT = "input_point"   # 可控输入点（参数、表单、header）
    PATH = "path"                 # 敏感路径
    DATA_PATTERN = "data_pattern" # 数据特征（JWT、序列化、Base64…）
    VULN = "vuln"                 # 已确认/疑似漏洞
    CREDENTIAL = "credential"     # 凭据
    ACCESS = "access"             # 访问能力（shell、后台、越权）
    FLAG = "flag"                 # 目标达成物
    DEADEND = "deadend"           # 已证伪的方向（避免重复尝试）
    ASSET = "asset"               # 资产（主机、域名、内网主机）
    NOTE = "note"                 # 自由文本情报（LLM 给出但尚未结构化的观察，兜底用）


# 高价值 kind：这些事实在 prompt 注入时优先
HIGH_VALUE_KINDS = frozenset({
    FactKind.CREDENTIAL, FactKind.ACCESS, FactKind.FLAG, FactKind.VULN,
})

# 默认价值分（analyzer 会在此基础上调整）
DEFAULT_VALUE_SCORE = {
    FactKind.FLAG: 1.0,
    FactKind.ACCESS: 0.95,
    FactKind.CREDENTIAL: 0.9,
    FactKind.VULN: 0.8,
    FactKind.ASSET: 0.6,
    FactKind.TECH: 0.5,
    FactKind.SERVICE: 0.5,
    FactKind.INPUT_POINT: 0.6,
    FactKind.PATH: 0.6,
    FactKind.DATA_PATTERN: 0.55,
    FactKind.DEADEND: 0.2,
    FactKind.NOTE: 0.4,
}


def default_value_score(kind: str) -> float:
    """按 kind 取默认价值分"""
    return DEFAULT_VALUE_SCORE.get(kind, 0.5)


# =============================================================================
# Fact
# =============================================================================

@dataclass
class Fact:
    """
    已确认的客观发现

    Attributes:
        id: 唯一标识，建议按 kind 构造便于去重，如 'tech:php:7.4'、'cred:admin:admin123'
        kind: 类别，见 FactKind
        description: 客观描述（一句话，不含推测）
        evidence: 证据（文件路径或命令摘要）；长内容应落盘后在此引用路径
        confidence: 置信度 0-1
        source: 产出该事实的节点名
        url: 归属 URL（可为空）
        round_no: 第几轮产出
        value_score: 价值分 0-1，由 analyzer 计算，影响 prompt 注入排序
        created_at: 时间戳
    """
    id: str
    kind: str
    description: str
    evidence: str = ""
    confidence: float = 1.0
    source: str = ""
    url: str = ""
    round_no: int = 0
    value_score: float = 0.0
    created_at: float = field(default_factory=time.time)

    def __post_init__(self):
        # 未显式指定价值分时，按 kind 取默认值
        if not self.value_score:
            self.value_score = default_value_score(self.kind)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Fact":
        known = {f for f in cls.__dataclass_fields__}
        return cls(**{k: v for k, v in data.items() if k in known})


# =============================================================================
# Intent
# =============================================================================

class IntentStatus:
    """Intent 状态机。注意 status 只允许前进，不允许回退（见 reducers.upsert_intents_reducer）。"""
    PENDING = "pending"           # 待认领
    IN_PROGRESS = "in_progress"   # 已认领执行中
    DONE = "done"                 # 已完成（产出 fact）
    FAILED = "failed"             # 已失败
    ABANDONED = "abandoned"       # 已放弃


# 状态推进顺序（用于 reducer 里阻止状态回退）
INTENT_STATUS_ORDER = {
    IntentStatus.PENDING: 0,
    IntentStatus.IN_PROGRESS: 1,
    IntentStatus.DONE: 2,
    IntentStatus.FAILED: 2,
    IntentStatus.ABANDONED: 2,
}


@dataclass
class Intent:
    """
    已声明但未执行的探索方向

    Attributes:
        id: 唯一标识
        sources: 该意图从哪些 fact 推导而来（对应 Cairn 的 intent.from）
        description: 探索方向描述
        skill: 引用的技能名（可为空）；attacker 消费时据此加载对应手法
        priority: 优先级 0-1，由 analyzer 计算
        cost: 预估成本 low|medium|high
        status: 见 IntentStatus
        claimed_by: 认领者（节点名）
        created_at: 时间戳
    """
    id: str
    description: str
    sources: List[str] = field(default_factory=list)
    skill: Optional[str] = None
    priority: float = 0.5
    cost: str = "medium"
    status: str = IntentStatus.PENDING
    claimed_by: Optional[str] = None
    created_at: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Intent":
        known = {f for f in cls.__dataclass_fields__}
        return cls(**{k: v for k, v in data.items() if k in known})


# =============================================================================
# BoardHint
# =============================================================================

@dataclass
class BoardHint:
    """
    人工注入的判断

    与 app/state_types/web.py:95 的 Hint 区分: 那个 Hint 已经接在 hint_history 上，
    本类用于黑板上下文里的人类纠偏。
    """
    id: str
    content: str
    author: str = "human"
    created_at: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "BoardHint":
        known = {f for f in cls.__dataclass_fields__}
        return cls(**{k: v for k, v in data.items() if k in known})
