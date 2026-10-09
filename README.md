<div align="center">

# CTF-Agent

**基于 LangGraph + 黑板架构的智能 CTF 自动化解题系统**

从信息侦察到漏洞利用的全流程自主渗透代理

[![Python](https://img.shields.io/badge/Python-3.10%2B-3776AB?logo=python&logoColor=white)](https://www.python.org/)
[![LangGraph](https://img.shields.io/badge/LangGraph-0.2%2B-1C3C3C?logo=langchain&logoColor=white)](https://github.com/langchain-ai/langgraph)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](./LICENSE)
[![Tools](https://img.shields.io/badge/集成工具-69-orange.svg)](#-工具生态)
[![Directions](https://img.shields.io/badge/CTF方向-8-blue.svg)](#-八大方向)

</div>

---

## 📖 简介

**CTF-Agent** 是一个 LLM 驱动的自动化渗透测试代理。它把渗透测试建模为**在未知状态空间中的有向搜索**——起点（目标）已知、终点（flag）明确、路径未知——通过多节点协同与黑板架构逐步逼近目标。

系统覆盖 **8 大 CTF 方向**，集成 **69 个安全工具**，支持从单点 Web 漏洞到多层内网渗透的完整链路。

> ⚠️ **仅供授权环境使用**：CTF 竞赛、靶场、已获书面授权的渗透测试。使用前请确认你拥有对目标的操作授权。

---

## ✨ 核心特性

<table>
<tr><td width="50%" valign="top">

### 🧠 黑板架构
- **Fact / Intent / Hint** 三原语
- 事实结构化（12 种类型），支持查询与技能匹配
- 图分析（PageRank）自动计算探索优先级
- 幂等合并：重复发现自动去重并提升置信度

</td><td width="50%" valign="top">

### 🎯 技能库
- YAML frontmatter + Markdown 的**攻击手法单元**
- 按技术栈/事实类型/关键词自动匹配
- 每个技能带**失败信号**，知道何时该换打法
- 可扩展：新增 `.md` 即新增技能

</td></tr>
<tr><td valign="top">

### 🤖 AI 驱动决策
- 所有决策节点由 LLM 驱动，避免硬编码流程
- 工具实测证伪：LLM 的推测必须经真实回包验证
- 失败分累积自动触发模式切换（exploit → explore → innovate）

</td><td valign="top">

### 🔬 差分检测
- MD5 内容比对识别页面变化
- **时间盲注检测**：内容不变但耗时异常 → 识别成功的盲注
- 大响应体自动落盘，不撑爆上下文

</td></tr>
</table>

---

## 🗺️ 八大方向

| 方向 | 核心模块 | 关键节点 |
|------|---------|---------|
| **Web** | `app/ctf_agent_graph.py` | `recon` `analyst` `attacker` `verifier` `innovator` |
| **内网渗透** | `internal_network/nodes.py` | `post_exploit` `internal_recon` `lateral_move` `privilege_escalation` |
| **密码学** | `crypto/nodes.py` | `crypto_analyst` `crypto_solver` |
| **Pwn** | `pwn/nodes.py` | `pwn_analyst` `pwn_exploiter` |
| **逆向** | `reverse/nodes.py` | `reverse_analyst` `reverse_decompiler` |
| **Misc** | `misc/nodes.py` | `misc_analyst` `misc_extractor` |
| **AI 安全** | `ai_security/nodes.py` | `ai_analyst` `model_attacker` |
| **云安全** | `cloud_security/nodes.py` | `cloud_recon` `cloud_exploit` |

---

## 🏗️ 架构

### 执行流（LangGraph）

```
                        ┌──────────────────┐
                        │  challenge_type  │
                        │    _detector     │
                        └────────┬─────────┘
                                 │
              ┌──────────────────┼──────────────────┐
              ▼                  ▼                  ▼
          [ Web CTF ]       [ 内网渗透 ]        [ 其他方向 ]
              │                  │                  │
      recon → analyst      post_exploit        crypto/pwn/...
         │       │              │              reverse/misc/...
         ▼       ▼              ▼              cloud/ai
      attacker → verifier   lateral_move
         │          │       privilege_escalation
         └──────────┤              │
                    ▼              ▼
              [ evolve ]      [ flag_search ]
                    │
                   END
```

### 黑板层（本项目新增）

黑板**叠加**在流程之上，不替代流程——它决定「**我看到了什么**」和「**接下来值得做什么**」：

```
   ┌─────────────────────────────────────────────┐
   │              黑  板（共享事实区）             │
   │  facts:   [tech, vuln, credential, ...]     │
   │  intents: [待探索方向（带优先级）]            │
   └────┬───────────────────────────────▲────────┘
        │ 读（投影 top-N）               │ 写（提议新事实）
        ▼                               │
   ┌─────────┐      行动      ┌─────────┴───────┐
   │attacker │ ─────────────> │    verifier     │
   └─────────┘                └─────────────────┘
        ▲                             │
        │ 读（该打哪个方向）           │ 算（重算优先级/匹配技能）
        │                             ▼
   ┌────┴────┐                ┌─────────────┐
   │ intents │ <───────────── │  board_node │
   └─────────┘     产出        └─────────────┘
```

**三个原语**：

| 原语 | 含义 | 谁产生 |
|------|------|--------|
| **Fact** | 已确认的客观发现（12 种类型） | recon / analyst / verifier |
| **Intent** | 已声明、待执行的探索方向 | analyst / 图分析 |
| **Hint** | 人类中途注入的判断 | 人 |

**为什么这样设计**：信息不再随流程流失，决策有了全局视野，重复观察自动变成交叉验证。

---

## 🚀 快速开始

### 环境要求

- Python **3.10+**
- Docker（可选，**推荐** —— 第三方工具已打包）

### 方式一：Docker（推荐）

```bash
git clone https://github.com/wsx138/CAPAgent.git
cd CAPAgent

cp config.yaml.example config.yaml
vim config.yaml          # 填入 LLM_API_KEY

docker-compose up -d --build
docker logs -f ctf-agent

# 访问 http://localhost:54565/fisher_ctf_agent/monitor
```

### 方式二：本地运行

```bash
pip install -r requirements.txt

cp config.yaml.example config.yaml
vim config.yaml          # 填入 LLM_API_KEY

# Windows
start_web.bat

# Linux / macOS
./start_web.sh
```

### 方式三：命令行

```bash
# 非交互模式：跑完一道题即退出
python app/ctf_agent_graph.py --target http://target.com

# 交互模式：连续出题
python app/ctf_agent_graph.py
```

### 最小配置

```yaml
# config.yaml
LLM_API_KEY: "sk-your-key"
LLM_BASE_URL: "https://api.deepseek.com/v1"

ANALYST_MODEL: "deepseek-chat"
ATTACKER_MODEL: "deepseek-chat"
VERIFIER_MODEL: "deepseek-chat"
```

---

## 🖥️ Web UI

启动后访问 `http://<host>:54565/fisher_ctf_agent/`

| 页面 | 路径 | 功能 |
|------|------|------|
| **控制台** | `/monitor` | 任务管理、实时日志流（SSE）、节点状态 |
| **模块** | `/modules` | 启用/禁用功能模块与工具 |
| **拓扑** | `/topology` | 站点结构可视化、关键节点、攻击路径 |
| **黑板** | `/board` | 事实/意图/技能命中查看 |

> 安全提示：服务**无默认首页**，必须使用完整路径访问。

---

## 🔧 工具生态

**69 个集成工具**，按用途分类：

| 分类 | 工具 |
|------|------|
| 漏洞扫描 | `nuclei` `xray` `fscan` `nmap` `cve-scanner` |
| 注入攻击 | `sqlmap` `fenjing`(SSTI) `dalfox`(XSS) `xxe-injector` |
| 反序列化 | `ysoserial` `phpggc` `marshalsec` `pickle-pwn` `phar-gen` |
| 内网渗透 | `impacket` 系列 `crackmapexec` `mimikatz` `msf` |
| 域渗透 | `bloodhound` `petitpotam` `rubeus` |
| 权限提升 | `potato` `privesc` |
| SSRF | `ssrfmap` `gopherus` `ssrf-scanner` |
| 目录/资产 | `dirsearch` `ffuf` `subfinder` `httpx` `jsfinder` |
| OA 漏洞 | `oa-exploiter` `ajp-shooter` |
| 隧道/代理 | `frp-manager` |
| 云/容器 | `cloud-scanner` `container-escape-checker` |
| AI 攻击 | `ai-attacker` |
| 其他 | `hydra` `jwt-tool` `flask-unsign` `jndi-exploit` `git-hacker` `db-attacks` |

### 🎓 技能库

`skills/` 目录下的攻击手法单元（Markdown + YAML frontmatter）：

```markdown
---
name: php-filter-chain
description: PHP filter chain 盲注（无回显场景）
triggers:
  tech_stack: [php]
  fact_kinds: [vuln]
  keywords: [文件包含, LFI, php://filter]
tools: [php-filter-chain]
cost: medium
---
## 适用条件
## 步骤
## 验证
## 失败信号
```

内置：`php-filter-chain` · `jinja2-ssti` · `sql-injection` · `ssrf-gopher` · `php-unserialize`

**新增技能只需放入一个 `.md` 文件。**

---

## 📁 目录结构

```
CAPAgent/
├── app/                        # 核心
│   ├── ctf_agent_graph.py      # 主程序入口 / LangGraph 图定义
│   ├── state_v2.py             # 状态定义（含黑板通道）
│   ├── board/                  # 黑板：事实-意图-技能
│   │   ├── models.py           #   Fact / Intent / Hint 数据模型
│   │   ├── reducers.py         #   幂等合并规约器
│   │   ├── extractors.py       #   从节点输出抽取事实
│   │   ├── analyzer.py         #   图分析 → 优先级
│   │   └── router_bridge.py    #   黑板路由决策
│   ├── skills/                 # 技能库加载与匹配
│   ├── topology/               # 站点拓扑 / 差分检测 / 剪枝
│   ├── router.py               # 节点路由
│   ├── llm_client.py           # LLM 客户端（限流/重试）
│   └── tool_framework.py       # 工具框架基类
├── skills/                     # 技能定义（Markdown）
├── tools/                      # 69 个安全工具封装
├── internal_network/           # 内网渗透模块
├── crypto/ pwn/ reverse/ misc/ # 各方向模块
├── ai_security/ cloud_security/
├── remote_executor/            # 远程执行 / 会话 / 隧道
├── memory/                     # 三层记忆管理
├── rag_builder/                # RAG 检索（历史 writeup）
├── web/                        # Web UI（Flask + Vue3）
├── thirdparty/                 # 第三方工具二进制
├── tests/                      # 单元测试
├── Dockerfile
├── docker-compose.yml
└── config.yaml.example
```

---

## ⚙️ 配置说明

```yaml
# ── LLM ──────────────────────────────
LLM_API_KEY: "sk-xxx"
LLM_BASE_URL: "https://api.deepseek.com/v1"
ANALYST_MODEL: "deepseek-chat"      # 分析：需强推理
ATTACKER_MODEL: "deepseek-chat"     # 攻击：需代码生成
VERIFIER_MODEL: "deepseek-chat"     # 验证：需长文本阅读

# ── 超时 ─────────────────────────────
NODE_TIMEOUT: 1800                  # 单节点 30 分钟
TASK_TIMEOUT: 1200                  # Web CTF 20 分钟
INTERNAL_TASK_TIMEOUT: 3000         # 内网渗透 50 分钟

# ── VPS（内网渗透必需）────────────────
LOCAL_PUBLIC_IP: "x.x.x.x"          # 反弹 shell / 隧道用
HTTP_SERVER_PORT: 8000
FRP_SERVER_PORT: 7000
FRP_SOCKS5_PORT: 10800

# ── 模式切换阈值 ──────────────────────
FAILURE_SCORE_FOR_EXPLORE: 5.0
FAILURE_SCORE_FOR_INNOVATE: 10.0

# ── 黑板（可选，默认关闭）──────────────
ENABLE_BOARD: false                 # 启用事实-意图黑板
ENABLE_BOARD_ROUTING: false         # 启用黑板路由覆盖
```

> **渐进启用**：黑板默认关闭时，行为与未引入时完全一致，可随时开关对比。

---

## 🛠️ 开发指南

### 添加新工具

```python
# tools/my_tool.py
from tool_framework import CommandLineTool

class MyTool(CommandLineTool):
    def name(self) -> str:
        return "my-tool"

    def description(self) -> str:
        return "工具用途说明（会展示给 LLM）"

    def supported_vulns(self) -> list:
        return ["SQL Injection"]

    def get_command(self, target: str, params: dict) -> str:
        return f"my-tool -t {target}"
```

`tools/__init__.py` 会自动扫描并注册，无需手动登记。

### 添加新技能

在 `skills/` 下新建 `.md`，编写 YAML frontmatter + 正文即可：

```markdown
---
name: my-skill
description: 一句话描述
triggers:
  tech_stack: [java]
  keywords: [反序列化]
tools: [ysoserial]
cost: medium
---
## 适用条件
## 步骤
## 验证
## 失败信号
```

### 运行测试

```bash
pip install -r requirements-dev.txt
pytest tests/ -q
```

---

## ⚠️ 安全注意

- **API Key 保护**：`config.yaml` 已在 `.gitignore` 中，切勿提交
- **授权使用**：仅在 CTF 竞赛 / 靶场 / 已获书面授权的环境使用
- **数据敏感**：`data/`、`.memory/` 含攻击过程数据，已排除出版本控制
- **爆炸半径**：避免对生产系统执行破坏性操作（删库、批量导出、清库存等）

---

## 📄 License

本项目基于 [MIT License](./LICENSE) 开源。

Copyright (c) 2026 Cyber Range Lab

---

<div align="center">

**致谢**：LangGraph · DeepSeek / OpenAI · 各开源安全工具作者

</div>
