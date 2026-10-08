---
name: jinja2-ssti
description: Jinja2 模板注入——从探测到 RCE 的完整链路
triggers:
  tech_stack: [flask, jinja2, python]
  fact_kinds: [vuln, input_point]
  keywords: [SSTI, 模板注入, template, "{{", render_template, Flask]
  scene: web
tools: [fenjing]
cost: medium
---

## 适用条件

- 目标是 Python Web（Flask / Django 的 `Template` / Tornado / 直接用户可控模板）
- 存在把用户输入拼进模板再渲染的点：`render_template_string(user_input)`、错误页回显、邮件模板、报表导出
- 页面出现 `{{ }}`、`{% %}` 语法痕迹，或渲染后内容随输入变化

**判据**：输入 `{{7*7}}`，回包出现 `49` 即确认存在 SSTI。

## 步骤

1. **探测**：在可疑参数打 `{{7*7}}`、`${7*7}`、`#{7*7}`、`<%= 7*7 %>`，覆盖 Jinja2/Twig/Freemarker/ERB 几种语法。
2. **确认 Jinja2**：`{{7*'7'}}` 返回 `7777777`（Jinja2/Python 语义），而非 Twig 的 `49`。
3. **交给工具自动利用**：
   ```
   fenjing crack --url "http://target/page?name=*" --method GET
   ```
   工具会自动探测 WAF 规则、生成绕过 payload，并在可执行时直接给 shell。
4. 若要手工构造，经典链是沿 `__class__.__mro__` / `__globals__` 找 `os.popen` 或 `subprocess.Popen`。

## 验证

- 命令执行：payload 里带 `id` / `whoami`，回包出现命令输出
- 文件读取：`{{ ''.__class__.__mro__[1].__subclasses__() }}` 能列出子类（说明沙箱可逃逸）
- 反弹 shell：`fenjing` 可直接生成反弹 payload，用目标可达的 IP

## 失败信号

- `{{7*7}}` 原样回显（未渲染）→ **不是模板注入**，是普通参数，换方向
- 回显 `49` 但 `{{7*'7'}}` 也返回 `49` → 可能是 **Twig（PHP）** 而非 Jinja2，改用 Twig 语法链
- 大量关键字（`__class__`、`os`、`eval`）被过滤且工具生成的 payload 也全 403 → 目标有 WAF 且规则较严，考虑 `attr()` 过滤器拼接或 unicode 绕过
- 渲染点在邮件/报表等**异步**通道 → 无同步回显，改盲注（时间差 / 外带 DNS）

**替代方向**：换 `fenjing` 的 blind 模式；若确认是 Twig，转 PHP 手法（`phpggc`）；若是 Freemarker，用 `<#assign>` 语法链。
