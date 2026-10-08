---
name: sql-injection
description: SQL 注入——从探测到数据提取，含 WAF 绕过
triggers:
  tech_stack: [php, java, python, asp, nodejs, mysql, postgresql, mssql, oracle]
  fact_kinds: [vuln, input_point]
  keywords: [SQL, 注入, id=, 查询, 搜索, 排序, order by, 报错]
  scene: web
tools: [sqlmap]
cost: medium
---

## 适用条件

- 存在把用户输入拼进 SQL 的点：查询参数、搜索框、排序字段、JSON body、Header（X-Forwarded-For 常被记录进库）
- **有差分面**：参数变化导致回包条数/内容/耗时变化，或出现数据库报错

**注意**：只回"请登录"、无任何业务字段的接口不在此列，那通常不是注入点。

## 步骤

1. **手工初判**（比直接上工具快）：
   - 单引号：`?id=1'` → 报错 / 500 / 回包变化
   - 布尔：`?id=1 and 1=1` vs `?id=1 and 1=2` → 回包是否不同
   - 数字型：`?id=1-0` / `?id=2-1` → 等价钱后结果是否一致
   - 排序：`?order=id` → `?order=(select 1)` 
2. **按技术栈选探针**：
   - MySQL/PG/MSSQL：上面的经典手法
   - **MongoDB / JSON body**：改用操作符 `{"user": {"$ne": null}}`、`{"$gt": ""}`
   - **搜索框**：优先测 ES/DSL 或 `OR 1=1` + 观察 total 数
3. **交给工具**：
   ```
   sqlmap -u "http://target/page?id=1" --batch --dbs
   ```
   有 Cookie/Token 时带 `--cookie` / `--headers`；POST 用 `--data`。
4. **WAF 绕过**（工具报大量 403 时）：
   - 换编码：`%0a`、`%0d`、双写、注释 `/**/`、大小写混用
   - **换位置**：从 query 换到 JSON body / Header / path
   - 降速：`--delay=2 --random-agent`

## 验证

- **布尔/时间盲注**：固定条件下回包稳定，加入 `and sleep(5)` 后响应时间明显增加
- **报错注入**：回包出现数据库版本/路径（如 `XPATH syntax error`）
- **联合查询**：`order by N` 逐步加直到报错，定位列数后 `union select` 出数据
- **实证**：能拖出 `information_schema.tables` 或实际业务表的一行数据

## 失败信号

- 单引号原样回显且布尔/时间均无差分 → **不是注入点**，换参数或换注入类型
- 全部请求被 WAF 拦截（403/406），换编码与换位置后仍拦截 → 考虑改用**业务逻辑漏洞**或从其他参数入手
- 目标是预编译语句（如 MyBatis `#{}`）且无二次注入点 → 通常无注入，转 XSS / 越权方向
- 数据库账号权限极低（只能读当前库）→ 仍可出数据，不要因"看不到别的库"就放弃

**替代方向**：转 `db-attacks`（UDF/写文件提权）；若是 NoSQL，用操作符注入；若有回显但无注入，转 XSS。
