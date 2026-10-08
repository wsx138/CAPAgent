---
name: ssrf-gopher
description: SSRF 利用——用 Gopher 协议打内网服务（Redis/MySQL/FastCGI）
triggers:
  tech_stack: [php, java, python, nodejs]
  fact_kinds: [vuln, input_point]
  keywords: [SSRF, url=, callback, webhook, fetch, proxy, 内网, 请求转发]
  scene: web
tools: [gopherus, ssrfmap, ssrf-scanner]
cost: high
---

## 适用条件

- 存在服务端发起请求的参数：`url=`、`callback=`、`webhook=`、`image=`、`proxy=`、`import=`、`preview=`、`fetch=`
- 服务端能访问内网（CTF 场景下几乎总是）
- 目标可用的协议不止 http（能发 `gopher://`、`dict://`、`file://` 更佳）

## 步骤

1. **确认 SSRF**：
   - 外带验证：参数填自己控制的 HTTP 地址，看是否收到请求（最可靠）
   - 内网探测：填 `http://127.0.0.1:80`，对比与公网地址的响应差异
   - 云环境：直接试元数据 `http://169.254.169.254/latest/meta-data/`
2. **探测内网服务**（用 `ssrf-scanner` 或手工）：
   - 常见目标端口：6379(Redis)、3306(MySQL)、9000(FastCGI)、9200(ES)、11211(Memcached)
   - 用响应时间差判断端口开放（关闭端口通常快速 RST，开放端口会等待）
3. **用 Gopher 打具体服务**：
   ```
   gopherus --exploit redis
   ```
   工具会生成完整的 gopher payload（Redis 写 cron / 写 SSH key / 主从复制 RCE）。
   同样支持 `--exploit mysql`、`--exploit fastcgi`、`--exploit zabbix`。
4. **发送**：把生成的 payload 作为 URL 参数值。注意 gopher payload 需 URL 编码一次（工具通常已处理）。

## 验证

- **Redis**：payload 执行后，访问写入的 webshell 或用写好的 SSH key 连接成功
- **FastCGI**：`<?php system('id');?>` 写入后回包出现命令输出
- **外带确认**：任何一步若能收到自己服务器的请求，即证明 SSRF 成立（哪怕利用未成）

## 失败信号

- 参数填外网地址后自己的服务器**收不到请求** → 不是 SSRF，或目标只允许白名单域名，换方向
- 只能发 http 且内网服务不接受 http → 若协议被限制为 http/https，`gopher` 用不了，转 `ssrfmap` 的 http 模式打内网 Web 应用
- 内网服务需要认证且凭证未知 → 先专注拿凭证（其他手法），拿到后再回来
- 云元数据返回 401/403（IMDSv2）→ 需要先拿 token，链路变长，评估性价比

**成本提示**：本手法链路长、依赖多，`cost: high`。若 30 秒内确认不了 SSRF 存在，**优先切回其他方向**，不要在这里耗时间。

**替代方向**：`ssrfmap` 的自动模式；若确认能读文件，转 `file://` 读源码找更多洞。
