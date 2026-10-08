---
name: php-filter-chain
description: PHP filter chain 盲注——无回显场景下利用 iconv 链构造任意字符串
triggers:
  tech_stack: [php]
  fact_kinds: [vuln, input_point]
  keywords: [文件包含, file_include, LFI, php://filter, include, require]
  scene: web
tools: [php-filter-chain]
cost: medium
---

## 适用条件

- 目标为 PHP，存在文件包含 / `file_get_contents` / `include` 类可控参数
- **无回显**（包含结果不返回）或只能间接观察——这正是本手法的价值所在
- 目标启用了 `iconv` 扩展（默认启用）

不需要目标有上传点或写权限，本手法可直接拼出任意内容（如 `<?php system($_GET[0]);?>`）。

## 步骤

1. 先确认包含点。常见形态：`?page=`, `?file=`, `?path=`, `?tpl=`，或 Cookie/Lang 参数。
2. 用工具生成 chain：
   ```
   php-filter-chain --chain "<?php system($_GET[0]);?>"
   ```
   工具会输出形如 `php://filter/convert.iconv.UTF8.CSISO2022KR|.../resource=php://temp` 的长串。
3. 把生成结果作为参数值发送。注意 **URL 编码**，chain 很长（数千字符）时改用 POST body 规避长度限制。
4. 若目标是 `include`，payload 会直接执行；若是 `file_get_contents`，回显即拿到的内容。

## 验证

- `include` 场景：请求带 `&0=id`，回包出现命令执行结果
- 读文件场景：回包出现构造的字符串内容
- 快速判定：先构造 `<?php phpinfo();?>`，回包出现 phpinfo 表格即链路通

## 失败信号

出现以下任一条 → **立即换手法**，不要反复调 chain：

- 参数被过滤掉 `php://` 或 `filter` 关键字（回包显示原始参数或报错）
- 目标禁用了 `iconv`（chain 执行后回包为空或 500，且换短 chain 同样失败）
- Web 服务器对 URL 长度硬限制且不接受 POST（414 持续出现）
- 目标非 PHP（`SceneDetector` 未识别出 PHP 却硬打本手法 = 浪费时间）

**替代方向**：换成 `phpggc`（反序列化）或直接找上传点；若包含点可用但无 PHP 环境，考虑日志包含 / session 文件包含。
