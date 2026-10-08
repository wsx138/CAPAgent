---
name: php-unserialize
description: PHP 反序列化——用 phpggc 生成框架 gadget 链（含 PHAR 免上传点利用）
triggers:
  tech_stack: [php, laravel, thinkphp, symfony, wordpress, monolog]
  fact_kinds: [vuln, data_pattern, input_point]
  keywords: [反序列化, unserialize, 序列化, O:, phar, 框架, cookie]
  scene: web
tools: [phpggc, phar-gen]
cost: medium
---

## 适用条件

- 存在 `unserialize()` 入口：Cookie / Session / 缓存 / 参数
- 页面出现序列化特征：`O:8:"stdClass"`、`a:2:{`、Base64 后的序列化串
- 目标用了已知存在 gadget 链的框架（Laravel / ThinkPHP / Symfony / Monolog / Guzzle）
- **无 unserialize 点也可打**：只要存在文件操作函数（`file_exists`、`getimagesize`），配合 `phar://` 伪协议即可触发反序列化（PHAR 反序列化，无需上传点）

## 步骤

1. **识别序列化点**：
   - Cookie 里 Base64 解码后是 `O:...` → 直接改 Cookie
   - 参数形如 `data=a:2:{...}` → 参数注入
2. **确认框架与版本**（决定用哪条链）：看报错页、`X-Powered-By`、静态资源路径、composer.lock 泄露。
3. **列出可用链**：
   ```
   phpggc -l
   ```
   按框架过滤，如 `phpggc -l laravel`。
4. **生成 payload**：
   ```
   phpggc Laravel/RCE1 system id -b
   ```
   `-b` 输出 Base64，`-u` 输出 URL 编码，`-f` 输出原始。
5. **PHAR 路线**（无 unserialize 点时）：
   ```
   phar-gen --chain "Laravel/RCE1" --cmd "id" --out shell.gif
   ```
   把生成的 phar 文件当图片上传（改扩展名绕过），再用 `phar://上传路径/shell.gif` 触发。

## 验证

- Cookie/参数注入：回包出现命令执行结果（`id` / `whoami` 输出）
- PHAR：`phar://` 触发后回包出现命令输出
- 快速判定链路通：payload 里带 `sleep(5)`，观察响应时间是否延长

## 失败信号

- 框架版本太新，gadget 链已被官方修复（`phpggc -l` 里的链打上去报错且无时间差）→ 换其他链，或找版本更匹配的 gadget
- 目标对传入的序列化串做了签名/加密（如 Laravel 的 `APP_KEY` 加密 Cookie）→ **必须先拿 APP_KEY**，否则改了也不生效（看 `.env` 泄露 / 报错页 / 弱密钥）
- `unserialize` 的类不在目标 autoload 范围内 → 该链不可用，换链
- PHAR 上传被校验文件内容（不是扩展名）→ 改用真实图片马 + phar 元数据构造

**替代方向**：若无 PHP gadget 可用，转 `ysoserial`（Java）或 `pickle-pwn`（Python）；若目标是 PHP 且有文件包含，转 `php-filter-chain`。
