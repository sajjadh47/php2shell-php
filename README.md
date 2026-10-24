# php2shell-php

A PHP CLI scanner for **CVE-2026-109618** and **CVE-2026-109619** (the
"php2shell" PHP multipart parser vulnerabilities).

`php2shell-php` detects whether a remote PHP target is likely affected by
sending a small number of crafted multipart bodies and observing how the
request handler responds. Detection is primarily **behavioral** — a crash,
an empty 500, a dead PHP-FPM worker — with an optional **version-based**
fallback when the target advertises its PHP version via `X-Powered-By`.

> ⚠️ **Authorized use only.** The probes are intentionally resource-heavy and
> can crash PHP workers. Only run this against systems you own or have
> explicit written permission to test. See [Legal](#legal).

---

## Table of contents

- [What it detects](#what-it-detects)
- [How detection works](#how-detection-works)
- [Requirements](#requirements)
- [Installation](#installation)
- [Usage](#usage)
  - [Single target](#single-target)
  - [Bulk scan](#bulk-scan)
  - [Custom headers](#custom-headers)
  - [Custom paths](#custom-paths)
  - [phpMyAdmin targets](#phpmyadmin-targets)
  - [JSON output](#json-output)
- [CLI reference](#cli-reference)
- [Exit codes](#exit-codes)
- [Verdicts explained](#verdicts-explained)
- [Performance and safety](#performance-and-safety)
- [Library usage](#library-usage)
- [Development](#development)
- [Legal](#legal)

---

## What it detects

`php2shell-php` looks for symptoms consistent with the php2shell multipart
parser vulnerabilities, where a deeply-nested multipart field name can cause
excessive resource use during parsing. Depending on the SAPI, the crash
manifests as:

| SAPI | Observable signal |
| --- | --- |
| `mod_php` | In-band PHP fatal error: `Allowed memory size of … bytes exhausted … in Unknown` |
| `mod_php` | HTTP 500 with an empty body while a control request produced output |
| `PHP-FPM` | HTTP 502 / 503 / 504 from the fronting web server (worker died) |
| `PHP-FPM` | HTTP 200 with an empty body while a control request produced output |
| Any | `X-Powered-By: PHP/x.y.z` reporting a version below the fixed release |

Fixed upstream releases (at the time of writing):

| Branch | First fixed patch |
| --- | --- |
| 8.2 | 8.2.35 |
| 8.3 | 8.3.36 |
| 8.4 | 8.4.27 |
| 8.5 | 8.5.12 |

Branches ≤ 8.1 are treated as **VULNERABLE** (end-of-life upstream, no fix
expected). Unknown newer branches are left **undecided** until their first
fixed release is known.

---

## How detection works

For each target `php2shell-php` performs a short sequence:

1. **Control request** — a minimal multipart body. If this fails, times out,
   or returns a 5xx, the target is marked `INCONCLUSIVE` and no probes run.
   If the control body contains `phpMyAdmin`, the scanner **retargets** to
   `/show_config_errors.php` and re-runs the control.
2. **Probe 1** — 1 MiB body, 4 000 parts, 62 nested `a[a]…[a]` keys.
3. **Probe 2** — 8 MiB body, 1 020 parts, 62 nested keys.
4. **Probe 3** — 20 MiB body, 1 020 parts, 62 nested keys.

After each probe the scanner checks, in order:

- Did the response contain a PHP memory-exhaustion fatal error? → `VULNERABLE`
- Was the probe rejected (400/403/411/413/414/417/422/429/431)? → mark
  rejected, stop probing, fall back to version check.
- Did the probe crash the worker (5xx / empty body / 200 with no body)? → `VULNERABLE`
- Does `X-Powered-By` report a **fixed** version? → `FIXED`, stop.
- Otherwise continue to the next probe.

If all probes complete without a signal, the scanner falls back to the
version verdict, then to `NO SIGNAL`.

A scan of one target typically takes **under a second** if the target
advertises a fixed version, and **a few seconds** otherwise.

---

## Requirements

- PHP **8.1** or newer, with `ext-openssl`, `ext-sockets`, `ext-pcntl` (CLI)
- Composer 2
- Network access to the target

---

## Installation

```bash
git clone https://github.com/sajjadh47/php2shell-php.git
cd php2shell-php
composer install --no-dev --optimize-autoloader
chmod +x bin/php2shell
