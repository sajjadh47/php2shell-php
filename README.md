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

## Table of contents

- [What it detects](#what-it-detects)
- [How detection works](#how-detection-works)
- [Detection limits](#detection-limits)
- [Requirements](#requirements)
- [Installation](#installation)
  - [Composer (recommended)](#composer-recommended)
  - [PHAR](#phar)
  - [From source](#from-source)
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

A scan of one target typically takes **under a second on a LAN** when the
target advertises a fixed version, and a few seconds over the internet or
when all three probes are sent.

## Detection limits

A `VULNERABLE` verdict from a 502/503/504 or an empty 200 proves the PHP
worker died mid-request, but not *why*. On well-behaved targets this
correlates strongly with the php2shell parser bug, but other causes exist:
resource exhaustion, a genuine server misconfiguration, or an unrelated
crash. For high-confidence reporting:

- Corroborate with the version check where `X-Powered-By` is exposed.
- Reproduce against a canary instance that you control.
- Prefer `VULNERABLE` with an in-band memory-exhaustion fatal error as the
  strongest signal, since that one is direct evidence of the parser bug.

A `NO SIGNAL` verdict is *not* proof of safety. A `FIXED` verdict based only
on `X-Powered-By` depends on the header telling the truth; upstream and
distribution backports can diverge, and headers can be overridden.

## Requirements

- PHP **8.2** or newer
- Required extensions: `ext-json`, `ext-openssl`, `ext-sockets`
- `ext-pcntl` is optional and not required by `php2shell-php`; install it
  only if you plan to add signal handling on top of the library
- Composer 2 (for installation)
- Network access to the target

## Installation

The package is published as **`sajjadh47/php2shell-php`** on Packagist.
The Composer bin name is `php2shell`.

### Composer (recommended)

Global install — puts `php2shell` on your `PATH`:

```bash
composer global require sajjadh47/php2shell-php
```

Make sure Composer's global bin directory is on your `PATH`:

```bash
# Linux/macOS
export PATH="$HOME/.config/composer/vendor/bin:$PATH"

# macOS + Homebrew PHP
export PATH="$HOME/.composer/vendor/bin:$PATH"
```

Add the appropriate line to your `~/.bashrc`, `~/.zshrc`, or `~/.profile`
to make it permanent. Then:

```bash
php2shell --version
```

Per-project install — use it as a library or a dev tool:

```bash
composer require --dev sajjadh47/php2shell-php
vendor/bin/php2shell --version
```

Upgrade:

```bash
composer global update sajjadh47/php2shell-php
# or, in a project:
composer update sajjadh47/php2shell-php
```

### PHAR

A standalone PHAR is attached to every GitHub release and does not require
Composer at runtime (PHP 8.2+ and the `openssl`/`sockets` extensions only):

```bash
curl -L -o php2shell.phar \
  https://github.com/sajjadh47/php2shell-php/releases/latest/download/php2shell.phar
chmod +x php2shell.phar
sudo mv php2shell.phar /usr/local/bin/php2shell
```

Or download via the GitHub CLI:

```bash
gh release download --repo sajjadh47/php2shell-php --pattern 'php2shell.phar'
```

The PHAR is built and attached automatically by the `release-phar` GitHub
Actions workflow whenever a `vX.Y.Z` tag is pushed — see
[Building the PHAR](#building-the-phar) below if you want to build one
yourself.

### From source

For development, auditing the code, or running an unreleased commit:

```bash
git clone https://github.com/sajjadh47/php2shell-php.git
cd php2shell-php
composer install --no-dev --optimize-autoloader
chmod +x bin/php2shell
./bin/php2shell -u https://example.com
```

Optional — install the working tree on your `PATH`:

```bash
ln -s "$PWD/bin/php2shell" /usr/local/bin/php2shell
```

## Usage

### Single target

```bash
php2shell -u https://example.com -v
```

Output:

```
[*] Loaded 1 host(s) to scan
[*] Default path: /index.php
[*] Using 10 thread(s)
[*] Timeout: 60s
[*] SAPI rules: auto

[VULNERABLE] https://example.com - Status: 502 - SAPI: PHP-FPM - Verdict: VULNERABLE
  -> probe 1 (1 MiB, 4000 parts) crashed the request handler: HTTP 502 from the web server fronting PHP-FPM (worker died mid-request)
```

The `-> ...` reason line (and, with `-v`, the response snippet) is only
printed in verbose mode. Without `-v` you get just the one-line summary:

```
[VULNERABLE] https://example.com - Status: 502 - SAPI: PHP-FPM - Verdict: VULNERABLE
```

### Bulk scan

```bash
php2shell -l hosts.txt -t 20 -o results.json
```

`hosts.txt` is one host per line; blank lines and lines starting with `#`
are ignored. Duplicate hosts (case-insensitive scheme + host + path) are
skipped.

### Custom headers

```bash
php2shell -u https://internal.example.com \
  -H "Authorization: Bearer $TOKEN" \
  -H "X-Forwarded-For: 10.0.0.1"
```

Sensitive header values (`Authorization`, `Cookie`, `Proxy-Authorization`,
`Set-Cookie`, `X-API-Key`) are redacted in verbose output and in the JSON
`response` field.

When combined with `--follow-redirects`, sensitive *request* headers
(`Authorization`, `Cookie`, `Proxy-Authorization`, `X-API-Key`) are stripped
automatically whenever a redirect's `Location` points at a different host
than the one that was requested. Only the host is compared — a same-host
scheme change (e.g. an `http://` → `https://` upgrade redirect) is not
treated as cross-origin and does not strip headers.

### Custom paths

```bash
# explicit paths (repeatable)
php2shell -u https://example.com --path /index.php --path /admin/index.php

# from a file
php2shell -l hosts.txt --path-file paths.txt
```

`paths.txt` uses the same format as the host list: one path per line, blank
lines and `#`-prefixed lines ignored. When multiple paths are supplied, each
is tried in order and the **first** `VULNERABLE` result wins; otherwise the
highest-priority fallback (`INCONCLUSIVE`/`ERROR` > `FIXED` > `NO SIGNAL`) is
returned.

### phpMyAdmin targets

If the control body contains `phpMyAdmin`, the scanner automatically
retargets to `/show_config_errors.php`, which is the endpoint that exercises
the multipart parser in phpMyAdmin setups. The `final_url` field in the JSON
records the retarget.

### JSON output

```bash
php2shell -l hosts.txt -o results.json
```

Default: only targets with `vulnerable === true` are written. Use
`--all-results` to include every scanned target with its verdict, probes,
and response metadata — including `INCONCLUSIVE` and `ERROR` entries.

Sample:

```json
{
  "scan_time": "2026-10-24T12:00:00Z",
  "total_results": 1,
  "results": [
    {
      "host": "https://example.com",
      "vulnerable": true,
      "verdict": "VULNERABLE",
      "status_code": 502,
      "sapi": "PHP-FPM",
      "powered_by": "PHP/8.3.20",
      "reason": "probe 1 (1 MiB, 4000 parts) crashed the request handler: HTTP 502 ...",
      "tested_url": "https://example.com/index.php",
      "final_url": "https://example.com/index.php",
      "control": {
        "status_code": 200,
        "response_bytes": 1234,
        "bytes_sent": 45,
        "error": null,
        "description": "HTTP 200, 1234 byte response (sent 45 bytes)"
      },
      "probes": [
        {
          "probe": 1,
          "size_mib": 1,
          "parts": 4000,
          "status_code": 502,
          "response_bytes": 0,
          "bytes_sent": 1048576,
          "error": null,
          "description": "HTTP 502, 0 byte response (sent 1048576 bytes)"
        }
      ],
      "timestamp": "2026-10-24T12:00:00Z"
    }
  ]
}
```

## CLI reference

| Option | Description |
| --- | --- |
| `-u, --url <url>` | Single target. One of `--url` / `--list` is required. |
| `-l, --list <file>` | File of hosts, one per line. |
| `-t, --threads <n>` | Maximum concurrent target scans (default: `10`). Probes within one target are always sequential. |
| `--timeout <s>` | Per-request timeout in seconds (default: `60`). |
| `-o, --output <file>` | Write results as JSON. |
| `--all-results` | Include non-vulnerable hosts in JSON. |
| `-k, --insecure` | Disable TLS certificate verification. |
| `--follow-redirects` | Follow up to 10 redirects (off by default). |
| `-H, --header "K: V"` | Add a request header (repeatable). |
| `--path <path>` | Test a specific path (repeatable). |
| `--path-file <file>` | Read paths from a file, one per line. |
| `--sapi auto\|mod_php\|fpm` | Select verdict rules (default: `auto`). |
| `-v, --verbose` | Show reasons, probe metadata, and response snippets (first 2 048 bytes). |
| `-q, --quiet` | Only print vulnerable hosts. |
| `--no-color` | Disable ANSI colors. |

`--sapi` selects which crash signals are considered diagnostic. `mod_php`
skips the PHP-FPM worker-death heuristics; `fpm` skips the in-band
fatal-error heuristic. Use `auto` unless you know the target's SAPI.

Symfony Console's standard `--no-interaction` flag is accepted at the
application level and is useful in CI.

## Exit codes

| Code | Meaning |
| --- | --- |
| `0` | Scan completed, no vulnerabilities found. Note this also covers runs where every target errored or was inconclusive — check `--all-results` JSON or the printed summary if you need to tell the two apart in CI. |
| `1` | At least one vulnerable target found. |
| `2` | Reserved (currently unused). |
| `3` | Tool error: bad arguments, unreadable list, failed JSON write, etc. |

## Verdicts explained

| Verdict | `vulnerable` | Meaning |
| --- | --- | --- |
| `VULNERABLE` | `true` | A crash signal was observed, **or** an unpatched version was advertised with no conflicting signal. |
| `FIXED` | `false` | No crash observed **and** `X-Powered-By` reports a patched release. |
| `NO SIGNAL` | `false` | No crash observed, no version advertised. Treat as *probably not affected* but not confirmed. |
| `INCONCLUSIVE` | `null` | Control request failed, timed out, returned 5xx, or the probes were rejected before PHP parsed them. Re-run with `-v`, a longer `--timeout`, or a different `--path`. |
| `ERROR` | `null` | Could not even reach the target (DNS, TLS, connection refused, invalid URL). |

`NO SIGNAL` and `INCONCLUSIVE` are *not* the same. `NO SIGNAL` means the
target responded and did not crash. `INCONCLUSIVE` means we could not draw a
conclusion.

## Performance and safety

- The three probes together total about **29 MiB** of request body (1 + 8 +
  20 MiB). A full scan of one target that never short-circuits sends about
  that much. A scan that hits the version check on probe 1 sends only ~1 MiB.
- `--threads` limits how many targets are scanned concurrently. Probes
  *within* a single target are always sequential — the scanner finishes the
  control request and every applicable probe for one host before moving on.
- The control request must succeed before probes run. This prevents
  accidentally hammering a broken endpoint.
- Redirects are **not** followed by default. When `--follow-redirects` is
  enabled, sensitive request headers are stripped on cross-host redirect
  hops by the `StripSensitiveOnCrossOrigin` interceptor (host only — see
  [Custom headers](#custom-headers)).
- TLS verification is **on** by default. Use `-k` only on lab targets.
- Response bodies are capped at **1 MiB**; request bodies are built once and
  reused across targets.
- This version has no built-in delay between probes. If a target is fragile,
  use `--threads 1` and a large `--timeout`; a `--delay-ms` option is planned.

If you are scanning a production fleet, prefer:

- `--timeout 30` and a modest `--threads` (5–10) to avoid saturating shared
  load balancers.
- A dedicated staging environment for exploratory runs.

## Library usage

`php2shell-php` can be embedded in another PHP tool:

```php
<?php

use Php2Shell\Http\Scanner;
use Php2Shell\Target\Target;

$scanner = Scanner::build(timeout: 30, sapi: 'auto');
$result  = $scanner->check(Target::fromUrl('https://example.com'));

if ($result['vulnerable'] === true) {
    echo "vulnerable: {$result['reason']}\n";
}
```

The returned array is the same structure written to JSON. All fields are
stable; unknown fields may be added in future versions.

## Development

Repository layout:

```text
src/                        # library
tests/                      # PHPUnit
bin/php2shell                # CLI entry point
.github/workflows/           # CI: tests + static analysis (ci.yml), PHAR release (release-phar.yml)
box.json                     # PHAR build configuration (Humbug Box)
.php-cs-fixer.dist.php       # code style configuration
composer.json
phpunit.xml.dist
phpstan.neon                 # static analysis config
```

Set up:

```bash
composer install
./bin/php2shell --help
```

`friendsofphp/php-cs-fixer` is already a `require-dev` dependency, so a
plain `composer install` is enough to get every tool below on `vendor/bin/`.

| Command | Runs |
| --- | --- |
| `composer test` | PHPUnit (`memory_limit=512M`) |
| `composer stan` | PHPStan (`phpstan.neon`, `level: max`) |
| `composer lint` | `php -l` across `src/`, `tests/`, and `bin/php2shell` |
| `composer cs` | php-cs-fixer, dry run with a diff (no files changed) |
| `composer cs-fix` | php-cs-fixer, applies fixes |
| `composer check` | `composer validate` + `composer audit` + `lint` + `stan` + `cs` + `test`, in that order |

`composer check` is the single command to run before opening a PR or
tagging a release — it's the same sequence `.github/workflows/ci.yml` runs
on every push and pull request (PHP 8.2–8.4), so a clean `composer check`
locally should mean a green CI run.

In CI, pass `--no-interaction` to any scanner invocation:

```bash
./bin/php2shell --no-interaction -u https://example.com
```

### Building the PHAR

PHARs are built with [Humbug Box](https://github.com/box-project/box) using
the `box.json` config shipped in the repo root:

```bash
composer install --no-dev --optimize-autoloader
box compile
./build/php2shell.phar --version
```

Install Box globally first if you don't have it (`composer global require
humbug/box`, or download `box.phar` directly from its GitHub releases). The
`.github/workflows/release-phar.yml` workflow runs the same steps and
attaches `build/php2shell.phar` to the GitHub release whenever a `vX.Y.Z`
tag is pushed.

## Legal

This tool is provided for **authorized security testing only**. The authors
are not responsible for misuse. By using `php2shell-php` you agree that:

- You own the targets, or
- You have explicit **written** authorization from the target owner, and
- You will not run the scanner against third-party systems, shared hosting,
  or infrastructure you do not control.

The probes are intentionally resource-intensive and may crash PHP workers or
exhaust memory on the target. Treat any run as a **potential denial of
service** and schedule accordingly.