# Stacutis PHP2Shell scanner: full details

The short version is in the [README](../README.md). This is the longer original write-up.

## Run this on the server

Paste this into the server's terminal. It downloads the scanner, checks the file, and scans. A scan changes nothing. If a menu appears, option 4 leaves the server as it is. An upgrade still waits for a separate yes.

```sh
cd /tmp &&
curl -fsSL -o stacutis-php2shell.sh https://www.stacutis.com/php2shell.sh &&
curl -fsSL -O https://www.stacutis.com/CHECKSUMS.txt &&
sha256sum -c CHECKSUMS.txt &&
bash stacutis-php2shell.sh
```

The check must print `stacutis-php2shell.sh: OK`. Read the script before you run it. Do not pipe the download into a shell.

This is a local tool for a Linux host you administer. It reports whether PHP on that host is exposed to [CVE-2026-109618](https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w) and [CVE-2026-109619](https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp) (CVSS v4.0 9.2). Upstream fixes are PHP 8.5.12, 8.4.27, 8.3.36, and 8.2.35. Tool version 1.0.0. CVE data date 2026-10-22. If that date is more than 14 days behind the clock, read the PHP advisory again before you trust a PATCHED result.

Provided as-is. Run it only on systems you own or administer. Take a backup before you answer yes. MIT license (`LICENSE`).

## Workaround tradeoffs

> [!CAUTION]
> Temporary settings do not upgrade PHP. The vulnerable build stays installed. The next scan can say MITIGATED, and the exit code stays 1. The new config is tested before anything restarts. If the test fails, the old files go back and nothing restarts. PHP is then reloaded, or restarted when a reload is not possible. A failed write also puts the old files back. Settings are written as admin config, so the site cannot turn them back on with `.user.ini` or `ini_set`. Config is copied to `/var/backups/stacutis/<stamp>/`. `--rollback <stamp>` restores those files and restarts the recorded services. It does not change packages.

On a terminal the same tradeoffs are printed in red before each yes.

| You turn on | What you give up |
| --- | --- |
| Upload progress off | Bars that use `PHP_SESSION_UPLOAD_PROGRESS` stop. This closes one confirmed path. Other ways into the bug stay open. |
| Fatal backtraces off (PHP 8.5) | Fatal errors lose that backtrace. This blocks one confirmed producer of the stale-state bug. |
| Post 8M / upload 2M, or post 32M / upload 8M | Larger forms, APIs, and file uploads fail. 8M and 32M are the advisory's post sizes. 2M and 8M are this tool's smaller upload caps. The proxy and any WAF are not edited. |
| `memory_limit=-1` | PHP stops capping RAM. One request can grow until the cgroup limit or the OS OOM killer. An allocation failure can still reach the bug. Pair it with a cgroup `memory.max`. This tool never sets `RLIMIT_AS` or `RLIMIT_DATA`. Written only in FPM and Apache admin blocks, not the shared ini drop-in. |
| `pm.max_requests=1` | Every FPM worker exits after one request. Under load that costs CPU, adds latency, and can fill the listen queue. |

`--workarounds --yes` applies only the first two. Post size needs `--upload-policy none` or `--upload-policy uploads`. The RAM cap needs `--allow-unlimited-memory`. One-request workers need `--max-requests-1`. Each of those stays off unless you pass the flag.

## Scan and upgrade

The default run is read-only and does not use the network. It finds CLI `php`, PHP-FPM, `mod_php`, php-cgi, FrankenPHP, and LiteSpeed `lsphp`, and it reads the local package changelog only. PATCHED (backport) needs both CVE IDs on lines that are not not-affected, wontfix, no-dsa, unfixed, or ignored. This tool rates `mod_php` highest risk because [GHSA-w8hw-w9fx-j79w](https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w) shows code execution when `mod_php` runs shutdown after a failed startup. That GHSA also says a complete PHP-FPM exploit was not demonstrated for that CVE. PHP 8.1 and older stay vulnerable unless the local changelog names both CVEs.

The changelog only counts for the package that owns the binary. A PHP you built yourself, or one in `/usr/local`, is never marked patched because a distro package on the same host is.

To read a version the tool runs `php -v` only when root owns the binary and nobody else can write it or any directory above it. It never runs a binary found through `/proc`. In every other case it reads the version string from the file without running it.

PHP running inside a container or another mount namespace is listed in its own section, "PHP running in containers or other namespaces". Its path does not exist on the host, so `--fix` and `--workarounds` leave it alone. BELOW_FIX means the upstream version is older than the fix. A distro build inside the container may still have a backport, and only a check inside the container can tell. These entries change the exit code only when you pass `--containers`.

`--fix` upgrades with apt, dnf, yum, or apk, and only a same-branch candidate at or above the fixed release, or one whose changelog names both CVEs. It does not compile PHP, does not add repositories, and does not move 8.1 and older to a new major version. Ondrej's PPA and remi are named only as archives a host may already use. The tool will not enable them.

`--ioc` and `--containers` are optional and read-only. Indicators are not proof, and the published AWS addresses are not blocked: `103.216.220.92`, `31.223.184.166`, `37.19.200.5`, `134.209.159.64`, `103.114.163.188`, `95.217.98.37`. The tool does not patch containers.

Needs bash 4.3 or newer. On Alpine, install bash first. A scan works without root. `--fix`, `--workarounds`, and `--rollback` need root, except `--dry-run` and `--test-root`.

## Flags

| Flag | Effect |
| --- | --- |
| `--json` | One JSON document on stdout. `schema_version` is 1. |
| `--quiet` | One summary line. |
| `--no-color` | Plain text. Also plain when stdout is not a terminal, `NO_COLOR` is set, or `--json` is set. |
| `--dry-run` | Show the plan and write nothing. A vulnerable host still exits 1. |
| `--yes` | Answer yes to an action you already named. It does not choose the action. |
| `--fix` | Upgrade when the repo has a confirmed fix. |
| `--workarounds` | Apply temporary settings. See the tradeoffs above. |
| `--upload-policy none\|uploads` | With `--workarounds`, set the post and upload caps above. |
| `--allow-unlimited-memory` | With `--workarounds`, lock `memory_limit=-1`. |
| `--max-requests-1` | With `--workarounds`, set `pm.max_requests=1`. |
| `--ioc` | Read-only indicators since 2026-10-17. Does not change the exit code. |
| `--containers` | List local Docker containers that look like PHP. |
| `--containers-exec` | With `--containers`, run `php -v` inside them. |
| `--log` | Append the scan summary to `/var/log/stacutis-php2shell.log` (mode 600). A scan does not create that file otherwise. |
| `--rollback STAMP` | Restore `/var/backups/stacutis/STAMP`. The stamp looks like `20261022T153000Z`. |
| `--test-root DIR` | Fixture mode. `DIR` must contain `fixture/IS_TEST_ROOT`. |
| `--version` / `--help` | Version and CVE data date, or usage. |

`--fix` and `--workarounds` cannot be combined. `--rollback` cannot be combined with either.

| Code | Meaning |
| --- | --- |
| 0 | No PHP, or every finding is PATCHED. |
| 1 | At least one finding is VULNERABLE or MITIGATED. |
| 2 | Bad usage. |
| 3 | UNKNOWN only. If any finding is vulnerable, the code is 1. |
| 4 | A requested change failed. |
| 5 | A change needs root. |

Exit 0 does not mean the host was checked for a past break-in.

## Check the file

`sha256sum -c CHECKSUMS.txt` must print `stacutis-php2shell.sh: OK`. That check catches a broken download. It does not catch a replaced repository, because both files would change together. This tree has no signing key. Sign with `gpg --detach-sign --armor` or `minisign -Sm`, and publish the public key on a second channel.

`bash tests/run-hermetic.sh` runs the fixture suite. The Docker image suite was not executed in the environment that produced this tree.

Sources: [PHP 21 October 2026 release](https://www.php.net/archive/2026.php#2026-10-21-5), [PHP Foundation](https://thephp.foundation/blog/2026/10/21/todays-php-security-release-and-how-were-strengthening-php-security/), [oss-security](https://openwall.com/lists/oss-security/2026/10/21/6), [CERT-EU 2026-018](https://www.cert.europa.eu/publications/security-advisories/2026-018/), [Canadian Centre AL26-026](https://www.cyber.gc.ca/en/alerts-advisories/al26-026-critical-vulnerabilities-impacting-php-cve-2026-109618-cve-2026-109619), [AWS MadPot](https://aws.amazon.com/blogs/security/amazon-threat-intelligence-identifies-php2shell-exploitation-prior-to-public-disclosure-in-madpot/), [AWS WAF](https://aws.amazon.com/blogs/security/using-aws-waf-to-apply-mitigations-for-php2shell-rce-vulnerabilities-cve-2026-109618-and-cve-2026-109619/).

## Coverage and safety details

- Layouts: distro packages, php.net Docker images, /usr/local builds, cPanel EasyApache (ea-php), Plesk (/opt/plesk/php) and CloudLinux alt-php (/opt/alt). For a trusted CLI on a live host, `php --ini` is used to find the ini files.
- Ini files in conf.d are followed through symlinks. Paths with `..` are rejected.
- Apache: only enabled config files are read. The workaround block covers both `php_module` and `php7_module`.
- If the package changelog is not installed, the result says so ("changelog-not-installed") instead of guessing.
- Held packages (apt-mark hold, dnf versionlock) are reported and skipped by `--fix`.
- `--fix` restarts only the services for the PHP branches that are vulnerable.
- The changelog server sometimes returns 404 for new security uploads. In that case the candidate cannot be confirmed and the script says so. It does not upgrade on a guess.
- IOC checks: crash lines and journal timestamps only, access logs are streamed, and only outbound connections from PHP processes are listed.
- Containers: docker and podman. `--containers-exec` probes every running container; without it only PHP-named containers are listed.
- Running the scan without root prints a warning, because some files and /proc entries cannot be read. Results can then be UNKNOWN.
- Repeated `--workarounds` runs give the same files. The marked block is replaced, and blank lines do not pile up.
- JSON output escapes every control character.
- Ini parsing skips `[PATH=...]` and `[HOST=...]` sections, keeps `;` inside quotes, and treats `key =` as an empty value.
- PATH: when it runs on a real host the script keeps only the standard system directories plus root-owned, non-writable entries of your PATH, so a writable directory in PATH cannot swap in a fake `apt-get` or `systemctl`.
- For apt, if the changelog server has nothing for the candidate, the signed candidate package is downloaded with `apt-get download` and its changelog is read from it. Nothing is installed or run from that download.
- `--fix` needs the network for the package manager, and `dnf` also reads the candidate changelog from repo metadata. The scan itself does not.
