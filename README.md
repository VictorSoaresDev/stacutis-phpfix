# Stacutis PHP2Shell scanner

`stacutis-php2shell.sh` is a local command-line tool. A server owner downloads it, reads it, and runs it on a Linux host they administer. It reports whether the PHP installs on that host are exposed to PHP2Shell, and it can upgrade PHP or write temporary settings after an explicit yes.

The tool version in this tree is **1.0.0**. The CVE data date is **2026-10-22**. If the banner says that date is more than 14 days behind the clock, read the PHP advisory again before you trust a PATCHED result.

This program is provided as-is, without warranty. Run it only on systems you own or administer. Take a backup before you answer yes. The license is MIT (`LICENSE`). The disclaimer is not a contract term that changes the MIT grant; it is the condition the authors expect operators to follow.

## What PHP2Shell is

PHP2Shell is the name used for two PHP core bugs disclosed on 21 October 2026:

- [CVE-2026-109618](https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w) (GHSA-w8hw-w9fx-j79w)
- [CVE-2026-109619](https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp) (GHSA-6wmf-4rv5-p3rp)

Both are scored CVSS v4.0 9.2 in those advisories. CERT-EU and the PHP project published on the same calendar day at different times. This README does not pick a minute. Read the sources below.

Upstream fixed releases, from the [PHP 21 October 2026 security release](https://www.php.net/archive/2026.php#2026-10-21-5):

| Branch | Fixed release |
| --- | --- |
| 8.5 | 8.5.12 |
| 8.4 | 8.4.27 |
| 8.3 | 8.3.36 |
| 8.2 | 8.2.35 |

PHP 8.2 reaches end of life on 31 December 2026, according to that same 8.2.35 note. This tool does not invent end-of-life dates for the other branches. PHP 8.1 and older have no upstream fixed release. php.net published minimal source backports for 7.4, 8.0, and 8.1. This tool does not compile them.

CVE-2026-109618 is an out-of-memory path. Hitting `memory_limit` aborts with `longjmp()` while request memory is only partly initialized, and cleanup can free attacker-influenced memory. Multipart parsing can reach `memory_limit` inside limits that look large enough. The GHSA says mod_php still runs shutdown when startup fails, and that a complete PHP-FPM exploit was not demonstrated for this CVE. The [PHP Foundation post](https://thephp.foundation/blog/2026/10/21/todays-php-security-release-and-how-were-strengthening-php-security/) says remote code execution was confirmed on PHP-FPM through application paths for the out-of-memory issue. Read both.

CVE-2026-109619 leaves global state (error, session, object, and extension state) pointing at freed memory after a fatal error at the wrong moment. The next request on the same worker uses that state. The GHSA describes unauthenticated heap use-after-free, memory disclosure, and remote code execution as the web worker user. The confirmed producer called out there for the fatal-error path is an error backtrace, which PHP 8.5 emits by default (`fatal_error_backtraces`). This tool does not claim OPcache is part of that state.

The confirmed consumer paths in the advisories are the session upload-progress handler (`session.upload_progress.enabled`, default On) and, on 8.5, fatal-error backtraces. The GHSA also describes INI diagnostics that run before request init, including mod_php `.htaccess` / `php_value` early, and PHP-FPM only when a frontend sends `PHP_VALUE` or `PHP_ADMIN_VALUE` that warn. `.user.ini` is applied after init, so this tool does not treat it as a mitigation.

The scanner looks for PHP-FPM, Apache `mod_php`, php-cgi, FrankenPHP, and LiteSpeed `lsphp`. This tool rates `mod_php` highest risk because the GHSA for CVE-2026-109618 shows code execution when `mod_php` runs shutdown after a failed startup. That GHSA also says a complete PHP-FPM exploit was not demonstrated for that CVE. Read the GHSA before you treat another SAPI as equivalent. This README does not claim a first affected version of 5.4. Builds older than 8.2 are reported VULNERABLE unless a local package changelog names both CVE IDs. PHP 8.6 was still a release candidate around this data date. 8.6 and anything newer are UNKNOWN unless that changelog names both CVEs. A pre-release (`RC`, `alpha`, `beta`, `dev`) of 8.2 through 8.5 is not the security release. A distro suffix such as `-1ubuntu2.22` is not a pre-release.

AWS MadPot [describes an exploit attempt on 17 October 2026](https://aws.amazon.com/blogs/security/amazon-threat-intelligence-identifies-php2shell-exploitation-prior-to-public-disclosure-in-madpot/) and broad exploitation after public disclosure. The [Canadian Centre AL26-026](https://www.cyber.gc.ca/en/alerts-advisories/al26-026-critical-vulnerabilities-impacting-php-cve-2026-109618-cve-2026-109619), published 21 October 2026, said it had not identified active exploitation at publication time. The optional indicator check looks back to 2026-10-17. A clean indicator check is not proof that the host is fine.

### Sources

- PHP Foundation, 21 October 2026: <https://thephp.foundation/blog/2026/10/21/todays-php-security-release-and-how-were-strengthening-php-security/>
- oss-security (Jakub Zelenka, CVE-2026-109618): <https://openwall.com/lists/oss-security/2026/10/21/6>
- CERT-EU 2026-018: <https://www.cert.europa.eu/publications/security-advisories/2026-018/>
- Canadian Centre AL26-026: <https://www.cyber.gc.ca/en/alerts-advisories/al26-026-critical-vulnerabilities-impacting-php-cve-2026-109618-cve-2026-109619>
- AWS MadPot: <https://aws.amazon.com/blogs/security/amazon-threat-intelligence-identifies-php2shell-exploitation-prior-to-public-disclosure-in-madpot/>
- php.net archive entry: <https://www.php.net/archive/2026.php#2026-10-21-5>
- GHSA-w8hw-w9fx-j79w and GHSA-6wmf-4rv5-p3rp (links above)
- AWS WAF mitigations: <https://aws.amazon.com/blogs/security/using-aws-waf-to-apply-mitigations-for-php2shell-rce-vulnerabilities-cve-2026-109618-and-cve-2026-109619/>

## What the tool does

The default is a read-only scan.

- It detects Debian, Ubuntu, RHEL, Alma, Rocky, Fedora, and Alpine from `/etc/os-release` and the package manager that is present (`apt`, `dnf`, `yum`, or `apk`).
- It finds CLI `php`, `php-fpm`, `php-cgi`, `mod_php` (`libphp*.so` and `apachectl -M` / `httpd -M`), FrankenPHP, and LiteSpeed `lsphp`, including versioned paths such as `/usr/bin/php8.3` and `/opt/remi/php*/root/usr/bin`.
- It classifies each build against the fixed releases above.
- It reads local changelogs only (`/usr/share/doc`, `rpm -q --changelog` on a real host). A scan does not run `apt-get update`, `apt-get changelog`, `dnf makecache`, or `apk update`.
- PATCHED (backport) requires both CVE IDs on lines that are not marked not-affected, not vulnerable, wontfix, no-dsa, unfixed, or ignored. One CVE stays VULNERABLE, with a partial-changelog note.
- It reads `session.upload_progress.enabled`, `memory_limit`, `post_max_size`, `upload_max_filesize`, `fatal_error_backtraces`, and `pm.max_requests` from the SAPI ini, `conf.d` in alphabetical order, FPM pool `php_admin_*` / `php_*`, and Apache `php_admin_*` / `php_*`. Admin values win over pool values, which win over ini, which win over the PHP default. Upload progress defaults to On. `fatal_error_backtraces` defaults to On only on 8.5.
- MITIGATED means the version is still vulnerable, upload progress is explicitly off in admin, pool, ini, or Apache config, and on 8.5 fatal backtraces are explicitly off too. `memory_limit=-1`, smaller post limits, and `pm.max_requests=1` are reported and do not by themselves produce MITIGATED. The human report says the out-of-memory path is still open unless `memory_limit=-1` is locked with `php_admin_value`.
- `--ioc` is read-only. It reports file:line for crash-like log lines and for access-log hits on `PHP_SESSION_UPLOAD_PROGRESS` or the AWS-published addresses below. It reports path, line, and a pattern id for recently modified `.php` files that contain common webshell strings. It reports unexpected children of PHP or Apache and established sockets of the pool user. It does not print file bodies or full log lines, and it does not delete anything. Indicators do not change the exit code.
- `--containers` lists running Docker containers whose image or name contains `php`. `docker exec php -v` runs only with `--containers-exec` or an interactive yes. The tool does not patch a container. Rebuild the image.
- On a terminal, after a vulnerable or mitigated scan, it offers a menu: upgrade, temporary settings, show the planned edits, or exit. The menu is skipped for `--json`, `--quiet`, `--yes`, and when stdin or stdout is not a terminal. `--yes` alone does not select the menu and does not change the host.

A full fix (`--fix`, or menu option 1):

1. Prints the package-manager commands and the candidate check.
2. Waits for yes (or `--yes`).
3. Copies PHP and pool config to `/var/backups/stacutis/<UTC stamp>/` and locks that directory down.
4. Refreshes package metadata. This is the network step, and it happens only after yes.
5. Installs with `apt-get install --only-upgrade`, `dnf upgrade`, `yum upgrade`, or `apk upgrade`, and only for packages whose candidate is the same branch at or above the fixed release, or whose changelog names both CVEs.
6. Restarts active `php*-fpm`, `php-fpm*`, `apache2`, `httpd`, `lsws`, `lshttpd`, and `frankenphp*` services. Old workers keep the previous code until they restart.
7. Scans again.

If the configured repositories have no confirmed package, it says so and does not add a repository. It points at the distro security pocket, and it names the ondrej PHP PPA (`https://launchpad.net/~ondrej/+archive/ubuntu/php`) and remi only as archives some hosts already use. On 21 October 2026 php.net said `rpms.remirepo.net` would not have the updates that day. This tool does not claim whether remi has them now. It will not enable remi or the PPA. PHP 8.1 and older are not moved to a new major version automatically. A candidate on another branch is refused. If PHP was compiled by hand, the tool will not build a replacement.

Temporary settings (`--workarounds`, or menu option 2) are written only in admin config: a `conf.d` drop-in, FPM `php_admin_flag` / `php_admin_value` inside every pool section, and an Apache conf when `mod_php` is loaded. They are not written to `.user.ini` and the tool does not call `ini_set`. Each family of settings waits for its own yes unless you passed the matching flag with `--yes`.

| Setting | When |
| --- | --- |
| `session.upload_progress.enabled=0` | Default for `--workarounds --yes` |
| `fatal_error_backtraces=0` | PHP 8.5 only. Default for `--workarounds --yes` |
| `post_max_size=8M` and `upload_max_filesize=2M` | `--upload-policy none` |
| `post_max_size=32M` and `upload_max_filesize=8M` | `--upload-policy uploads` |
| `php_admin_value[memory_limit]=-1` | `--allow-unlimited-memory` only. Written in FPM pool admin blocks and, when `mod_php` is loaded, the Apache admin file. The ini drop-in does not get this setting |
| `pm.max_requests=1` | `--max-requests-1` only |

The 8M and 32M post sizes are the figures in the out-of-memory advisory. 2M and 8M are this tool's choices for a smaller `upload_max_filesize`. `--yes` does not pick a post size, does not set `memory_limit=-1`, and does not set `pm.max_requests=1`.

`memory_limit=-1` removes PHP's own memory guard. The advisory says an allocation failure can still reach the bug, so pair it with a cgroup `memory.max`. The tool never sets `RLIMIT_AS` or `RLIMIT_DATA`, because those limits take the vulnerable path. It prints example nginx `client_max_body_size` / `large_client_header_buffers` lines and Apache `LimitRequestBody` / `LimitRequestFields` / `LimitRequestFieldSize` lines. Those numbers are illustrative. It does not edit nginx, Apache proxy config, or a WAF. Part count and nesting are not applied from invented nginx directives.

When those settings turn upload progress off, and on PHP 8.5 also turn fatal backtraces off, the rescan says MITIGATED. The tool still prints that the install is vulnerable until PHP is upgraded.

`--rollback <stamp>` restores the config files from that backup and restarts the recorded services. It does not downgrade packages. The manifest lists the package versions from before the change so you can reinstall them yourself. Created paths are removed only when the basename contains `stacutis-php2shell` and the path is under `/etc`, `/usr/local/etc`, or `/usr/local/lsws/conf`.

Actions are appended to `/var/log/stacutis-php2shell.log` (mode 600). A scan does not create that file unless you pass `--log`.

## What the tool does not do

- It does not scan other hosts, spread, or send telemetry.
- It does not change a file, install a package, or restart a service without a yes for that action. `--dry-run` prints the plan and writes nothing.
- It does not compile PHP and it does not add apt, dnf, or apk repositories.
- It does not phone home. The only network use is the package manager, during a confirmed fix, when it refreshes metadata and downloads the packages you already asked it to install.
- It does not treat indicators of compromise as proof, and it does not block the addresses below. AWS published them as shared anonymization infrastructure: `103.216.220.92` (17 October 2026), `31.223.184.166`, `37.19.200.5`, `134.209.159.64`, `103.114.163.188`, `95.217.98.37` (21 October 2026).

## Install

Read the script before you run it. Do not pipe the download into a shell.

```sh
curl -fsSL https://stacutis.com/php2shell.sh -o php2shell.sh
less php2shell.sh
# Download CHECKSUMS.txt from the same place, then:
sha256sum -c CHECKSUMS.txt
sudo bash php2shell.sh
```

The file in this tree is `stacutis-php2shell.sh`. A publisher who uses the URL above is serving that script under the shorter name. There is no project URL hardcoded in the tool. Fill in the real release page when you publish one. Do not guess an organization name.

The script is POSIX-oriented bash. It needs bash 4.3 or newer (arrays, `mapfile`, `${var,,}`, namerefs) and the usual coreutils, grep, sed, and awk. BusyBox `sh` is not enough. On Alpine, install bash first. A package manager is required only for `--fix`.

Scan mode works without root and warns about files it could not read. `--fix`, `--workarounds`, and `--rollback` require root, except `--dry-run` and `--test-root`.

## Usage

```text
stacutis-php2shell.sh [options]
```

```text
sudo bash php2shell.sh
sudo bash php2shell.sh --json
sudo bash php2shell.sh --ioc
sudo bash php2shell.sh --dry-run --fix
sudo bash php2shell.sh --fix --yes
sudo bash php2shell.sh --workarounds --yes --upload-policy none
sudo bash php2shell.sh --rollback 20261022T153000Z --yes
```

### Flags

| Flag | Effect |
| --- | --- |
| `--json` | One JSON document on stdout. Progress goes to stderr. |
| `--quiet` | One human summary line. |
| `--no-color` | Plain text. Also plain when stdout is not a terminal, when `NO_COLOR` is set, or when `--json` is set. |
| `--ioc` | Read-only indicators since 2026-10-17. |
| `--containers` | List local Docker containers that look like PHP. |
| `--containers-exec` | With `--containers`, run `php -v` in those containers. |
| `--log` | Append the scan summary to the log. |
| `--dry-run` | Show changes and write nothing. A vulnerable host still exits 1. |
| `--yes` | Answer yes to prompts for an action you already named. |
| `--fix` | Upgrade packages whose candidate is a confirmed fix. |
| `--workarounds` | Apply temporary settings. |
| `--upload-policy none\|uploads` | With `--workarounds`, set the post and upload limits above. |
| `--allow-unlimited-memory` | With `--workarounds`, lock `memory_limit=-1` in web-SAPI admin config. |
| `--max-requests-1` | With `--workarounds`, set `pm.max_requests=1`. |
| `--rollback STAMP` | Restore `/var/backups/stacutis/STAMP`. The stamp looks like `20261022T153000Z`. |
| `--test-root DIR` | Test mode. `DIR` must be absolute, must not be a system directory, and must contain `fixture/IS_TEST_ROOT`. |
| `--version` | Print the tool version and the CVE data date. |
| `--help` | Print usage. |

`--fix` and `--workarounds` cannot be combined. `--rollback` cannot be combined with either. The upload, memory, and max-requests flags belong with `--workarounds`.

### Exit codes

| Code | Meaning |
| --- | --- |
| 0 | No PHP was found, or every finding is PATCHED. |
| 1 | At least one finding is VULNERABLE or MITIGATED. MITIGATED is still vulnerable. A declined change on a vulnerable host also exits 1. |
| 2 | Bad usage. |
| 3 | At least one finding is UNKNOWN, and none are VULNERABLE or MITIGATED. |
| 4 | A requested change failed: no confirmed package, metadata refresh failed, a restart failed, or a deleted binary is still mapped after an upgrade that otherwise looked patched. |
| 5 | A change needs root. |

`--ioc` does not change the code. Exit 0 does not mean the host was checked for compromise.

## JSON

`--json` prints one object. `schema_version` is `1`. After `--fix` or a real `--workarounds` run, the object is the scan from after the change. `ioc` is `null` unless `--ioc` was passed. `containers` is `null` unless `--containers` was passed.

```json
{
  "schema_version": 1,
  "tool": "stacutis-php2shell",
  "tool_version": "1.0.0",
  "cve_data_date": "2026-10-22",
  "cves": ["CVE-2026-109618", "CVE-2026-109619"],
  "fixed_upstream": ["8.5.12", "8.4.27", "8.3.36", "8.2.35"],
  "hostname": "web01",
  "scanned_at": "2026-10-22T00:00:00Z",
  "os": {"id": "ubuntu", "version": "22.04", "pretty": "Ubuntu 22.04", "package_manager": "apt"},
  "counts": {"vulnerable": 1, "mitigated": 0, "patched": 0, "unknown": 0},
  "mod_php": false,
  "running_deleted_binary": false,
  "findings": [
    {
      "sapi": "fpm",
      "path": "/usr/sbin/php-fpm8.3",
      "version": "8.3.6",
      "prerelease": false,
      "version_string": "PHP 8.3.6 (cli)",
      "package": "php8.3-fpm",
      "package_version": "8.3.6-1",
      "backport": "unchecked",
      "status": "VULNERABLE",
      "kind": "none",
      "detail": "8.3.6 is older than the fixed release 8.3.36",
      "changelog_note": "no-changelog",
      "risk": "high",
      "session_upload_progress_enabled": "On",
      "session_upload_progress_source": "default",
      "memory_limit": "128M",
      "memory_limit_source": "ini",
      "post_max_size": "8M",
      "post_max_size_source": "ini",
      "upload_max_filesize": "2M",
      "upload_max_filesize_source": "ini",
      "fatal_error_backtraces": "n/a",
      "fatal_error_backtraces_source": "n/a",
      "pm_max_requests": "www=500",
      "running_deleted": false,
      "note": ""
    }
  ],
  "ioc": null,
  "containers": null,
  "warnings": [],
  "actions": []
}
```

`status` is `VULNERABLE`, `PATCHED`, `MITIGATED`, or `UNKNOWN`. `kind` is `version`, `backport`, or `none`. `backport` is `both`, `one`, `none`, or `unchecked`. `risk` is `highest` for mod_php, `high` for FPM, CGI, FrankenPHP, and LiteSpeed, and `low` for CLI. `changelog_note` is empty, `partial-changelog`, `no-changelog`, or `changelog-without-cve`.

When `--ioc` is set, `ioc` is an object with `since`, `crash_lines`, `upload_progress_requests`, `webshell_hits`, `child_processes`, `outbound`, `watched_ip_hits`, and `notes`. Entries are locations and pattern ids. When `--containers` is set, `containers` is an object with `rows` and `notes`.

## Verify a download

`CHECKSUMS.txt` is the SHA-256 of `stacutis-php2shell.sh`. Check it before you run the script:

```sh
sha256sum -c CHECKSUMS.txt
```

A checksum only helps if it arrived by a path you trust. A signature helps only if the public key arrived by a second path. This tree does not contain a private key, a public key, or a signature. Generate those when you publish.

GnuPG, detached ASCII signature:

```sh
gpg --detach-sign --armor --output stacutis-php2shell.sh.asc stacutis-php2shell.sh
gpg --verify stacutis-php2shell.sh.asc stacutis-php2shell.sh
```

minisign:

```sh
minisign -Sm stacutis-php2shell.sh
minisign -Vm stacutis-php2shell.sh -p stacutis.pub
```

Publish the `.asc` or `.minisig` next to the script. Publish the public key somewhere else (a release announcement you already control, a keyserver plus a fingerprint printed on a second site). Operators should compare the fingerprint before `--verify` / `-Vm`.

## Tests

`bash tests/run-hermetic.sh` runs the classification, backport, dry-run, fix, workaround, rollback, and indicator cases against fixtures. `tests/TEST-PLAN.md` lists the Docker images (`ubuntu:22.04`, `ubuntu:24.04`, `debian:12`, `almalinux:9`, `alpine:3.20`) and how to run them. The Docker suite was not executed in the environment that produced this tree: the Docker socket was not accessible.

## Files

| File | Role |
| --- | --- |
| `stacutis-php2shell.sh` | The scanner |
| `LICENSE` | MIT |
| `CHECKSUMS.txt` | SHA-256 of the scanner |
| `tests/run-hermetic.sh` | Host test runner |
| `tests/TEST-PLAN.md` | Cases and Docker images |
| `site/index.html` | Static page for stacutis.com |
