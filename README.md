# Stacutis PHP2Shell scanner

A small bash script that checks a Linux server for PHP2Shell (CVE-2026-109618 / CVE-2026-109619) and, only if you say yes, fixes it.

## Quick start

Download, check, read, then run. Please don't pipe it into a shell.

```sh
cd /tmp
curl -fsSL -o stacutis-php2shell.sh https://www.stacutis.com/php2shell.sh
curl -fsSL -O https://www.stacutis.com/CHECKSUMS.txt
sha256sum -c CHECKSUMS.txt       # must say: stacutis-php2shell.sh: OK
less stacutis-php2shell.sh    # read it, it's plain bash
bash stacutis-php2shell.sh    # scan only, changes nothing
```

Official download: https://www.stacutis.com/php2shell.sh (same file as `stacutis-php2shell.sh` in this repo, SHA256 in `CHECKSUMS.txt`).

A checksum only proves the download wasn't broken. If you want more, compare it with the one in this repo and read the script. It's one file, no dependencies besides bash 4.3+.

## What it checks

- Every PHP it can find: CLI, PHP-FPM, mod_php, php-cgi, FrankenPHP, LiteSpeed lsphp.
- Version against the fixed releases: 8.5.12, 8.4.27, 8.3.36, 8.2.35.
- Your distro's package changelog, so backported fixes count as PATCHED.
- Optional: `--ioc` looks for signs of exploitation in logs, `--containers` lists PHP-looking Docker containers.

The scan is read-only, works without root, uses no network and sends nothing anywhere.

## What it changes

Nothing, unless you pass one of these flags **and** answer `y` (or add `--yes`). Add `--dry-run` to any of them to see the plan without writing anything.

| Option | Touches | Undo |
| --- | --- | --- |
| `--fix` | Upgrades installed PHP packages with your package manager (`apt-get install --only-upgrade`, `dnf/yum upgrade`, `apk upgrade`), same branch only. Restarts PHP-FPM / Apache so workers load the new code. No new repos, no compiling. | A normal package downgrade, if you really need one. |
| `--workarounds` | Writes `<php conf.d>/99-stacutis-php2shell.ini`, adds a marked `stacutis-php2shell` block to vulnerable FPM pool files, and on mod_php hosts writes `/etc/apache2/conf-available/stacutis-php2shell.conf` (+ `conf-enabled` link) or `/etc/httpd/conf.d/stacutis-php2shell.conf`. Restarts those services. | `--rollback <stamp>` (see below). |
| `--log` | Appends one line to `/var/log/stacutis-php2shell.log`. | Delete the file. |

Workarounds are temporary, not a fix. By default they only turn off `session.upload_progress` (and fatal error backtraces on 8.5). Smaller post/upload limits, `memory_limit=-1` and `pm.max_requests=1` each need their own flag because they can break things. Tradeoffs are printed in red before each prompt; full list in [docs/DETAILS.md](docs/DETAILS.md#workaround-tradeoffs).

## Undo

Before any workaround is written, the touched files are copied to `/var/backups/stacutis/<stamp>/` (stamp looks like `20261022T153000Z`).

```sh
ls /var/backups/stacutis/
sudo bash stacutis-php2shell.sh --rollback 20261022T153000Z
```

That restores the files and restarts the services it had restarted. Package upgrades are not rolled back.

## Options

| Flag | What it does |
| --- | --- |
| *(none)* | Read-only scan |
| `--fix` | Upgrade PHP packages (asks first) |
| `--workarounds` | Temporary settings (asks first) |
| `--upload-policy none\|uploads` | With workarounds: post 8M/upload 2M, or 32M/8M |
| `--allow-unlimited-memory` | With workarounds: `memory_limit=-1` |
| `--max-requests-1` | With workarounds: `pm.max_requests=1` |
| `--rollback STAMP` | Restore a workaround backup |
| `--dry-run` | Show what would change, write nothing |
| `--yes` | Say yes to the action you picked (doesn't pick one for you) |
| `--ioc` / `--containers` / `--containers-exec` | Extra read-only checks |
| `--json` / `--quiet` / `--no-color` / `--log` | Output options |
| `--help` / `--version` | |

Exit codes: 0 patched or no PHP, 1 vulnerable or only mitigated, 2 bad usage, 3 unknown, 4 change failed, 5 needs root.

## License and credits

MIT, see `LICENSE`. Provided as-is; run it only on servers you administer and keep a backup. Built by Victor Soares ([Stacutis](https://www.stacutis.com)). Advisory sources and the deep details are in [docs/DETAILS.md](docs/DETAILS.md). Tests: `bash tests/run-hermetic.sh`.
