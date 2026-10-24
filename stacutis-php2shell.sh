#!/usr/bin/env bash
# stacutis-php2shell: scan a Linux host for PHP2Shell
# (CVE-2026-109618 / CVE-2026-109619) and, only if you say yes, fix it.
#
# What it reads (default, scan only):
#   - php / php-fpm / php-cgi / lsphp / frankenphp binaries and their -v output
#   - PHP ini files, FPM pool configs, Apache config (to spot mod_php)
#   - the local package database and package changelogs (dpkg, rpm, apk)
#   - with --ioc: web and PHP logs; with --containers: docker ps
#
# What it may change (only with --fix, --workarounds or --rollback, and only
# after you answer y, or pass --yes):
#   --fix          upgrades installed PHP packages with apt/dnf/yum/apk,
#                  then restarts PHP-FPM / Apache so workers load the new code
#   --workarounds  writes <php conf.d>/99-stacutis-php2shell.ini, adds a
#                  marked block to vulnerable FPM pool files, and on mod_php
#                  hosts writes stacutis-php2shell.conf in the Apache config
#                  dir; backs up first to /var/backups/stacutis/<stamp>/ and
#                  restarts the affected services
#   --rollback     restores a backup made by --workarounds
#   --log          appends one summary to /var/log/stacutis-php2shell.log
#
# What it never does: send data anywhere, phone home, add repositories,
# compile PHP, or touch other hosts. The scan itself does not use the network.
# --dry-run shows what a change would do without writing anything.
#
# Provided as-is. Run it only on systems you own or administer, and take
# a backup before you answer yes to a change.
# SPDX-License-Identifier: MIT
#
# CVE data date: 2026-10-22
# CVE-2026-109618  CVE-2026-109619
# Fixed upstream: 8.5.12, 8.4.27, 8.3.36, 8.2.35
# https://www.php.net/archive/2026.php#2026-10-21-5

# --- settings and state (nothing below runs until main at the bottom) ---

set -euo pipefail
IFS=$'\n\t'

TOOL_NAME="stacutis-php2shell"
TOOL_VERSION="1.0.0"
CVE_DATA_DATE="2026-10-22"
CVE_DATA_EPOCH=1792627200
CVE_A="CVE-2026-109618"
CVE_B="CVE-2026-109619"
IOC_SINCE="2026-10-17"
IOC_EPOCH=1792195200
SCHEMA_VERSION=1

JSON=0
QUIET=0
FLAG_NO_COLOR=0
DO_LOG=0
LOG_FOR_SCAN=0
DO_IOC=0
DO_CONTAINERS=0
CONTAINERS_EXEC=0
DRY_RUN=0
ASSUME_YES=0
DO_FIX=0
DO_WORK=0
UPLOAD_POLICY=""
DO_UNLIMITED_MEM=0
DO_MAX_REQUESTS=0
ROLLBACK=""
TEST_ROOT=""

USE_COLOR=0
RED=""
GREEN=""
YELLOW=""
MAGENTA=""
CYAN=""
BOLD=""
RESET=""

OS_ID="unknown"
OS_VERSION="unknown"
OS_PRETTY="unknown"
PM="unknown"
MOD_PHP=0
ANY_RUNNING_DELETED=0
RESTARTS_DONE=0
BACKUP_DIR=""
BACKUP_STAMP=""

WARNINGS=()
ACTIONS=()
WEB_USERS=()

F_SAPI=()
F_PATH=()
F_VERSION=()
F_PRE=()
F_RAW=()
F_PKG=()
F_PKGVER=()
F_BACKPORT=()
F_UP=()
F_UPSRC=()
F_MEM=()
F_MEMSRC=()
F_POST=()
F_POSTSRC=()
F_UMAX=()
F_UMAXSRC=()
F_FATAL=()
F_FATALSRC=()
F_PM=()
F_RISK=()
F_DROPIN=()
F_MAININI=()
F_POOLS=()
F_NOTE=()
F_DELETED=()
F_STATUS=()
F_KIND=()
F_DETAIL=()
F_CNOTE=()

IOC_CRASHES=()
IOC_UPLOADS=()
IOC_SHELLS=()
IOC_CHILDREN=()
IOC_OUTBOUND=()
IOC_IP_HITS=()
IOC_NOTES=()

WATCHED_IPS=(
  "103.216.220.92"
  "31.223.184.166"
  "37.19.200.5"
  "134.209.159.64"
  "103.114.163.188"
  "95.217.98.37"
)

usage() {
  cat <<'EOF'
stacutis-php2shell: local PHP2Shell scanner and patch helper

Usage:
  stacutis-php2shell.sh [options]

The default is a read-only scan. A scan does not write config, does not
restart services, and does not call the network. Logging a scan is off
unless you pass --log.

Options:
  --json                 Machine-readable report on stdout
  --quiet                One-line human summary
  --no-color             Plain text even on a terminal
  --ioc                  Read-only compromise indicators since 2026-10-17
  --containers           List local Docker containers that look like PHP
  --containers-exec      With --containers, run "php -v" inside them
  --log                  Append the scan to /var/log/stacutis-php2shell.log
  --dry-run              Show changes and write nothing
  --yes                  Answer yes to prompts for an action you named
  --fix                  Upgrade installed PHP packages if the repo has a fix
  --workarounds          Apply temporary settings (not a fix)
  --upload-policy VALUE  none (post 8M) or uploads (post 32M)
  --allow-unlimited-memory
                         Also set memory_limit=-1 with php_admin_value
  --max-requests-1       Also set pm.max_requests=1 on FPM pools
  --rollback STAMP       Restore configs from /var/backups/stacutis/STAMP
  --test-root DIR        Test mode. DIR must contain fixture/IS_TEST_ROOT
  --version
  --help

--yes does not choose an action. Combine it with --fix, --workarounds,
or --rollback. --workarounds --yes turns off session upload progress and,
on PHP 8.5, fatal error backtraces. Post size, memory_limit=-1, and
pm.max_requests=1 stay off unless their flags are set.

Exit codes:
  0  no vulnerable install found
  1  vulnerable or only mitigated (mitigated is still vulnerable)
  2  bad usage
  3  a PHP install could not be classified
  4  a requested change failed
  5  a change needs root
EOF
}

print_version() {
  printf '%s %s\n' "$TOOL_NAME" "$TOOL_VERSION"
  printf 'CVE data date: %s\n' "$CVE_DATA_DATE"
  printf 'CVEs: %s %s (CVSS v4.0 9.2)\n' "$CVE_A" "$CVE_B"
  printf 'Fixed upstream: 8.5.12, 8.4.27, 8.3.36, 8.2.35\n'
}

die_usage() {
  printf 'error: %s\n' "$1" >&2
  printf 'Run with --help for usage.\n' >&2
  exit 2
}

warn() {
  local msg=$1
  WARNINGS+=("$msg")
  if [[ "$QUIET" -eq 0 || "$JSON" -eq 0 ]]; then
    printf '%swarning:%s %s\n' "$YELLOW" "$RESET" "$msg" >&2
  fi
}

err() {
  printf '%serror:%s %s\n' "$RED" "$RESET" "$1" >&2
}

note_action() {
  ACTIONS+=("$1")
  log_line "$1"
}

rootp() {
  local logical=$1
  if [[ "$logical" != /* ]]; then
    printf '%s\n' "$logical"
    return 0
  fi
  if [[ -n "$TEST_ROOT" ]]; then
    printf '%s%s\n' "$TEST_ROOT" "$logical"
  else
    printf '%s\n' "$logical"
  fi
}

setup_colors() {
  USE_COLOR=0
  if [[ "$JSON" -eq 0 && "$FLAG_NO_COLOR" -eq 0 && -z "${NO_COLOR:-}" && -t 1 ]]; then
    USE_COLOR=1
  fi
  if [[ "$USE_COLOR" -eq 1 ]]; then
    RED=$'\033[31m'
    GREEN=$'\033[32m'
    YELLOW=$'\033[33m'
    MAGENTA=$'\033[35m'
    CYAN=$'\033[36m'
    BOLD=$'\033[1m'
    RESET=$'\033[0m'
  else
    RED=""
    GREEN=""
    YELLOW=""
    MAGENTA=""
    CYAN=""
    BOLD=""
    RESET=""
  fi
}

say() {
  if [[ "$JSON" -eq 1 ]]; then
    printf '%s\n' "$*" >&2
    return 0
  fi
  if [[ "$QUIET" -eq 1 ]]; then
    return 0
  fi
  printf '%s\n' "$*"
}

# Human text follows say(): stderr under --json, nothing under --quiet.
out() {
  if [[ "$JSON" -eq 1 ]]; then
    printf '%s\n' "$1" >&2
    return 0
  fi
  if [[ "$QUIET" -eq 1 ]]; then
    return 0
  fi
  printf '%s\n' "$1"
}

# Tradeoff lines stay visible under --quiet and --json (stderr), in red on a terminal.
tradeoff() {
  local line="${RED}${BOLD}Tradeoff:${RESET} ${RED}$1${RESET}"
  if [[ "$JSON" -eq 1 || "$QUIET" -eq 1 ]]; then
    printf '%s\n' "$line" >&2
    return 0
  fi
  printf '\n%s\n' "$line"
}

workaround_banner() {
  local line="${RED}${BOLD}These settings leave the vulnerable PHP installed. MITIGATED is still vulnerable. The config is tested first, then PHP is reloaded. If a reload is not possible it restarts, which drops requests in flight.${RESET}"
  if [[ "$JSON" -eq 1 || "$QUIET" -eq 1 ]]; then
    printf '%s\n' "$line" >&2
    return 0
  fi
  printf '\n%s\n' "$line"
}

checked_again() {
  out ""
  out "${BOLD}Checked again${RESET}"
}

emit_notice() {
  if [[ "$JSON" -eq 1 || "$QUIET" -eq 1 ]]; then
    cat >&2
  else
    cat
  fi
}

log_line() {
  local f msg
  if [[ "$DO_LOG" -eq 0 ]]; then
    return 0
  fi
  f=$(rootp /var/log/stacutis-php2shell.log)
  if ! mkdir -p "$(dirname "$f")" 2>/dev/null; then
    warn "cannot create $(dirname "$f"); actions will not be logged"
    DO_LOG=0
    return 0
  fi
  msg=$1
  if ! printf '%s %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$msg" >>"$f" 2>/dev/null; then
    warn "cannot append to $f"
    DO_LOG=0
    return 0
  fi
  chmod 600 "$f" 2>/dev/null || true
}

json_escape() {
  local s=$1
  s=${s//\\/\\\\}
  s=${s//\"/\\\"}
  s=${s//$'\n'/\\n}
  s=${s//$'\r'/\\r}
  s=${s//$'\t'/\\t}
  if [[ "$s" == *[$'\x01'-$'\x1f'$'\x7f']* ]]; then
    local out="" c i
    for ((i = 0; i < ${#s}; i++)); do
      c=${s:i:1}
      case "$c" in
        [$'\x01'-$'\x1f'$'\x7f']) printf -v c '\\u%04x' "'$c" ;;
      esac
      out+=$c
    done
    s=$out
  fi
  printf '%s' "$s"
}

json_string() {
  printf '"%s"' "$(json_escape "$1")"
}

confirm() {
  local prompt=$1 reply
  if [[ "$DRY_RUN" -eq 1 ]]; then
    say "dry-run: would ask: ${prompt}"
    return 1
  fi
  if [[ "$ASSUME_YES" -eq 1 ]]; then
    note_action "confirmed via --yes: ${prompt}"
    return 0
  fi
  if [[ ! -t 0 ]]; then
    warn "no terminal on stdin; refusing this change. Pass --yes to confirm it."
    return 1
  fi
  printf '\n%s%s%s %s[y/N]%s ' "$BOLD" "$prompt" "$RESET" "$YELLOW" "$RESET" >&2
  if ! read -r reply; then
    return 1
  fi
  [[ "$reply" == "y" || "$reply" == "Y" ]]
}

require_root() {
  if [[ "$DRY_RUN" -eq 1 || -n "$TEST_ROOT" ]]; then
    return 0
  fi
  if [[ "$(id -u)" -ne 0 ]]; then
    err "this change needs root. Re-run with sudo."
    exit 5
  fi
}

trim() {
  local s=$1
  s=${s#"${s%%[![:space:]]*}"}
  s=${s%"${s##*[![:space:]]}"}
  printf '%s' "$s"
}

lower() {
  printf '%s' "${1,,}"
}

is_off() {
  case "$(lower "$1")" in
    0|off|false|no) return 0 ;;
    *) return 1 ;;
  esac
}

is_on() {
  case "$(lower "$1")" in
    1|on|true|yes) return 0 ;;
    *) return 1 ;;
  esac
}

parse_args() {
  while [[ $# -gt 0 ]]; do
    case "$1" in
      -h|--help) usage; exit 0 ;;
      --version) print_version; exit 0 ;;
      --json) JSON=1 ;;
      --quiet) QUIET=1 ;;
      --no-color) FLAG_NO_COLOR=1 ;;
      --log) LOG_FOR_SCAN=1 ;;
      --ioc) DO_IOC=1 ;;
      --containers) DO_CONTAINERS=1 ;;
      --containers-exec) DO_CONTAINERS=1; CONTAINERS_EXEC=1 ;;
      --dry-run) DRY_RUN=1 ;;
      --yes) ASSUME_YES=1 ;;
      --fix) DO_FIX=1 ;;
      --workarounds) DO_WORK=1 ;;
      --upload-policy)
        shift
        [[ $# -gt 0 ]] || die_usage "--upload-policy needs none or uploads"
        UPLOAD_POLICY=$1
        ;;
      --allow-unlimited-memory) DO_UNLIMITED_MEM=1 ;;
      --max-requests-1) DO_MAX_REQUESTS=1 ;;
      --rollback)
        shift
        [[ $# -gt 0 ]] || die_usage "--rollback needs a timestamp"
        ROLLBACK=$1
        ;;
      --test-root)
        shift
        [[ $# -gt 0 ]] || die_usage "--test-root needs a directory"
        TEST_ROOT=$1
        ;;
      --)
        shift
        break
        ;;
      -*)
        die_usage "unknown option: $1"
        ;;
      *)
        die_usage "unexpected argument: $1"
        ;;
    esac
    shift
  done
  if [[ $# -gt 0 ]]; then
    die_usage "unexpected argument: $1"
  fi
  if [[ -n "$UPLOAD_POLICY" && "$UPLOAD_POLICY" != "none" && "$UPLOAD_POLICY" != "uploads" ]]; then
    die_usage "--upload-policy must be none or uploads"
  fi
  if [[ "$DO_FIX" -eq 1 && "$DO_WORK" -eq 1 ]]; then
    die_usage "use either --fix or --workarounds"
  fi
  if [[ -n "$ROLLBACK" && ( "$DO_FIX" -eq 1 || "$DO_WORK" -eq 1 ) ]]; then
    die_usage "--rollback cannot be combined with --fix or --workarounds"
  fi
  if [[ -n "$UPLOAD_POLICY" || "$DO_UNLIMITED_MEM" -eq 1 || "$DO_MAX_REQUESTS" -eq 1 ]]; then
    if [[ "$DO_WORK" -eq 0 ]]; then
      die_usage "post-size, memory, and max-requests flags belong with --workarounds"
    fi
  fi
  if [[ -n "$ROLLBACK" && ! "$ROLLBACK" =~ ^[0-9]{8}T[0-9]{6}Z(-[0-9]+)?$ ]]; then
    die_usage "--rollback timestamp must look like 20261022T153000Z"
  fi
  if [[ -n "$TEST_ROOT" ]]; then
    if [[ "$TEST_ROOT" != /* ]]; then
      die_usage "--test-root must be an absolute path"
    fi
    if [[ ! -d "$TEST_ROOT" ]]; then
      die_usage "--test-root is not a directory"
    fi
    TEST_ROOT=$(readlink -f "$TEST_ROOT")
    case "$TEST_ROOT" in
      /|/usr|/etc|/var|/home|/opt|/bin|/sbin|/usr/bin|/usr/sbin)
        die_usage "--test-root refuses a system directory"
        ;;
    esac
    if [[ ! -f "$TEST_ROOT/fixture/IS_TEST_ROOT" ]]; then
      die_usage "--test-root must contain fixture/IS_TEST_ROOT"
    fi
  fi
}

parse_php_version_text() {
  local text=$1 line suffix
  PARSED_OK=0
  PARSED_PRE=0
  PARSED_MAJOR=0
  PARSED_MINOR=0
  PARSED_PATCH=0
  PARSED_TRIPLE=""
  line=$(printf '%s\n' "$text" | awk '/^PHP /{print; exit}')
  if [[ -z "$line" ]]; then
    line=$text
  fi
  if [[ "$line" =~ PHP[[:space:]]+([0-9]+)\.([0-9]+)\.([0-9]+)([^[:space:]]*) ]]; then
    PARSED_MAJOR=${BASH_REMATCH[1]}
    PARSED_MINOR=${BASH_REMATCH[2]}
    PARSED_PATCH=${BASH_REMATCH[3]}
    suffix=${BASH_REMATCH[4]}
    PARSED_OK=1
  fi
  if [[ "$PARSED_OK" -eq 0 ]]; then
    local bare=${line#*:}
    if [[ "$bare" =~ ([0-9]+)\.([0-9]+)\.([0-9]+)([^[:space:]]*) ]]; then
      PARSED_MAJOR=${BASH_REMATCH[1]}
      PARSED_MINOR=${BASH_REMATCH[2]}
      PARSED_PATCH=${BASH_REMATCH[3]}
      suffix=${BASH_REMATCH[4]}
      PARSED_OK=1
    fi
  fi
  if [[ "$PARSED_OK" -eq 1 ]]; then
    PARSED_TRIPLE="${PARSED_MAJOR}.${PARSED_MINOR}.${PARSED_PATCH}"
    if [[ "$suffix" =~ ^[-.]?(RC|rc|alpha|beta|dev|Alpha|Beta|DEV) ]]; then
      PARSED_PRE=1
    fi
  fi
}

fixed_triple() {
  case "$1.$2" in
    8.5) printf '%s\n' "8.5.12" ;;
    8.4) printf '%s\n' "8.4.27" ;;
    8.3) printf '%s\n' "8.3.36" ;;
    8.2) printf '%s\n' "8.2.35" ;;
    *) return 1 ;;
  esac
}

version_ge() {
  local a1 a2 a3 b1 b2 b3
  IFS='.' read -r a1 a2 a3 <<<"$1"
  IFS='.' read -r b1 b2 b3 <<<"$2"
  a1=${a1:-0}; a2=${a2:-0}; a3=${a3:-0}
  b1=${b1:-0}; b2=${b2:-0}; b3=${b3:-0}
  if ((10#$a1 > 10#$b1)); then return 0; fi
  if ((10#$a1 < 10#$b1)); then return 1; fi
  if ((10#$a2 > 10#$b2)); then return 0; fi
  if ((10#$a2 < 10#$b2)); then return 1; fi
  ((10#$a3 >= 10#$b3))
}

branch_class() {
  local major=$1 minor=$2
  if ((major == 8 && minor >= 2 && minor <= 5)); then
    printf '%s\n' "fixed-line"
  elif ((major > 8 || (major == 8 && minor >= 6))); then
    printf '%s\n' "outside"
  else
    printf '%s\n' "eol"
  fi
}

# classify_result VERSION_TEXT BACKPORT UPLOAD_OFF FATAL_OFF
# BACKPORT: both|one|none|unchecked
# UPLOAD_OFF / FATAL_OFF: 1 only when the setting is explicitly off.
# Prints STATUS|KIND|DETAIL|NOTE
classify_result() {
  local text=$1 backport=$2 upload_off=$3 fatal_off=$4
  local note="" fixed class
  parse_php_version_text "$text"
  if [[ "$backport" == "one" ]]; then
    note="partial-changelog"
  elif [[ "$backport" == "unchecked" ]]; then
    note="no-changelog"
  elif [[ "$backport" == "missing" ]]; then
    note="changelog-not-installed"
  elif [[ "$backport" == "none" ]]; then
    note="changelog-without-cve"
  fi

  if [[ "$PARSED_OK" -eq 1 && "$PARSED_PRE" -eq 0 ]]; then
    if fixed=$(fixed_triple "$PARSED_MAJOR" "$PARSED_MINOR"); then
      if version_ge "$PARSED_TRIPLE" "$fixed"; then
        printf '%s\n' "PATCHED|version|${PARSED_TRIPLE} is at least the fixed release ${fixed}|${note}"
        return 0
      fi
    fi
  fi

  if [[ "$backport" == "both" ]]; then
    printf '%s\n' "PATCHED|backport|local package changelog names both CVEs|${note}"
    return 0
  fi

  if [[ "$PARSED_OK" -eq 0 ]]; then
    printf '%s\n' "UNKNOWN|none|version could not be parsed|${note}"
    return 0
  fi

  class=$(branch_class "$PARSED_MAJOR" "$PARSED_MINOR")
  if [[ "$class" == "outside" ]]; then
    local extra=""
    if [[ "$PARSED_PRE" -eq 1 ]]; then
      extra=" This build is a pre-release."
    fi
    printf '%s\n' "UNKNOWN|none|branch is outside the ${CVE_DATA_DATE} fixed-release table.${extra}|${note}"
    return 0
  fi

  local detail
  if [[ "$PARSED_PRE" -eq 1 ]]; then
    detail="pre-release is not the security release"
  elif [[ "$class" == "fixed-line" ]]; then
    fixed=$(fixed_triple "$PARSED_MAJOR" "$PARSED_MINOR")
    detail="${PARSED_TRIPLE} is older than the fixed release ${fixed}"
  else
    detail="branch has no upstream fixed release"
  fi

  local need_fatal=0
  if [[ "$PARSED_MAJOR" -eq 8 && "$PARSED_MINOR" -eq 5 ]]; then
    need_fatal=1
  fi
  if [[ "$upload_off" -eq 1 && ( "$need_fatal" -eq 0 || "$fatal_off" -eq 1 ) ]]; then
    printf '%s\n' "MITIGATED|none|stale-state settings are off and the install is still vulnerable|${note}"
    return 0
  fi
  printf '%s\n' "VULNERABLE|none|${detail}|${note}"
}

cve_is_fixed_in_file() {
  local file=$1 cve=$2 line low
  [[ -f "$file" ]] || return 1
  while IFS= read -r line || [[ -n "$line" ]]; do
    [[ "$line" == *"$cve"* ]] || continue
    low=$(lower "$line")
    if [[ "$low" == *not-affected* || "$low" == *"not affected"* || "$low" == *not-vulnerable* || "$low" == *"not vulnerable"* || "$low" == *wontfix* || "$low" == *"won't fix"* || "$low" == *no-dsa* || "$low" == *unfixed* ]]; then
      continue
    fi
    if [[ "$low" =~ (^|[^a-z])ignored([^a-z]|$) ]]; then
      continue
    fi
    return 0
  done <"$file"
  return 1
}

cve_state_file() {
  local file=$1 a=1 b=1
  if cve_is_fixed_in_file "$file" "$CVE_A"; then a=0; fi
  if cve_is_fixed_in_file "$file" "$CVE_B"; then b=0; fi
  if [[ "$a" -eq 0 && "$b" -eq 0 ]]; then
    printf '%s\n' "both"
  elif [[ "$a" -eq 0 || "$b" -eq 0 ]]; then
    printf '%s\n' "one"
  else
    printf '%s\n' "none"
  fi
}

explicit_off() {
  local value=$1 src=$2
  case "$src" in
    admin|pool|ini|apache)
      if is_off "$value"; then
        return 0
      fi
      ;;
  esac
  return 1
}

# --- os, packages, changelogs (read-only) ---

parse_os_release() {
  local f line
  f=$(rootp /etc/os-release)
  OS_ID="unknown"
  OS_VERSION="unknown"
  OS_PRETTY="unknown"
  [[ -r "$f" ]] || return 0
  while IFS= read -r line || [[ -n "$line" ]]; do
    case "$line" in
      ID=*) OS_ID=${line#ID=} ;;
      VERSION_ID=*) OS_VERSION=${line#VERSION_ID=} ;;
      PRETTY_NAME=*) OS_PRETTY=${line#PRETTY_NAME=} ;;
    esac
  done <"$f"
  OS_ID=${OS_ID//\"/}
  OS_VERSION=${OS_VERSION//\"/}
  OS_PRETTY=${OS_PRETTY//\"/}
}

detect_pm() {
  local marker
  if [[ -n "$TEST_ROOT" ]]; then
    marker=$(rootp /fixture/package-manager)
    if [[ -r "$marker" ]]; then
      PM=$(trim "$(<"$marker")")
      return 0
    fi
  fi
  if command -v apt-get >/dev/null 2>&1 && command -v dpkg-query >/dev/null 2>&1; then
    PM="apt"
  elif command -v dnf >/dev/null 2>&1; then
    PM="dnf"
  elif command -v yum >/dev/null 2>&1; then
    PM="yum"
  elif command -v apk >/dev/null 2>&1; then
    PM="apk"
  else
    PM="unknown"
  fi
}

series_from_basename() {
  local b=$1
  SERIES_MAJOR=""
  SERIES_MINOR=""
  if [[ "$b" =~ php-?fpm([0-9])\.([0-9]) || "$b" =~ php([0-9])\.([0-9]) || "$b" =~ libphp([0-9])\.([0-9]) ]]; then
    SERIES_MAJOR=${BASH_REMATCH[1]}
    SERIES_MINOR=${BASH_REMATCH[2]}
    return 0
  fi
  if [[ "$b" =~ php-?fpm([0-9])([0-9])([^0-9]|$) || "$b" =~ php([0-9])([0-9])([^0-9]|$) || "$b" =~ libphp([0-9])([0-9])([^0-9]|$) ]]; then
    SERIES_MAJOR=${BASH_REMATCH[1]}
    SERIES_MINOR=${BASH_REMATCH[2]}
    return 0
  fi
  return 1
}

php_binary_kind() {
  local b=$1
  case "$b" in
    *.conf|*.ini|*.txt|*.md|*.xml|*.default|*.html|*.gz|*.json) printf '\n'; return 0 ;;
    php-config*|phpize*|*-config) printf '\n'; return 0 ;;
    libphp*.so|libphp*.so.*) printf '%s\n' "modphp"; return 0 ;;
    frankenphp) printf '%s\n' "frankenphp"; return 0 ;;
    lsphp|lsphp[0-9]*|lsphp-[0-9]*) printf '%s\n' "litespeed"; return 0 ;;
    phpdbg|php[0-9]*-phpdbg|php[0-9]*dbg) printf '%s\n' "phpdbg"; return 0 ;;
    php-cgi*|php[0-9]*-cgi|php[0-9].[0-9]-cgi) printf '%s\n' "cgi"; return 0 ;;
    php-fpm*|php[0-9]*-fpm|php[0-9].[0-9]-fpm) printf '%s\n' "fpm"; return 0 ;;
    php|php[0-9]|php[0-9][0-9]|php[0-9].[0-9]|php[0-9][0-9][0-9]) printf '%s\n' "cli"; return 0 ;;
  esac
  printf '\n'
}

# Temp files go in one private directory that is removed on exit, even when
# the run stops early.
WORK_TMP=""
tmpfile() {
  if [[ -z "$WORK_TMP" || ! -d "$WORK_TMP" ]]; then
    mktemp
    return
  fi
  mktemp "$WORK_TMP/t.XXXXXX"
}

cleanup_tmp() {
  if [[ -n "$WORK_TMP" && -d "$WORK_TMP" ]]; then
    rm -rf -- "$WORK_TMP"
  fi
}

run_limited() {
  if command -v timeout >/dev/null 2>&1; then
    timeout 10 "$@"
  else
    "$@"
  fi
}

# Owner uid of a path. In --test-root, fixture/owners can pretend a file
# belongs to someone else ("<logical path> <uid>" per line).
path_owner() {
  local p=$1 logical line lp uid
  if [[ -n "$TEST_ROOT" ]]; then
    logical=${p#"$TEST_ROOT"}
    if [[ -r "$TEST_ROOT/fixture/owners" ]]; then
      while IFS=' ' read -r lp uid || [[ -n "$lp" ]]; do
        if [[ "$lp" == "$logical" ]]; then
          printf '%s\n' "$uid"
          return 0
        fi
      done <"$TEST_ROOT/fixture/owners"
    fi
    printf '0\n'
    return 0
  fi
  stat -c %u -- "$p" 2>/dev/null
}

# A binary is run (for -v) only when root owns it and nobody else can write
# it or any directory above it. Anything else could be a planted program,
# and this scan usually runs as root.
trusted_to_run() {
  local real d owner mode
  real=$(readlink -f -- "$1" 2>/dev/null) || return 1
  [[ -n "$real" && -f "$real" ]] || return 1
  d=$real
  while :; do
    owner=$(path_owner "$d") || return 1
    mode=$(stat -c %a -- "$d" 2>/dev/null) || return 1
    [[ "$owner" == "0" ]] || return 1
    if (( (8#$mode & 8#022) != 0 )); then
      return 1
    fi
    if [[ "$d" == "/" || ( -n "$TEST_ROOT" && "$d" == "$TEST_ROOT" ) ]]; then
      break
    fi
    d=$(dirname -- "$d")
  done
  return 0
}

# Read the version a PHP build carries without running it. PHP embeds
# "X-Powered-By: PHP/<version>" in every SAPI binary and in libphp.so.
static_php_version() {
  local f=$1 hit
  [[ -r "$f" ]] || return 1
  hit=$(LC_ALL=C grep -aoE -m1 'X-Powered-By: PHP/[0-9]+\.[0-9]+\.[0-9]+[A-Za-z0-9.~+-]*' -- "$f" 2>/dev/null | head -n 1 || true)
  [[ -n "$hit" ]] || return 1
  printf 'PHP %s\n' "${hit#X-Powered-By: PHP/}"
}

php_version_text_of() {
  local bin=$1 out
  if ! trusted_to_run "$bin"; then
    static_php_version "$bin" || true
    return 0
  fi
  out=$(run_limited "$bin" -v 2>&1 </dev/null || true)
  if printf '%s\n' "$out" | awk 'BEGIN{e=1} /^PHP /{e=0} END{exit e}'; then
    printf '%s\n' "$out"
    return 0
  fi
  out=$(run_limited "$bin" version 2>&1 </dev/null || true)
  if printf '%s\n' "$out" | awk 'BEGIN{e=1} /^PHP /{e=0} END{exit e}'; then
    printf '%s\n' "$out"
    return 0
  fi
  out=$(run_limited "$bin" php-cli -v 2>&1 </dev/null || true)
  if printf '%s\n' "$out" | awk 'BEGIN{e=1} /^PHP /{e=0} END{exit e}'; then
    printf '%s\n' "$out"
    return 0
  fi
  static_php_version "$bin" || printf '%s\n' "$out"
}

append_changelog_file() {
  local src=$1 dest=$2
  [[ -r "$src" ]] || return 0
  if [[ "$src" == *.gz ]]; then
    gzip -dc -- "$src" >>"$dest" 2>/dev/null || true
  else
    cat -- "$src" >>"$dest" 2>/dev/null || true
  fi
  printf '\n' >>"$dest"
}

# Changelog evidence comes only from the package that owns the binary being
# classified. A changelog from another package in the same series says
# nothing about a hand-built or leftover binary.
collect_changelog_text() {
  local major=$1 minor=$2 pkg=$3 dest=$4
  local rp
  : >"$dest"
  [[ -n "$pkg" && "$pkg" != "unknown" ]] || return 0
  for rp in "/usr/share/doc/${pkg}/changelog.Debian.gz" "/usr/share/doc/${pkg}/changelog.Debian" \
    "/usr/share/doc/${pkg}/changelog.gz" "/usr/share/doc/${pkg}/changelog" "/fixture/changelogs/${pkg}"; do
    append_changelog_file "$(rootp "$rp")" "$dest"
  done
  if [[ -z "$TEST_ROOT" ]] && command -v rpm >/dev/null 2>&1; then
    rpm -q --changelog "$pkg" >>"$dest" 2>/dev/null || true
  fi
}

backport_state_for() {
  local major=$1 minor=$2 pkg=$3
  local tmp state
  if [[ -z "$major" || -z "$minor" || -z "$pkg" || "$pkg" == "unknown" ]]; then
    printf '%s\n' "unchecked"
    return 0
  fi
  tmp=$(tmpfile)
  collect_changelog_text "$major" "$minor" "$pkg" "$tmp"
  if [[ ! -s "$tmp" ]]; then
    rm -f "$tmp"
    printf '%s\n' "missing"
    return 0
  fi
  state=$(cve_state_file "$tmp")
  rm -f "$tmp"
  printf '%s\n' "$state"
}

lookup_fixture_pkg() {
  local path=$1 line p pkg ver
  FIX_PKG=""
  FIX_PKGVER=""
  local table
  table=$(rootp /fixture/installed.tsv)
  [[ -r "$table" ]] || return 1
  while IFS=$'\t' read -r pkg ver p || [[ -n "$pkg" ]]; do
    [[ -z "$pkg" || "$pkg" == \#* ]] && continue
    local abs="$p"
    if [[ -n "$TEST_ROOT" && "$p" == /* && "$p" != "$TEST_ROOT"/* ]]; then
      abs="${TEST_ROOT}${p}"
    fi
    if [[ "$p" == "$path" || "$abs" == "$path" ]]; then
      FIX_PKG=$pkg
      FIX_PKGVER=$ver
      return 0
    fi
  done <"$table"
  return 1
}

pkg_of_path() {
  local path=$1 line pkg
  FOUND_PKG=""
  FOUND_PKGVER=""
  if [[ -n "$TEST_ROOT" ]]; then
    if lookup_fixture_pkg "$path"; then
      FOUND_PKG=$FIX_PKG
      FOUND_PKGVER=$FIX_PKGVER
    fi
    return 0
  fi
  if command -v dpkg-query >/dev/null 2>&1; then
    line=$(dpkg-query -S "$path" 2>/dev/null | awk -F: 'NR==1{print $1; exit}' || true)
    if [[ -n "$line" ]]; then
      FOUND_PKG=${line%%:*}
      FOUND_PKGVER=$(dpkg-query -W -f '${Version}' "$FOUND_PKG" 2>/dev/null || true)
    fi
    return 0
  fi
  if command -v rpm >/dev/null 2>&1; then
    line=$(rpm -qf --queryformat '%{NAME}\t%{EPOCH}:%{VERSION}-%{RELEASE}\n' "$path" 2>/dev/null || true)
    if [[ -n "$line" && "$line" != *"is not owned"* && "$line" != *"not owned"* ]]; then
      FOUND_PKG=${line%%$'\t'*}
      FOUND_PKGVER=${line#*$'\t'}
      if [[ "$FOUND_PKGVER" == "(none):"* ]]; then
        FOUND_PKGVER=${FOUND_PKGVER#(none):}
      fi
    fi
    return 0
  fi
  if command -v apk >/dev/null 2>&1; then
    line=$(apk info -W "$path" 2>/dev/null || true)
    if [[ "$line" =~ owned\ by\ (.+)-([0-9].*)$ ]]; then
      FOUND_PKG=${BASH_REMATCH[1]}
      FOUND_PKGVER=${BASH_REMATCH[2]}
    fi
  fi
}

# --- config parsing (read-only) ---

list_ini_files() {
  local main=$1 dropin=$2
  local f extra rp
  if [[ -n "$main" ]]; then
    rp=$(rootp "$main")
    if [[ -f "$rp" ]]; then
      printf '%s\n' "$rp"
    fi
  fi
  if [[ -n "$dropin" ]]; then
    rp=$(rootp "$dropin")
    if [[ -d "$rp" ]]; then
      local sorted=""
      sorted=$(find -L "$rp" -maxdepth 1 -type f -name '*.ini' 2>/dev/null | sort || true)
      if [[ -n "$sorted" ]]; then
        while IFS= read -r extra; do
          [[ -n "$extra" ]] || continue
          printf '%s\n' "$extra"
        done <<<"$sorted"
      fi
    fi
  fi
}

ini_key_value() {
  local key=$1
  shift
  local f line k v val found=0 scoped
  INI_FOUND=0
  INI_VALUE=""
  for f in "$@"; do
    [[ -f "$f" && -r "$f" ]] || continue
    scoped=0
    while IFS= read -r line || [[ -n "$line" ]]; do
      # Inline trim: no subshell per line.
      line=${line#"${line%%[![:space:]]*}"}
      [[ -z "$line" || "$line" == \;* ]] && continue
      if [[ "$line" == \[* ]]; then
        # [PATH=...] and [HOST=...] apply only to some requests.
        case "${line^^}" in
          "[PATH="*|"[HOST="*) scoped=1 ;;
          *) scoped=0 ;;
        esac
        continue
      fi
      [[ "$scoped" -eq 1 ]] && continue
      [[ "$line" == *"="* ]] || continue
      k=${line%%=*}
      k=${k%"${k##*[![:space:]]}"}
      v=${line#*=}
      v=${v#"${v%%[![:space:]]*}"}
      if [[ "$v" == \"* ]]; then
        v=${v#\"}
        v=${v%%\"*}
      elif [[ "$v" == \'* ]]; then
        v=${v#\'}
        v=${v%%\'*}
      else
        v=${v%%;*}
        v=${v%"${v##*[![:space:]]}"}
      fi
      if [[ "$k" == "$key" ]]; then
        val=$v
        found=1
      fi
    done <"$f"
  done
  if [[ "$found" -eq 1 ]]; then
    INI_FOUND=1
    INI_VALUE=$val
  fi
}

# locate_layout MAJOR MINOR SAPI [BINARY]. Panel builds (cPanel, Plesk,
# CloudLinux) are tried first when the binary lives under their prefix.
locate_layout() {
  local major=$1 minor=$2 sapi=$3 bin=${4:-}
  local dotted="${major}.${minor}" compact="${major}${minor}" sapi_dir
  LOC_MAIN=""
  LOC_DROPIN=""
  LOC_POOLS=""
  case "$sapi" in
    fpm) sapi_dir="fpm" ;;
    modphp) sapi_dir="apache2" ;;
    cgi) sapi_dir="cgi" ;;
    frankenphp|litespeed) sapi_dir="fpm" ;;
    *) sapi_dir="cli" ;;
  esac
  local rows=()
  local cp="/opt/cpanel/ea-php${compact}/root/etc" pl="/opt/plesk/php/${dotted}/etc" alt="/opt/alt/php${compact}/etc"
  case "$bin" in
    /opt/cpanel/ea-php"${compact}"/*) rows+=("${cp}/php.ini|${cp}/php.d|${cp}/php-fpm.d") ;;
    /opt/plesk/php/"${dotted}"/*) rows+=("${pl}/php.ini|${pl}/php.d|${pl}/php-fpm.d") ;;
    /opt/alt/php"${compact}"/*) rows+=("${alt}/php.ini|${alt}/php.d|${alt}/php-fpm.d") ;;
    /usr/local/*) rows+=("/usr/local/etc/php/php.ini|/usr/local/etc/php/conf.d|/usr/local/etc/php-fpm.d") ;;
  esac
  rows+=("/etc/php/${dotted}/${sapi_dir}/php.ini|/etc/php/${dotted}/${sapi_dir}/conf.d|/etc/php/${dotted}/fpm/pool.d")
  rows+=("/etc/php${compact}/php.ini|/etc/php${compact}/conf.d|/etc/php${compact}/php-fpm.d")
  rows+=("/etc/opt/remi/php${compact}/php.ini|/etc/opt/remi/php${compact}/php.d|/etc/opt/remi/php${compact}/php-fpm.d")
  rows+=("/etc/php.ini|/etc/php.d|/etc/php-fpm.d")
  rows+=("/usr/local/etc/php/php.ini|/usr/local/etc/php/conf.d|/usr/local/etc/php-fpm.d")
  local row main drop pools
  for row in "${rows[@]}"; do
    IFS='|' read -r main drop pools <<<"$row"
    local ok=0
    if [[ -f "$(rootp "$main")" || -d "$(rootp "$drop")" ]]; then
      ok=1
    elif [[ "$sapi" == "fpm" && -d "$(rootp "$pools")" ]]; then
      ok=1
    fi
    if [[ "$ok" -eq 1 ]]; then
      LOC_MAIN=$main
      LOC_DROPIN=$drop
      if [[ "$sapi" == "fpm" || "$sapi" == "frankenphp" || "$sapi" == "litespeed" ]]; then
        LOC_POOLS=$pools
      fi
      return 0
    fi
  done
  return 1
}

# Last resort for a layout this tool does not know: ask a trusted CLI binary
# where its ini files are. Never used in --test-root.
php_ini_layout() {
  local bin=$1 kind=$2 outp main drop
  [[ -z "$TEST_ROOT" && ( "$kind" == "cli" || "$kind" == "cgi" ) ]] || return 1
  trusted_to_run "$bin" || return 1
  outp=$(run_limited "$bin" --ini </dev/null 2>/dev/null) || return 1
  main=$(printf '%s\n' "$outp" | awk -F': *' '/^Loaded Configuration File/ {print $2; exit}')
  drop=$(printf '%s\n' "$outp" | awk -F': *' '/^Scan for additional .ini files in/ {print $2; exit}')
  [[ "$main" == "(none)" ]] && main=""
  [[ "$drop" == "(none)" ]] && drop=""
  drop=${drop%%:*}
  [[ -n "$main" || -n "$drop" ]] || return 1
  LOC_MAIN=$main
  LOC_DROPIN=$drop
  LOC_POOLS=""
  return 0
}

pool_files_in() {
  local dir=$1 f rp
  [[ -n "$dir" ]] || return 0
  rp=$(rootp "$dir")
  [[ -d "$rp" ]] || return 0
  for f in "$rp"/*.conf; do
    [[ -f "$f" ]] || continue
    printf '%s\n' "$f"
  done
}

# Prints records:
# admin|key|value
# pool|key|value
# pm|section|value
# user|section|value
parse_pool_records() {
  local file=$1 line k v sec
  sec="default"
  while IFS= read -r line || [[ -n "$line" ]]; do
    line=${line%%;*}
    line=$(trim "$line")
    [[ -z "$line" ]] && continue
    if [[ "$line" =~ ^\[(.+)\]$ ]]; then
      sec=${BASH_REMATCH[1]}
      continue
    fi
    if [[ "$line" =~ ^php_admin_flag\[([^]]+)\][[:space:]]*=[[:space:]]*(.+)$ ]]; then
      printf 'admin|%s|%s\n' "${BASH_REMATCH[1]}" "$(trim "${BASH_REMATCH[2]}")"
      continue
    fi
    if [[ "$line" =~ ^php_admin_value\[([^]]+)\][[:space:]]*=[[:space:]]*(.+)$ ]]; then
      printf 'admin|%s|%s\n' "${BASH_REMATCH[1]}" "$(trim "${BASH_REMATCH[2]}")"
      continue
    fi
    if [[ "$line" =~ ^php_flag\[([^]]+)\][[:space:]]*=[[:space:]]*(.+)$ ]]; then
      printf 'pool|%s|%s\n' "${BASH_REMATCH[1]}" "$(trim "${BASH_REMATCH[2]}")"
      continue
    fi
    if [[ "$line" =~ ^php_value\[([^]]+)\][[:space:]]*=[[:space:]]*(.+)$ ]]; then
      printf 'pool|%s|%s\n' "${BASH_REMATCH[1]}" "$(trim "${BASH_REMATCH[2]}")"
      continue
    fi
    if [[ "$line" =~ ^pm\.max_requests[[:space:]]*=[[:space:]]*(.+)$ ]]; then
      printf 'pm|%s|%s\n' "$sec" "$(trim "${BASH_REMATCH[1]}")"
      continue
    fi
    if [[ "$line" =~ ^user[[:space:]]*=[[:space:]]*(.+)$ ]]; then
      printf 'user|%s|%s\n' "$sec" "$(trim "${BASH_REMATCH[1]}")"
      continue
    fi
  done <"$file"
}

parse_apache_records() {
  local file=$1 line
  [[ -r "$file" ]] || return 0
  while IFS= read -r line || [[ -n "$line" ]]; do
    line=${line%%#*}
    line=$(trim "$line")
    [[ -z "$line" ]] && continue
    if [[ "$line" =~ ^php_admin_flag[[:space:]]+([^[:space:]]+)[[:space:]]+([^[:space:]]+) ]]; then
      printf 'admin|%s|%s\n' "${BASH_REMATCH[1]}" "${BASH_REMATCH[2]}"
      continue
    fi
    if [[ "$line" =~ ^php_admin_value[[:space:]]+([^[:space:]]+)[[:space:]]+([^[:space:]]+) ]]; then
      printf 'admin|%s|%s\n' "${BASH_REMATCH[1]}" "${BASH_REMATCH[2]}"
      continue
    fi
    if [[ "$line" =~ ^php_flag[[:space:]]+([^[:space:]]+)[[:space:]]+([^[:space:]]+) ]]; then
      printf 'pool|%s|%s\n' "${BASH_REMATCH[1]}" "${BASH_REMATCH[2]}"
      continue
    fi
    if [[ "$line" =~ ^php_value[[:space:]]+([^[:space:]]+)[[:space:]]+([^[:space:]]+) ]]; then
      printf 'pool|%s|%s\n' "${BASH_REMATCH[1]}" "${BASH_REMATCH[2]}"
    fi
  done <"$file"
}

remember_web_user() {
  local u=$1
  local existing
  [[ -n "$u" ]] || return 0
  for existing in "${WEB_USERS[@]+"${WEB_USERS[@]}"}"; do
    [[ "$existing" == "$u" ]] && return 0
  done
  WEB_USERS+=("$u")
}

fill_config_at() {
  local i=$1
  local major="" minor="" files=() f kind key val
  local ini_up="" ini_mem="" ini_post="" ini_umax="" ini_fatal=""
  local have_ini_up=0 have_ini_mem=0 have_ini_post=0 have_ini_umax=0 have_ini_fatal=0
  local src_up="default" src_mem="default" src_post="default" src_umax="default" src_fatal="default"
  local val_up="On" val_mem="" val_post="" val_umax="" val_fatal=""
  local pm_bits=() pool_worst_up="" pool_worst_src="" saw_pool=0

  if [[ -n "${F_VERSION[i]}" ]]; then
    major=${F_VERSION[i]%%.*}
    local rest=${F_VERSION[i]#*.}
    minor=${rest%%.*}
  fi

  mapfile -t files < <(list_ini_files "${F_MAININI[i]}" "${F_DROPIN[i]}")
  if [[ ${#files[@]} -gt 0 ]]; then
    ini_key_value "session.upload_progress.enabled" "${files[@]}"
    if [[ "$INI_FOUND" -eq 1 ]]; then ini_up=$INI_VALUE; have_ini_up=1; fi
    ini_key_value "memory_limit" "${files[@]}"
    if [[ "$INI_FOUND" -eq 1 ]]; then ini_mem=$INI_VALUE; have_ini_mem=1; fi
    ini_key_value "post_max_size" "${files[@]}"
    if [[ "$INI_FOUND" -eq 1 ]]; then ini_post=$INI_VALUE; have_ini_post=1; fi
    ini_key_value "upload_max_filesize" "${files[@]}"
    if [[ "$INI_FOUND" -eq 1 ]]; then ini_umax=$INI_VALUE; have_ini_umax=1; fi
    ini_key_value "fatal_error_backtraces" "${files[@]}"
    if [[ "$INI_FOUND" -eq 1 ]]; then ini_fatal=$INI_VALUE; have_ini_fatal=1; fi
  elif [[ -z "${F_MAININI[i]}" && -z "${F_DROPIN[i]}" ]]; then
    F_NOTE[i]="${F_NOTE[i]} no php.ini found."
  fi

  if [[ "$have_ini_up" -eq 1 ]]; then val_up=$ini_up; src_up="ini"; fi
  if [[ "$have_ini_mem" -eq 1 ]]; then val_mem=$ini_mem; src_mem="ini"; else val_mem="(not set)"; fi
  if [[ "$have_ini_post" -eq 1 ]]; then val_post=$ini_post; src_post="ini"; else val_post="(not set)"; fi
  if [[ "$have_ini_umax" -eq 1 ]]; then val_umax=$ini_umax; src_umax="ini"; else val_umax="(not set)"; fi
  if [[ "$have_ini_fatal" -eq 1 ]]; then val_fatal=$ini_fatal; src_fatal="ini"; fi

  local pool_logical pool_path
  if [[ -n "${F_POOLS[i]}" ]]; then
    local IFS=$'\x1e'
    # shellcheck disable=SC2086
    for pool_logical in ${F_POOLS[i]}; do
      IFS=$'\n\t'
      pool_path=$(rootp "$pool_logical")
      [[ -r "$pool_path" ]] || continue
      saw_pool=1
      local p_admin_up="" p_pool_up="" p_admin_mem="" p_mem="" p_admin_post="" p_post=""
      local p_admin_umax="" p_umax="" p_admin_fatal="" p_fatal=""
      local have_pm=0
      while IFS='|' read -r kind key val; do
        case "$kind|$key" in
          admin\|session.upload_progress.enabled) p_admin_up=$val ;;
          pool\|session.upload_progress.enabled) p_pool_up=$val ;;
          admin\|memory_limit) p_admin_mem=$val ;;
          pool\|memory_limit) p_mem=$val ;;
          admin\|post_max_size) p_admin_post=$val ;;
          pool\|post_max_size) p_post=$val ;;
          admin\|upload_max_filesize) p_admin_umax=$val ;;
          pool\|upload_max_filesize) p_umax=$val ;;
          admin\|fatal_error_backtraces) p_admin_fatal=$val ;;
          pool\|fatal_error_backtraces) p_fatal=$val ;;
          pm\|*) pm_bits+=("${key}=${val}"); have_pm=1 ;;
          user\|*) remember_web_user "$val" ;;
        esac
      done < <(parse_pool_records "$pool_path")
      local eff effsrc
      if [[ -n "$p_admin_up" ]]; then eff=$p_admin_up; effsrc="admin"
      elif [[ -n "$p_pool_up" ]]; then eff=$p_pool_up; effsrc="pool"
      else eff=$val_up; effsrc=$src_up
      fi
      if ! is_off "$eff" || [[ "$effsrc" == "default" || "$effsrc" == "missing" ]]; then
        pool_worst_up=$eff
        pool_worst_src=$effsrc
      elif [[ -z "$pool_worst_up" ]]; then
        pool_worst_up=$eff
        pool_worst_src=$effsrc
      fi
      if [[ -n "$p_admin_mem" ]]; then val_mem=$p_admin_mem; src_mem="admin"
      elif [[ -n "$p_mem" && "$src_mem" != "admin" ]]; then val_mem=$p_mem; src_mem="pool"; fi
      if [[ -n "$p_admin_post" ]]; then val_post=$p_admin_post; src_post="admin"
      elif [[ -n "$p_post" && "$src_post" != "admin" ]]; then val_post=$p_post; src_post="pool"; fi
      if [[ -n "$p_admin_umax" ]]; then val_umax=$p_admin_umax; src_umax="admin"
      elif [[ -n "$p_umax" && "$src_umax" != "admin" ]]; then val_umax=$p_umax; src_umax="pool"; fi
      if [[ -n "$p_admin_fatal" ]]; then val_fatal=$p_admin_fatal; src_fatal="admin"
      elif [[ -n "$p_fatal" && "$src_fatal" != "admin" ]]; then val_fatal=$p_fatal; src_fatal="pool"; fi
      if [[ "$have_pm" -eq 0 ]]; then
        pm_bits+=("$(basename "$pool_path" .conf)=default")
      fi
    done
    IFS=$'\n\t'
  fi

  if [[ "$saw_pool" -eq 1 && -n "$pool_worst_up" ]]; then
    val_up=$pool_worst_up
    src_up=$pool_worst_src
  fi

  if [[ "${F_SAPI[i]}" == "modphp" ]]; then
    local afile
    while IFS= read -r afile; do
      while IFS='|' read -r kind key val; do
        case "$kind|$key" in
          admin\|session.upload_progress.enabled) val_up=$val; src_up="admin" ;;
          pool\|session.upload_progress.enabled)
            if [[ "$src_up" != "admin" ]]; then val_up=$val; src_up="apache"; fi
            ;;
          admin\|memory_limit) val_mem=$val; src_mem="admin" ;;
          admin\|post_max_size) val_post=$val; src_post="admin" ;;
          admin\|upload_max_filesize) val_umax=$val; src_umax="admin" ;;
          admin\|fatal_error_backtraces) val_fatal=$val; src_fatal="admin" ;;
        esac
      done < <(parse_apache_records "$afile")
    done < <(apache_conf_files)
  fi

  if [[ -z "$val_fatal" ]]; then
    if [[ "$major" == "8" && "$minor" == "5" ]]; then
      val_fatal="On"
      if [[ "$src_fatal" != "admin" && "$src_fatal" != "ini" && "$src_fatal" != "pool" ]]; then
        src_fatal="default"
      fi
    else
      val_fatal="n/a"
      src_fatal="n/a"
    fi
  fi

  F_UP[i]=$val_up
  F_UPSRC[i]=$src_up
  F_MEM[i]=$val_mem
  F_MEMSRC[i]=$src_mem
  F_POST[i]=$val_post
  F_POSTSRC[i]=$src_post
  F_UMAX[i]=$val_umax
  F_UMAXSRC[i]=$src_umax
  F_FATAL[i]=$val_fatal
  F_FATALSRC[i]=$src_fatal
  if [[ ${#pm_bits[@]} -eq 0 ]]; then
    F_PM[i]="n/a"
  else
    local joined="" bit
    for bit in "${pm_bits[@]}"; do
      if [[ -n "$joined" ]]; then joined="${joined},"; fi
      joined="${joined}${bit}"
    done
    F_PM[i]=$joined
  fi
  if [[ "${F_MAININI[i]}" == "/etc/php.ini" ]]; then
    F_NOTE[i]="${F_NOTE[i]} shared /etc/php.ini."
  fi
}

# Apache files that are actually loaded. On Debian that is apache2.conf and
# the *-enabled directories, which hold symlinks. On RHEL it is conf/,
# conf.d/ and conf.modules.d/. *-available files are not read.
apache_conf_files() {
  local rp d
  rp=$(rootp /etc/apache2)
  if [[ -d "$rp" ]]; then
    [[ -f "$rp/apache2.conf" ]] && printf '%s\n' "$rp/apache2.conf"
    for d in conf-enabled mods-enabled sites-enabled; do
      [[ -d "$rp/$d" ]] || continue
      find -L "$rp/$d" -maxdepth 1 -type f \( -name '*.conf' -o -name '*.load' \) 2>/dev/null | sort || true
    done
  fi
  rp=$(rootp /etc/httpd)
  if [[ -d "$rp" ]]; then
    for d in conf conf.d conf.modules.d; do
      [[ -d "$rp/$d" ]] || continue
      find -L "$rp/$d" -maxdepth 1 -type f -name '*.conf' 2>/dev/null | sort || true
    done
  fi
}

# --- discovery: find every PHP install (read-only) ---

reset_findings() {
  OTHER_NS=()
  F_SAPI=()
  F_PATH=()
  F_VERSION=()
  F_PRE=()
  F_RAW=()
  F_PKG=()
  F_PKGVER=()
  F_BACKPORT=()
  F_UP=()
  F_UPSRC=()
  F_MEM=()
  F_MEMSRC=()
  F_POST=()
  F_POSTSRC=()
  F_UMAX=()
  F_UMAXSRC=()
  F_FATAL=()
  F_FATALSRC=()
  F_PM=()
  F_RISK=()
  F_DROPIN=()
  F_MAININI=()
  F_POOLS=()
  F_NOTE=()
  F_DELETED=()
  F_STATUS=()
  F_KIND=()
  F_DETAIL=()
  F_CNOTE=()
  WEB_USERS=()
  MOD_PHP=0
  ANY_RUNNING_DELETED=0
}

risk_for() {
  case "$1" in
    modphp) printf '%s\n' "highest" ;;
    fpm|cgi|frankenphp|litespeed) printf '%s\n' "high" ;;
    *) printf '%s\n' "low" ;;
  esac
}

add_raw() {
  F_SAPI+=("$1")
  F_PATH+=("$2")
  F_VERSION+=("$3")
  F_PRE+=("$4")
  F_RAW+=("$5")
  F_PKG+=("$6")
  F_PKGVER+=("$7")
  F_BACKPORT+=("$8")
  F_RISK+=("$9")
  F_DROPIN+=("${10}")
  F_MAININI+=("${11}")
  F_POOLS+=("${12}")
  F_DELETED+=("${13}")
  F_NOTE+=("${14}")
  F_UP+=("")
  F_UPSRC+=("")
  F_MEM+=("")
  F_MEMSRC+=("")
  F_POST+=("")
  F_POSTSRC+=("")
  F_UMAX+=("")
  F_UMAXSRC+=("")
  F_FATAL+=("")
  F_FATALSRC+=("")
  F_PM+=("")
  F_STATUS+=("")
  F_KIND+=("")
  F_DETAIL+=("")
  F_CNOTE+=("")
}

seen_key() {
  local key=$1 existing
  for existing in "${SEEN[@]+"${SEEN[@]}"}"; do
    [[ "$existing" == "$key" ]] && return 0
  done
  return 1
}

consider_file() {
  local path=$1 kind base real
  [[ -e "$path" ]] || return 0
  base=$(basename "$path")
  kind=$(php_binary_kind "$base")
  [[ -n "$kind" ]] || return 0
  if [[ "$kind" != "modphp" && ! -x "$path" && ! -L "$path" ]]; then
    return 0
  fi
  if [[ -L "$path" ]]; then
    real=$(readlink -f "$path" 2>/dev/null || true)
  else
    real=$path
  fi
  [[ -n "$real" ]] || real=$path
  local key="${kind}|${real}"
  if seen_key "$key"; then
    return 0
  fi
  SEEN+=("$key")

  local vertext="" version="" pre=0 raw="" major="" minor="" pkg="" pkgver="" back="unchecked"
  local drop="" main="" pools="" note="${2:-}"
  if [[ "$kind" == "modphp" ]]; then
    # M7: read the module's version string without loading it.
    vertext=$(static_php_version "$path" || true)
    parse_php_version_text "$vertext"
    if [[ -n "$vertext" && "$PARSED_OK" -eq 1 ]]; then
      version=$PARSED_TRIPLE
      pre=$PARSED_PRE
      raw=$vertext
      major=$PARSED_MAJOR
      minor=$PARSED_MINOR
    fi
  else
    if ! trusted_to_run "$path"; then
      note="${note} Not run: root does not own it, or others can write it or a directory above it. Version read from the file."
    fi
    vertext=$(php_version_text_of "$path")
    parse_php_version_text "$vertext"
    if [[ "$PARSED_OK" -eq 1 ]]; then
      version=$PARSED_TRIPLE
      pre=$PARSED_PRE
      raw=$(printf '%s\n' "$vertext" | awk '/^PHP /{print; exit}')
      major=$PARSED_MAJOR
      minor=$PARSED_MINOR
    fi
  fi
  if [[ -z "$major" ]]; then
    if series_from_basename "$base"; then
      major=$SERIES_MAJOR
      minor=$SERIES_MINOR
    fi
  fi
  pkg_of_path "$real"
  if [[ -z "$FOUND_PKG" && "$real" != "$path" ]]; then
    pkg_of_path "$path"
  fi
  pkg=$FOUND_PKG
  pkgver=$FOUND_PKGVER
  if [[ -z "$version" && -n "$pkgver" ]]; then
    parse_php_version_text "$pkgver"
    if [[ "$PARSED_OK" -eq 1 ]]; then
      version=$PARSED_TRIPLE
      pre=$PARSED_PRE
      raw=$pkgver
      major=$PARSED_MAJOR
      minor=$PARSED_MINOR
    fi
  fi
  if [[ -n "$major" && -n "$minor" ]]; then
    back=$(backport_state_for "$major" "$minor" "$pkg")
    local logical_real=$real
    [[ -n "$TEST_ROOT" ]] && logical_real=${real#"$TEST_ROOT"}
    if locate_layout "$major" "$minor" "$kind" "$logical_real" || php_ini_layout "$path" "$kind"; then
      main=$LOC_MAIN
      drop=$LOC_DROPIN
      if [[ -n "$LOC_POOLS" && -d "$(rootp "$LOC_POOLS")" ]]; then
        local pf logical
        pools=""
        while IFS= read -r pf; do
          logical=${pf#"$TEST_ROOT"}
          if [[ -z "$TEST_ROOT" ]]; then
            logical=$pf
          fi
          if [[ -n "$pools" ]]; then pools="${pools}"$'\x1e'; fi
          pools="${pools}${logical}"
        done < <(pool_files_in "$LOC_POOLS")
      fi
    fi
  else
    note="${note} series not identified."
  fi
  if [[ "$kind" == "modphp" ]]; then
    MOD_PHP=1
    note="${note} This tool rates mod_php highest risk."
  fi
  add_raw "$kind" "$path" "$version" "$pre" "$raw" "${pkg:-unknown}" "$pkgver" "$back" \
    "$(risk_for "$kind")" "$drop" "$main" "$pools" "0" "$(trim "$note")"
}

walk_dir() {
  local dir=$1 f
  [[ -d "$dir" ]] || return 0
  for f in "$dir"/*; do
    [[ -e "$f" || -L "$f" ]] || continue
    if [[ -d "$f" && ! -L "$f" ]]; then
      continue
    fi
    consider_file "$f"
  done
}

discover_dirs() {
  local d
  SEEN=()
  for d in /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin \
    /usr/lib/apache2/modules /usr/lib64/httpd/modules /usr/lib/httpd/modules \
    /usr/local/lsws/bin /usr/local/lsws/fcgi-bin; do
    walk_dir "$(rootp "$d")"
  done
  local opt
  opt=$(rootp /opt)
  if [[ -d "$opt" ]]; then
    for d in "$opt"/remi/php*/root/usr/bin "$opt"/remi/php*/root/usr/sbin \
      "$opt"/cpanel/ea-php*/root/usr/bin "$opt"/cpanel/ea-php*/root/usr/sbin \
      "$opt"/plesk/php/*/bin "$opt"/plesk/php/*/sbin \
      "$opt"/alt/php*/usr/bin "$opt"/alt/php*/usr/sbin; do
      [[ -d "$d" ]] || continue
      walk_dir "$d"
    done
  fi
}

load_apache_modules() {
  local out="" f
  if [[ -n "$TEST_ROOT" ]]; then
    f=$(rootp /fixture/apache-modules)
    if [[ -r "$f" ]]; then
      out=$(<"$f")
    fi
  else
    local c
    for c in apache2ctl apachectl httpd; do
      if command -v "$c" >/dev/null 2>&1; then
        out=$(run_limited "$c" -M 2>&1 || true)
        [[ -n "$out" ]] && break
      fi
    done
  fi
  if printf '%s\n' "$out" | awk 'BEGIN{e=1} tolower($0) ~ /php[0-9]*_module/ {e=0} END{exit e}'; then
    MOD_PHP=1
    local have=0 s
    for s in "${F_SAPI[@]+"${F_SAPI[@]}"}"; do
      [[ "$s" == "modphp" ]] && have=1
    done
    if [[ "$have" -eq 0 ]]; then
      local only_ver="" mixed=0 i
      for i in "${!F_SAPI[@]}"; do
        [[ -n "${F_VERSION[i]}" ]] || continue
        if [[ -z "$only_ver" ]]; then
          only_ver=${F_VERSION[i]}
        elif [[ "$only_ver" != "${F_VERSION[i]}" ]]; then
          mixed=1
        fi
      done
      local ver="" note="php_module is loaded."
      if [[ "$mixed" -eq 0 && -n "$only_ver" ]]; then
        ver=$only_ver
        note="${note} Version copied from the other PHP binaries, which agree."
      else
        note="${note} No single PHP version was found for the module, so the version is unknown."
      fi
      local pre=0 raw="" major="" minor="" back="unchecked" drop="" main="" pools=""
      if [[ -n "$ver" ]]; then
        parse_php_version_text "$ver"
        pre=$PARSED_PRE
        raw=$ver
        major=$PARSED_MAJOR
        minor=$PARSED_MINOR
        back=$(backport_state_for "$major" "$minor" "")
        if locate_layout "$major" "$minor" "modphp"; then
          main=$LOC_MAIN
          drop=$LOC_DROPIN
        fi
      fi
      add_raw "modphp" "apache-php-module" "$ver" "$pre" "$raw" "unknown" "" "$back" \
        "highest" "$drop" "$main" "$pools" "0" "$note"
    fi
  fi
}

# True when two paths are the same file (same device and inode).
same_file() {
  local a b
  a=$(stat -L -c '%d:%i' "$1" 2>/dev/null) || return 1
  b=$(stat -L -c '%d:%i' "$2" 2>/dev/null) || return 1
  [[ "$a" == "$b" ]]
}

# A PHP process in another mount namespace, usually a container. Its path
# means nothing on the host, so it is only reported, never changed.
record_other_ns() {
  local pid=$1 path=$2 exe=$3 text ver="" status="UNKNOWN" fixed
  text=$(static_php_version "$exe" || true)
  parse_php_version_text "$text"
  if [[ -n "$text" && "$PARSED_OK" -eq 1 ]]; then
    ver=$PARSED_TRIPLE
    if fixed=$(fixed_triple "$PARSED_MAJOR" "$PARSED_MINOR") && version_ge "$PARSED_TRIPLE" "$fixed"; then
      status="PATCHED"
    else
      status="BELOW_FIX"
    fi
  fi
  OTHER_NS+=("${pid}"$'\t'"${path}"$'\t'"${ver:-unknown}"$'\t'"${status}")
}

# Running PHP processes. Their binaries are never run from /proc: a process
# can belong to any user. A live file on disk goes through consider_file,
# which runs it only when it is root-only. A deleted binary is read in
# place for its version string and reported as its own finding, because the
# code in memory is no longer the file on disk.
discover_procs() {
  local procroot pid dir raw deleted base kind key i real
  procroot=$(rootp /proc)
  [[ -d "$procroot" ]] || return 0
  local self_ns ns
  self_ns=$(readlink "$procroot/self/ns/mnt" 2>/dev/null || true)
  for dir in "$procroot"/[0-9]*; do
    [[ -d "$dir" ]] || continue
    pid=$(basename "$dir")
    raw=$(readlink "$dir/exe" 2>/dev/null || true)
    [[ -n "$raw" ]] || continue
    deleted=0
    if [[ "$raw" == *" (deleted)" ]]; then
      deleted=1
      raw=${raw%" (deleted)"}
    fi
    base=$(basename "$raw")
    kind=$(php_binary_kind "$base")
    [[ -n "$kind" ]] || continue
    ns=$(readlink "$dir/ns/mnt" 2>/dev/null || true)
    if [[ -n "$self_ns" && -n "$ns" && "$ns" != "$self_ns" ]] && ! same_file "$dir/exe" "$(rootp "$raw")"; then
      record_other_ns "$pid" "$raw" "$dir/exe"
      continue
    fi
    if [[ "$deleted" -eq 0 ]]; then
      local phys
      phys=$(rootp "$raw")
      real=$(readlink -f "$phys" 2>/dev/null || true)
      key="${kind}|${real:-$phys}"
      if ! seen_key "$key" && [[ -e "$phys" ]]; then
        consider_file "$phys" "seen as pid ${pid}."
      fi
      continue
    fi
    ANY_RUNNING_DELETED=1
    for i in "${!F_PATH[@]}"; do
      if [[ "${F_PATH[i]}" == "$raw" || "$(readlink -f "${F_PATH[i]}" 2>/dev/null || true)" == "$raw" ]]; then
        F_DELETED[i]=1
        F_NOTE[i]="${F_NOTE[i]} running process ${pid} is mapped to a deleted binary."
      fi
    done
    key="deleted|${kind}|${raw}"
    seen_key "$key" && continue
    SEEN+=("$key")
    local vertext="" version="" pre=0 major="" minor="" drop="" main=""
    local note="pid ${pid} runs a deleted binary. Version read from memory without running it. Restart the service."
    vertext=$(static_php_version "$dir/exe" || true)
    parse_php_version_text "$vertext"
    if [[ -n "$vertext" && "$PARSED_OK" -eq 1 ]]; then
      version=$PARSED_TRIPLE
      pre=$PARSED_PRE
      major=$PARSED_MAJOR
      minor=$PARSED_MINOR
    elif series_from_basename "$base"; then
      major=$SERIES_MAJOR
      minor=$SERIES_MINOR
    fi
    if [[ -n "$major" ]] && locate_layout "$major" "$minor" "$kind"; then
      main=$LOC_MAIN
      drop=$LOC_DROPIN
    fi
    add_raw "$kind" "${raw} (deleted, pid ${pid})" "$version" "$pre" "$vertext" "unknown" "" "unchecked" \
      "$(risk_for "$kind")" "$drop" "$main" "" "1" "$note"
  done
}

classify_all() {
  local i text upload_off fatal_off line status kind detail cnote
  for i in "${!F_SAPI[@]}"; do
    if [[ -n "${F_VERSION[i]}" ]]; then
      text=${F_VERSION[i]}
      if [[ "${F_PRE[i]}" -eq 1 ]]; then
        text="${text}-dev"
      fi
    else
      text=${F_RAW[i]}
    fi
    upload_off=0
    fatal_off=0
    if explicit_off "${F_UP[i]}" "${F_UPSRC[i]}"; then
      upload_off=1
    fi
    if explicit_off "${F_FATAL[i]}" "${F_FATALSRC[i]}"; then
      fatal_off=1
    fi
    line=$(classify_result "$text" "${F_BACKPORT[i]}" "$upload_off" "$fatal_off")
    IFS='|' read -r status kind detail cnote <<<"$line"
    F_STATUS[i]=$status
    F_KIND[i]=$kind
    F_DETAIL[i]=$detail
    F_CNOTE[i]=$cnote
    if [[ "${F_BACKPORT[i]}" == "missing" && "$status" != "PATCHED" ]]; then
      F_NOTE[i]="${F_NOTE[i]} The changelog for ${F_PKG[i]} is not on this host, so a distro backport could not be checked. Check your distro's security tracker for ${F_PKG[i]} ${F_PKGVER[i]}."
    fi
    if [[ "${F_DELETED[i]}" -eq 1 && "$status" == "PATCHED" ]]; then
      F_NOTE[i]="${F_NOTE[i]} On-disk build looks patched and a deleted binary is still running."
    fi
  done
}

count_status() {
  COUNT_VULN=0
  COUNT_MIT=0
  COUNT_PATCH=0
  COUNT_UNK=0
  local s
  for s in "${F_STATUS[@]+"${F_STATUS[@]}"}"; do
    case "$s" in
      VULNERABLE) COUNT_VULN=$((COUNT_VULN + 1)) ;;
      MITIGATED) COUNT_MIT=$((COUNT_MIT + 1)) ;;
      PATCHED) COUNT_PATCH=$((COUNT_PATCH + 1)) ;;
      UNKNOWN) COUNT_UNK=$((COUNT_UNK + 1)) ;;
    esac
  done
}

scan_code() {
  count_status
  local orow other_below=0
  if [[ "$DO_CONTAINERS" -eq 1 ]]; then
    for orow in "${OTHER_NS[@]+"${OTHER_NS[@]}"}"; do
      [[ "$orow" == *$'\t'BELOW_FIX ]] && other_below=1
    done
  fi
  if ((COUNT_VULN + COUNT_MIT + other_below > 0)); then
    printf '%s\n' "1"
  elif ((COUNT_UNK > 0)); then
    printf '%s\n' "3"
  else
    printf '%s\n' "0"
  fi
}

needs_menu() {
  count_status
  ((COUNT_VULN + COUNT_MIT > 0))
}

# --- IOC: optional log checks, --ioc only (read-only) ---

append_cap() {
  local name=$1 value=$2
  local -n arr=$name
  if [[ ${#arr[@]} -ge 40 ]]; then
    return 0
  fi
  arr+=("$value")
}

ioc_log_files() {
  local patterns=(
    /var/log/syslog
    /var/log/messages
    /var/log/kern.log
    /var/log/apache2/error.log
    /var/log/httpd/error_log
    /var/log/nginx/error.log
    /var/log/php*-fpm.log
    /var/log/php*fpm*.log
    /var/log/php-fpm/error.log
    /var/log/php-fpm/www-error.log
  )
  local p f rp
  for p in "${patterns[@]}"; do
    if [[ "$p" == *\** ]]; then
      for f in $(rootp /)/${p#/}; do
        [[ -f "$f" ]] || continue
        printf '%s\n' "$f"
      done
    else
      rp=$(rootp "$p")
      [[ -f "$rp" ]] && printf '%s\n' "$rp"
    fi
  done
}

ioc_access_files() {
  local roots=(/var/log/apache2 /var/log/httpd /var/log/nginx) r rp f
  for r in "${roots[@]}"; do
    rp=$(rootp "$r")
    [[ -d "$rp" ]] || continue
    for f in "$rp"/*access* "$rp"/*access*.gz; do
      [[ -f "$f" ]] || continue
      printf '%s\n' "$f"
    done
  done
}

file_mtime() {
  stat -c %Y "$1" 2>/dev/null || stat -f %m "$1" 2>/dev/null || printf '%s\n' "0"
}

CRASH_RE='[Ss]egfault|segmentation fault|core dumped|Allowed memory size|Maximum execution time exceeded'

ioc_crashes() {
  local f n
  while IFS= read -r f; do
    [[ -r "$f" ]] || { IOC_NOTES+=("unreadable log: $f"); continue; }
    while IFS=: read -r n _; do
      [[ -n "$n" ]] && append_cap IOC_CRASHES "${f}:${n}"
    done < <(grep -nE -- "$CRASH_RE" "$f" 2>/dev/null || true)
  done < <(ioc_log_files)
  if [[ -z "$TEST_ROOT" ]] && command -v journalctl >/dev/null 2>&1; then
    # Only the time of each matching entry is reported, not its text.
    local ts
    while IFS=' ' read -r ts _; do
      [[ -n "$ts" ]] && append_cap IOC_CRASHES "journalctl ${ts}"
    done < <(journalctl --since "${IOC_SINCE} 00:00:00" --no-pager -o short-iso 2>/dev/null \
      | grep -E -- "$CRASH_RE" || true)
  fi
}

ioc_access() {
  local f n ip ipfile
  ipfile=$(tmpfile)
  printf '%s\n' "${WATCHED_IPS[@]}" >"$ipfile"
  while IFS= read -r f; do
    [[ -r "$f" ]] || { IOC_NOTES+=("unreadable access log: $f"); continue; }
    # Stream the log once per pattern. Only file and line numbers are kept.
    while IFS=: read -r n _; do
      [[ -n "$n" ]] && append_cap IOC_UPLOADS "${f}:${n}"
    done < <(read_log "$f" | grep -nF PHP_SESSION_UPLOAD_PROGRESS || true)
    while IFS=' ' read -r n ip; do
      [[ -n "$n" ]] && append_cap IOC_IP_HITS "${ip} ${f}:${n}"
    done < <(read_log "$f" | awk 'NR == FNR {ips[$0]; next}
      {for (ip in ips) if (index($0, ip)) {print FNR " " ip; break}}' "$ipfile" - || true)
  done < <(ioc_access_files)
  rm -f "$ipfile"
}

read_log() {
  if [[ "$1" == *.gz ]]; then
    gzip -dc -- "$1" 2>/dev/null || true
  else
    cat -- "$1" 2>/dev/null || true
  fi
}

web_roots() {
  local defaults=(/var/www /var/www/html /srv/www /srv/http /usr/share/nginx/html)
  local d rp seen=$'\n' f line path
  for d in "${defaults[@]}"; do
    rp=$(rootp "$d")
    if [[ -d "$rp" && "$seen" != *$'\n'"$rp"$'\n'* ]]; then
      printf '%s\n' "$rp"
      seen="${seen}${rp}"$'\n'
    fi
  done
  while IFS= read -r f; do
    [[ -r "$f" ]] || continue
    while IFS= read -r line; do
      if [[ "$line" =~ [Dd]ocument[Rr]oot[[:space:]]+([^[:space:]]+) ]]; then
        path=${BASH_REMATCH[1]}
        path=${path//\"/}
        rp=$(rootp "$path")
        if [[ -d "$rp" && "$path" != "/" && "$seen" != *$'\n'"$rp"$'\n'* ]]; then
          printf '%s\n' "$rp"
          seen="${seen}${rp}"$'\n'
        fi
      fi
      if [[ "$line" =~ ^[[:space:]]*root[[:space:]]+([^[:space:];]+) ]]; then
        path=${BASH_REMATCH[1]}
        path=${path//\"/}
        [[ "$path" == /* ]] || continue
        rp=$(rootp "$path")
        if [[ -d "$rp" && "$seen" != *$'\n'"$rp"$'\n'* ]]; then
          printf '%s\n' "$rp"
          seen="${seen}${rp}"$'\n'
        fi
      fi
    done <"$f"
  done < <(apache_conf_files; nginx_conf_files)
}

nginx_conf_files() {
  local rp
  rp=$(rootp /etc/nginx)
  [[ -d "$rp" ]] || return 0
  find "$rp" -maxdepth 3 -type f -name '*.conf' 2>/dev/null || true
}

find_supports_newermt() {
  local dir=$1
  find "$dir" -maxdepth 0 -newermt "1970-01-01" >/dev/null 2>&1
}

ioc_webshell() {
  local root php n=0 line file
  local -a patterns=(
    "eval_base64|eval(base64_decode"
    "eval_gzinflate|eval(gzinflate"
    "eval_rot13|eval(str_rot13"
    "assert_input|assert(\$_"
    "system_input|system(\$_"
    "shell_input|shell_exec(\$_"
    "passthru_input|passthru(\$_"
    "exec_input|exec(\$_"
  )
  while IFS= read -r root; do
    case "$root" in
      /|/etc|/usr|/bin|/proc|/sys|"$TEST_ROOT"|"$TEST_ROOT"/etc|"$TEST_ROOT"/proc) continue ;;
    esac
    if find_supports_newermt "$root"; then
      while IFS= read -r php; do
        n=$((n + 1))
        [[ "$n" -gt 5000 ]] && { IOC_NOTES+=("webshell scan stopped after 5000 files"); return 0; }
        local pair id pat
        for pair in "${patterns[@]}"; do
          id=${pair%%|*}
          pat=${pair#*|}
          if grep -n -F -q -- "$pat" "$php" 2>/dev/null; then
            line=$(grep -n -F -- "$pat" "$php" 2>/dev/null | awk -F: 'NR==1{print $1; exit}')
            append_cap IOC_SHELLS "${php}:${line}:${id}"
          fi
        done
      done < <(find "$root" -xdev -type f -name '*.php' -newermt "$IOC_SINCE" 2>/dev/null || true)
    else
      while IFS= read -r php; do
        n=$((n + 1))
        [[ "$n" -gt 5000 ]] && { IOC_NOTES+=("webshell scan stopped after 5000 files"); return 0; }
        local mt
        mt=$(file_mtime "$php")
        [[ "$mt" -ge "$IOC_EPOCH" ]] || continue
        local pair id pat
        for pair in "${patterns[@]}"; do
          id=${pair%%|*}
          pat=${pair#*|}
          if grep -n -F -q -- "$pat" "$php" 2>/dev/null; then
            line=$(grep -n -F -- "$pat" "$php" 2>/dev/null | awk -F: 'NR==1{print $1; exit}')
            append_cap IOC_SHELLS "${php}:${line}:${id}"
          fi
        done
      done < <(find "$root" -xdev -type f -name '*.php' 2>/dev/null || true)
    fi
  done < <(web_roots)
}

comm_is_expected() {
  case "$1" in
    php-fpm|php-fpm[0-9]*|php|php[0-9]*|apache2|httpd|nginx|lsphp|lsphp[0-9]*|frankenphp|php-cgi|php-cgi[0-9]*)
      return 0
      ;;
  esac
  return 1
}

ioc_children_and_net() {
  local procroot dir pid comm ppid exe
  procroot=$(rootp /proc)
  [[ -d "$procroot" ]] || return 0
  local -a webpids=()
  for dir in "$procroot"/[0-9]*; do
    [[ -d "$dir" ]] || continue
    pid=$(basename "$dir")
    exe=$(readlink "$dir/exe" 2>/dev/null || true)
    comm=$(cat "$dir/comm" 2>/dev/null || true)
    case "$(basename "${exe% (deleted)}")" in
      php-fpm*|php[0-9]*|apache2|httpd|lsphp*|frankenphp|php-cgi*)
        webpids+=("$pid")
        ;;
    esac
    if [[ "$comm" == "php-fpm" || "$comm" == "apache2" || "$comm" == "httpd" ]]; then
      webpids+=("$pid")
    fi
  done
  for dir in "$procroot"/[0-9]*; do
    [[ -r "$dir/status" ]] || continue
    pid=$(basename "$dir")
    comm=$(cat "$dir/comm" 2>/dev/null || true)
    # /proc/PID/stat puts the command in parentheses, so PPid is read from status.
    ppid=$(awk '/^PPid:/{print $2; exit}' "$dir/status" 2>/dev/null || true)
    local parent=0 w
    for w in "${webpids[@]+"${webpids[@]}"}"; do
      [[ "$ppid" == "$w" ]] && parent=1
    done
    if [[ "$parent" -eq 1 ]] && ! comm_is_expected "$comm"; then
      append_cap IOC_CHILDREN "pid ${pid} comm ${comm} ppid ${ppid}"
    fi
  done
  local uid name
  for name in "${WEB_USERS[@]+"${WEB_USERS[@]}"}"; do
    uid=$(awk -F: -v n="$name" '$1==n{print $3; exit}' "$(rootp /etc/passwd)" 2>/dev/null || true)
    [[ -n "$uid" ]] || continue
    parse_proc_net "$uid" "$name"
  done
}

# Established TCP connections owned by a web user whose local port is not
# one this host listens on. Those are outbound: a web worker that dials out
# is a strong hint. Inbound requests to the web server are skipped.
parse_proc_net() {
  local uid=$1 name=$2 files=() file
  for file in "$(rootp /proc/net/tcp)" "$(rootp /proc/net/tcp6)"; do
    [[ -r "$file" ]] && files+=("$file")
  done
  [[ ${#files[@]} -gt 0 ]] || return 0
  local line
  while IFS= read -r line; do
    [[ -n "$line" ]] && append_cap IOC_OUTBOUND "${name} uid ${uid} remote ${line} state ESTABLISHED"
  done < <(awk -v u="$uid" '
    FNR == 1 {next}
    { split($2, l, ":"); port = l[length(l)] }
    $4 == "0A" {listen[port] = 1; next}
    $4 == "01" && $8 == u {cand[++n] = port " " $3}
    END {
      for (i = 1; i <= n; i++) {
        split(cand[i], c, " ")
        if (!(c[1] in listen)) print c[2]
      }
    }' "${files[@]}" 2>/dev/null)
}

ioc_scan() {
  IOC_CRASHES=()
  IOC_UPLOADS=()
  IOC_SHELLS=()
  IOC_CHILDREN=()
  IOC_OUTBOUND=()
  IOC_IP_HITS=()
  IOC_NOTES=()
  IOC_NOTES+=("Indicators are hints to review. They are not proof of compromise.")
  IOC_NOTES+=("AWS published the watched IPs as shared anonymization infrastructure.")
  if [[ "$(id -u)" -ne 0 && -z "$TEST_ROOT" ]]; then
    IOC_NOTES+=("Not root: some logs and /proc entries may be unreadable.")
  fi
  ioc_crashes
  ioc_access
  ioc_webshell
  ioc_children_and_net
}

# --- containers: optional, --containers only (read-only) ---

scan_containers() {
  CONTAINER_NOTES=()
  CONTAINER_ROWS=()
  if [[ -n "$TEST_ROOT" ]]; then
    local f line
    f=$(rootp /fixture/docker-ps)
    if [[ -r "$f" ]]; then
      while IFS= read -r line; do
        [[ -n "$line" ]] && CONTAINER_ROWS+=("$line")
      done <"$f"
    else
      CONTAINER_NOTES+=("test root has no fixture/docker-ps")
    fi
    return 0
  fi
  local engines=() eng
  for eng in docker podman; do
    command -v "$eng" >/dev/null 2>&1 && engines+=("$eng")
  done
  if [[ ${#engines[@]} -eq 0 ]]; then
    CONTAINER_NOTES+=("neither docker nor podman is installed")
    return 0
  fi
  # Without --containers-exec only names and images are listed, so only the
  # ones that look like PHP are shown. With it, every running container is
  # asked, because a PHP app image is often not named after PHP.
  local do_exec=0
  if [[ "$CONTAINERS_EXEC" -eq 1 ]]; then
    do_exec=1
  elif [[ "$ASSUME_YES" -eq 0 && -t 0 && "$JSON" -eq 0 ]]; then
    if confirm "Run read-only 'php -v' in each running container?"; then
      do_exec=1
    fi
  fi
  local id image name out ver any=0
  for eng in "${engines[@]}"; do
    while IFS=$'\t' read -r id image name; do
      [[ -n "$id" ]] || continue
      any=1
      if [[ ! "$id" =~ ^[0-9a-fA-F]+$ ]]; then
        CONTAINER_NOTES+=("skipped ${eng} container id that is not hex")
        continue
      fi
      if [[ "$do_exec" -eq 0 ]]; then
        if [[ "$image" == *[Pp][Hh][Pp]* || "$name" == *[Pp][Hh][Pp]* ]]; then
          CONTAINER_ROWS+=("${id}"$'\t'"${image}"$'\t'"${name}"$'\t'"unverified")
        fi
        continue
      fi
      out=$(run_limited "$eng" exec "$id" php -v 2>/dev/null </dev/null || true)
      parse_php_version_text "$out"
      if [[ "$PARSED_OK" -eq 1 ]]; then
        ver=$PARSED_TRIPLE
      elif [[ "$image" == *[Pp][Hh][Pp]* || "$name" == *[Pp][Hh][Pp]* ]]; then
        ver="unknown"
      else
        continue
      fi
      CONTAINER_ROWS+=("${id}"$'\t'"${image}"$'\t'"${name}"$'\t'"${ver}")
    done < <("$eng" ps --format '{{.ID}}\t{{.Image}}\t{{.Names}}' 2>/dev/null || true)
  done
  if [[ "$any" -eq 0 ]]; then
    CONTAINER_NOTES+=("no running containers")
  elif [[ ${#CONTAINER_ROWS[@]} -eq 0 ]]; then
    CONTAINER_NOTES+=("no running container showed PHP")
  fi
  if [[ "$do_exec" -eq 0 ]]; then
    CONTAINER_NOTES+=("container versions were not read. Pass --containers-exec to run php -v in every running container.")
  fi
}

# --- report: print results, set exit code ---

status_color() {
  case "$1" in
    VULNERABLE) printf '%s' "$RED" ;;
    MITIGATED) printf '%s' "$YELLOW" ;;
    PATCHED) printf '%s' "$GREEN" ;;
    *) printf '%s' "$MAGENTA" ;;
  esac
}

risk_color() {
  case "$1" in
    highest) printf '%s' "$RED" ;;
    high) printf '%s' "$YELLOW" ;;
    low) printf '%s' "$GREEN" ;;
    *) printf '%s' "$RESET" ;;
  esac
}

status_label() {
  local status=$1 kind=$2
  case "$status" in
    PATCHED)
      if [[ "$kind" == "backport" ]]; then
        printf '%s\n' "PATCHED (backport)"
      else
        printf '%s\n' "PATCHED (version)"
      fi
      ;;
    MITIGATED) printf '%s\n' "MITIGATED (still vulnerable)" ;;
    *) printf '%s\n' "$status" ;;
  esac
}

stale_data_warning() {
  local now
  now=$(date -u +%s)
  if (( now > CVE_DATA_EPOCH + 14 * 86400 )); then
    warn "CVE data date is ${CVE_DATA_DATE}. This clock is more than 14 days later. Re-read the PHP advisory before trusting PATCHED."
  fi
}

human_field() {
  printf '  %s%-20s%s %s\n' "$CYAN" "${1}:" "$RESET" "$2"
}

human_report() {
  [[ "$JSON" -eq 1 ]] && return 0
  if [[ "$QUIET" -eq 1 ]]; then
    count_status
    printf '%s: vulnerable=%s mitigated=%s patched=%s unknown=%s\n' \
      "$TOOL_NAME" "$COUNT_VULN" "$COUNT_MIT" "$COUNT_PATCH" "$COUNT_UNK"
    return 0
  fi
  printf '%s%s%s%s %s\n' "$BOLD" "$CYAN" "$TOOL_NAME" "$RESET" "$TOOL_VERSION"
  printf '%sCVE data:%s %s\n' "$CYAN" "$RESET" "$CVE_DATA_DATE"
  printf '%sCVEs:%s %s, %s\n' "$CYAN" "$RESET" "$CVE_A" "$CVE_B"
  printf '%sFixed upstream:%s 8.5.12, 8.4.27, 8.3.36, 8.2.35\n' "$CYAN" "$RESET"
  printf '\n%sHost:%s %s\n' "$CYAN" "$RESET" "$(uname -n)"
  printf '%sOS:%s %s %s    %spackages:%s %s\n' "$CYAN" "$RESET" "$OS_ID" "$OS_VERSION" "$CYAN" "$RESET" "$PM"
  if [[ ${#F_SAPI[@]} -eq 0 ]]; then
    printf '\nNo PHP binary or mod_php module found.\n'
  fi
  local i label color rcolor vuln_c mit_c patch_c unk_c
  for i in "${!F_SAPI[@]}"; do
    label=$(status_label "${F_STATUS[i]}" "${F_KIND[i]}")
    color=$(status_color "${F_STATUS[i]}")
    rcolor=$(risk_color "${F_RISK[i]}")
    printf '\n%s------------------------------------------------------------%s\n' "$CYAN" "$RESET"
    printf '%s%s%s   %s%s%s%s\n' "$BOLD" "${F_SAPI[i]}" "$RESET" "$BOLD" "$color" "$label" "$RESET"
    printf '%s%s%s\n' "$CYAN" "${F_PATH[i]}" "$RESET"
    printf '\n'
    human_field "Version" "${F_VERSION[i]:-(unknown)}"
    if [[ -n "${F_RAW[i]}" && "${F_RAW[i]}" != "${F_VERSION[i]}" ]]; then
      printf '  %s%-20s%s %s\n' "$CYAN" "Version string:" "$RESET" "${F_RAW[i]}"
    fi
    human_field "Package" "${F_PKG[i]} ${F_PKGVER[i]}"
    human_field "Backport" "${F_BACKPORT[i]}"
    printf '  %s%-20s%s %s%s%s\n' "$CYAN" "Status:" "$RESET" "$color" "$label" "$RESET"
    human_field "Detail" "${F_DETAIL[i]}"
    if [[ -n "${F_CNOTE[i]}" ]]; then
      human_field "Changelog" "${F_CNOTE[i]}"
    fi
    printf '  %s%-20s%s %s%s%s\n' "$CYAN" "Risk:" "$RESET" "$rcolor" "${F_RISK[i]}" "$RESET"
    printf '\n%s  Settings%s\n' "$CYAN" "$RESET"
    human_field "Upload progress" "${F_UP[i]} (${F_UPSRC[i]})"
    human_field "Memory limit" "${F_MEM[i]} (${F_MEMSRC[i]})"
    human_field "Post max size" "${F_POST[i]} (${F_POSTSRC[i]})"
    human_field "Upload max size" "${F_UMAX[i]} (${F_UMAXSRC[i]})"
    human_field "Fatal backtraces" "${F_FATAL[i]} (${F_FATALSRC[i]})"
    human_field "Max requests" "${F_PM[i]//,/, }"
    if [[ -n "$(trim "${F_NOTE[i]}")" ]]; then
      printf '\n  %sNote%s %s\n' "$CYAN" "$RESET" "$(trim "${F_NOTE[i]}")"
    fi
    if [[ "${F_MEM[i]}" != "-1" || "${F_MEMSRC[i]}" != "admin" ]]; then
      if [[ "${F_STATUS[i]}" == "VULNERABLE" || "${F_STATUS[i]}" == "MITIGATED" ]]; then
        printf '\n  %sOut-of-memory path%s\n' "$YELLOW" "$RESET"
        printf '  memory_limit is not locked to -1. The OOM advisory'\''s primary config mitigation is\n'
        printf '  php_admin_value memory_limit=-1, and that still leaves an allocation-failure path.\n'
      fi
    fi
  done
  count_status
  vuln_c=$RESET
  mit_c=$RESET
  patch_c=$RESET
  unk_c=$RESET
  if ((COUNT_VULN > 0)); then vuln_c=$RED; fi
  if ((COUNT_MIT > 0)); then mit_c=$YELLOW; fi
  if ((COUNT_PATCH > 0)); then patch_c=$GREEN; fi
  if ((COUNT_UNK > 0)); then unk_c=$MAGENTA; fi
  printf '\n%s------------------------------------------------------------%s\n' "$CYAN" "$RESET"
  printf '%sSummary%s\n' "$BOLD" "$RESET"
  printf '  %s%s vulnerable%s    %s%s mitigated%s    %s%s patched%s    %s%s unknown%s\n' \
    "$vuln_c" "$COUNT_VULN" "$RESET" \
    "$mit_c" "$COUNT_MIT" "$RESET" \
    "$patch_c" "$COUNT_PATCH" "$RESET" \
    "$unk_c" "$COUNT_UNK" "$RESET"
  if ((COUNT_MIT > 0)); then
    printf '\n%sStill VULNERABLE until PHP is upgraded. Mitigations are not a patch.%s\n' "$RED" "$RESET"
  fi
  if [[ "$MOD_PHP" -eq 1 ]]; then
    printf '\n%smod_php is loaded. This tool rates it highest risk: the CVE-2026-109618 advisory shows code execution when mod_php runs shutdown after a failed startup.%s\n' "$RED" "$RESET"
  fi
  if [[ "$ANY_RUNNING_DELETED" -eq 1 ]]; then
    printf '\n%sA running PHP process is mapped to a deleted binary. Restart that service.%s\n' "$RED" "$RESET"
  fi
  if [[ "$DO_IOC" -eq 1 ]]; then
    printf '\n%sIndicators since %s%s\n' "$BOLD" "$IOC_SINCE" "$RESET"
    printf '%sReview only. Nothing is deleted.%s\n' "$CYAN" "$RESET"
    printf '\n'
    human_field "Crash lines" "${#IOC_CRASHES[@]}"
    human_field "Upload progress" "${#IOC_UPLOADS[@]}"
    human_field "Webshell patterns" "${#IOC_SHELLS[@]}"
    human_field "Child processes" "${#IOC_CHILDREN[@]}"
    human_field "Outbound" "${#IOC_OUTBOUND[@]}"
    human_field "Watched IPs" "${#IOC_IP_HITS[@]}"
    local item
    for item in "${IOC_CRASHES[@]+"${IOC_CRASHES[@]}"}" "${IOC_UPLOADS[@]+"${IOC_UPLOADS[@]}"}" \
      "${IOC_SHELLS[@]+"${IOC_SHELLS[@]}"}" "${IOC_CHILDREN[@]+"${IOC_CHILDREN[@]}"}" \
      "${IOC_OUTBOUND[@]+"${IOC_OUTBOUND[@]}"}" "${IOC_IP_HITS[@]+"${IOC_IP_HITS[@]}"}"; do
      printf '  - %s\n' "$item"
    done
    for item in "${IOC_NOTES[@]+"${IOC_NOTES[@]}"}"; do
      printf '  note: %s\n' "$item"
    done
  fi
  if [[ ${#OTHER_NS[@]} -gt 0 ]]; then
    printf '\n%sPHP running in containers or other namespaces%s\n' "$BOLD" "$RESET"
    local orow opid opath over ostat
    for orow in "${OTHER_NS[@]}"; do
      IFS=$'\t' read -r opid opath over ostat <<<"$orow"
      printf '  pid %s  %s  PHP %s  %s\n' "$opid" "$opath" "$over" "$ostat"
    done
    printf '  These are not changed by --fix or --workarounds. BELOW_FIX means the\n'
    printf '  upstream version is older than the fix. A distro build inside may still\n'
    printf '  carry a backport. Check or rebuild the image. They set the exit code\n'
    printf '  only with --containers.\n'
  fi
  if [[ "$DO_CONTAINERS" -eq 1 ]]; then
    printf '\n%sContainers%s\n' "$BOLD" "$RESET"
    local row
    if [[ ${#CONTAINER_ROWS[@]} -eq 0 ]]; then
      printf '  (none listed)\n'
    fi
    for row in "${CONTAINER_ROWS[@]+"${CONTAINER_ROWS[@]}"}"; do
      printf '  %s\n' "$row"
    done
    for row in "${CONTAINER_NOTES[@]+"${CONTAINER_NOTES[@]}"}"; do
      printf '  note: %s\n' "$row"
    done
    printf '\n  In-place upgrades inside containers are out of scope. Rebuild the image.\n'
  fi
}

json_array_strings() {
  local first=1 item
  printf '['
  for item in "$@"; do
    if [[ "$first" -eq 0 ]]; then printf ','; fi
    first=0
    json_string "$item"
  done
  printf ']'
}

json_report() {
  [[ "$JSON" -eq 1 ]] || return 0
  count_status
  local i first=1
  printf '{\n'
  printf '  "schema_version": %s,\n' "$SCHEMA_VERSION"
  printf '  "tool": %s,\n' "$(json_string "$TOOL_NAME")"
  printf '  "tool_version": %s,\n' "$(json_string "$TOOL_VERSION")"
  printf '  "cve_data_date": %s,\n' "$(json_string "$CVE_DATA_DATE")"
  printf '  "cves": [%s, %s],\n' "$(json_string "$CVE_A")" "$(json_string "$CVE_B")"
  printf '  "fixed_upstream": ["8.5.12", "8.4.27", "8.3.36", "8.2.35"],\n'
  printf '  "hostname": %s,\n' "$(json_string "$(uname -n)")"
  printf '  "scanned_at": %s,\n' "$(json_string "$(date -u +%Y-%m-%dT%H:%M:%SZ)")"
  printf '  "os": {"id": %s, "version": %s, "pretty": %s, "package_manager": %s},\n' \
    "$(json_string "$OS_ID")" "$(json_string "$OS_VERSION")" "$(json_string "$OS_PRETTY")" "$(json_string "$PM")"
  printf '  "counts": {"vulnerable": %s, "mitigated": %s, "patched": %s, "unknown": %s},\n' \
    "$COUNT_VULN" "$COUNT_MIT" "$COUNT_PATCH" "$COUNT_UNK"
  printf '  "mod_php": %s,\n' "$([[ "$MOD_PHP" -eq 1 ]] && printf 'true' || printf 'false')"
  printf '  "running_deleted_binary": %s,\n' "$([[ "$ANY_RUNNING_DELETED" -eq 1 ]] && printf 'true' || printf 'false')"
  printf '  "findings": [\n'
  for i in "${!F_SAPI[@]}"; do
    if [[ "$first" -eq 0 ]]; then printf ',\n'; fi
    first=0
    printf '    {"sapi": %s, "path": %s, "version": %s, "prerelease": %s, "version_string": %s, "package": %s, "package_version": %s, "backport": %s, "status": %s, "kind": %s, "detail": %s, "changelog_note": %s, "risk": %s, "session_upload_progress_enabled": %s, "session_upload_progress_source": %s, "memory_limit": %s, "memory_limit_source": %s, "post_max_size": %s, "post_max_size_source": %s, "upload_max_filesize": %s, "upload_max_filesize_source": %s, "fatal_error_backtraces": %s, "fatal_error_backtraces_source": %s, "pm_max_requests": %s, "running_deleted": %s, "note": %s}' \
      "$(json_string "${F_SAPI[i]}")" \
      "$(json_string "${F_PATH[i]}")" \
      "$(json_string "${F_VERSION[i]}")" \
      "$([[ "${F_PRE[i]}" -eq 1 ]] && printf 'true' || printf 'false')" \
      "$(json_string "${F_RAW[i]}")" \
      "$(json_string "${F_PKG[i]}")" \
      "$(json_string "${F_PKGVER[i]}")" \
      "$(json_string "${F_BACKPORT[i]}")" \
      "$(json_string "${F_STATUS[i]}")" \
      "$(json_string "${F_KIND[i]}")" \
      "$(json_string "${F_DETAIL[i]}")" \
      "$(json_string "${F_CNOTE[i]}")" \
      "$(json_string "${F_RISK[i]}")" \
      "$(json_string "${F_UP[i]}")" \
      "$(json_string "${F_UPSRC[i]}")" \
      "$(json_string "${F_MEM[i]}")" \
      "$(json_string "${F_MEMSRC[i]}")" \
      "$(json_string "${F_POST[i]}")" \
      "$(json_string "${F_POSTSRC[i]}")" \
      "$(json_string "${F_UMAX[i]}")" \
      "$(json_string "${F_UMAXSRC[i]}")" \
      "$(json_string "${F_FATAL[i]}")" \
      "$(json_string "${F_FATALSRC[i]}")" \
      "$(json_string "${F_PM[i]}")" \
      "$([[ "${F_DELETED[i]}" -eq 1 ]] && printf 'true' || printf 'false')" \
      "$(json_string "$(trim "${F_NOTE[i]}")")"
  done
  printf '\n  ],\n'
  if [[ "$DO_IOC" -eq 1 ]]; then
    printf '  "ioc": {"since": %s, "crash_lines": ' "$(json_string "$IOC_SINCE")"
    json_array_strings "${IOC_CRASHES[@]+"${IOC_CRASHES[@]}"}"
    printf ', "upload_progress_requests": '
    json_array_strings "${IOC_UPLOADS[@]+"${IOC_UPLOADS[@]}"}"
    printf ', "webshell_hits": '
    json_array_strings "${IOC_SHELLS[@]+"${IOC_SHELLS[@]}"}"
    printf ', "child_processes": '
    json_array_strings "${IOC_CHILDREN[@]+"${IOC_CHILDREN[@]}"}"
    printf ', "outbound": '
    json_array_strings "${IOC_OUTBOUND[@]+"${IOC_OUTBOUND[@]}"}"
    printf ', "watched_ip_hits": '
    json_array_strings "${IOC_IP_HITS[@]+"${IOC_IP_HITS[@]}"}"
    printf ', "notes": '
    json_array_strings "${IOC_NOTES[@]+"${IOC_NOTES[@]}"}"
    printf '},\n'
  else
    printf '  "ioc": null,\n'
  fi
  if [[ "$DO_CONTAINERS" -eq 1 ]]; then
    printf '  "containers": {"rows": '
    json_array_strings "${CONTAINER_ROWS[@]+"${CONTAINER_ROWS[@]}"}"
    printf ', "notes": '
    json_array_strings "${CONTAINER_NOTES[@]+"${CONTAINER_NOTES[@]}"}"
    printf '},\n'
  else
    printf '  "containers": null,\n'
  fi
  printf '  "other_namespace_processes": ['
  local ofirst=1 orow opid opath over ostat
  for orow in "${OTHER_NS[@]+"${OTHER_NS[@]}"}"; do
    IFS=$'\t' read -r opid opath over ostat <<<"$orow"
    if [[ "$ofirst" -eq 0 ]]; then printf ', '; fi
    ofirst=0
    printf '{"pid": %s, "path": %s, "version": %s, "status": %s}' "$(json_string "$opid")" \
      "$(json_string "$opath")" "$(json_string "$over")" "$(json_string "$ostat")"
  done
  printf '],\n'
  printf '  "warnings": '
  json_array_strings "${WARNINGS[@]+"${WARNINGS[@]}"}"
  printf ',\n  "actions": '
  json_array_strings "${ACTIONS[@]+"${ACTIONS[@]}"}"
  printf '\n}\n'
}

# --- backup, restart, edits: WRITES, only reached after a yes ---

safe_logical_path() {
  case "$1" in
    */../*|*/..|*$'\n'*|*$'\r'*) return 1 ;;
    /etc/*|/usr/local/etc/*|/usr/local/lsws/conf/*) return 0 ;;
    /opt/cpanel/ea-php*/root/etc/*|/opt/plesk/php/*/etc/*|/opt/alt/php*/etc/*) return 0 ;;
    *) return 1 ;;
  esac
}

begin_backup() {
  local base n=0
  base=$(date -u +%Y%m%dT%H%M%SZ)
  BACKUP_STAMP=$base
  while [[ -e "$(rootp "/var/backups/stacutis/${BACKUP_STAMP}")" ]]; do
    n=$((n + 1))
    BACKUP_STAMP="${base}-${n}"
  done
  BACKUP_DIR=$(rootp "/var/backups/stacutis/${BACKUP_STAMP}")
  if [[ "$DRY_RUN" -eq 1 ]]; then
    say "dry-run: would create ${BACKUP_DIR}"
    return 0
  fi
  local parent
  parent=$(dirname "$BACKUP_DIR")
  mkdir -p "$parent" || { err "could not create ${parent}"; return 1; }
  chmod 700 "$parent" 2>/dev/null || true
  # mkdir without -p fails if another run took the same name in the meantime.
  if ! mkdir -m 700 "$BACKUP_DIR" || ! mkdir -m 700 "$BACKUP_DIR/files"; then
    err "could not create a new backup directory ${BACKUP_DIR}"
    BACKUP_DIR=""
    return 1
  fi
  if ! {
    printf 'STACUTIS_BACKUP 1\n'
    printf 'STAMP %s\n' "$BACKUP_STAMP"
    printf 'PM %s\n' "$PM"
    printf 'TOOL %s\n' "$TOOL_VERSION"
  } >"$BACKUP_DIR/manifest"; then
    err "could not write ${BACKUP_DIR}/manifest"
    return 1
  fi
  note_action "backup ${BACKUP_STAMP} at ${BACKUP_DIR}"
}

seal_backup() {
  if [[ "$DRY_RUN" -eq 1 || -z "$BACKUP_DIR" || ! -d "$BACKUP_DIR" ]]; then
    return 0
  fi
  chmod -R go-rwx "$BACKUP_DIR" 2>/dev/null || true
  chmod 700 "$BACKUP_DIR" 2>/dev/null || true
}

backup_existing() {
  local logical=$1 src dest
  safe_logical_path "$logical" || {
    err "refusing to back up path outside config roots: $logical"
    return 1
  }
  src=$(rootp "$logical")
  [[ -e "$src" ]] || return 0
  if [[ "$DRY_RUN" -eq 1 ]]; then
    say "dry-run: would back up ${logical}"
    return 0
  fi
  # Keep the first copy. A second backup in the same run would save our own edit.
  if grep -qxF "EXISTING ${logical}" "$BACKUP_DIR/manifest" 2>/dev/null; then
    return 0
  fi
  dest="${BACKUP_DIR}/files${logical}"
  if ! mkdir -p "$(dirname "$dest")" || ! cp -a "$src" "$dest"; then
    err "could not back up ${logical}"
    return 1
  fi
  printf 'EXISTING %s\n' "$logical" >>"$BACKUP_DIR/manifest" || return 1
}

# Puts a finished temp file in place. The temp file lives in the same
# directory, so the rename is atomic. It keeps owner, group and mode of the
# file it replaces and restores the SELinux label when restorecon exists.
install_tmp() {
  local tmp=$1 path=$2
  if [[ -e "$path" ]]; then
    chmod --reference="$path" "$tmp" 2>/dev/null || chmod 644 "$tmp"
    chown --reference="$path" "$tmp" 2>/dev/null || true
  else
    chmod 644 "$tmp"
  fi
  if ! mv -f "$tmp" "$path"; then
    rm -f "$tmp"
    err "could not write ${path}"
    return 1
  fi
  if [[ -z "$TEST_ROOT" ]] && command -v restorecon >/dev/null 2>&1; then
    restorecon "$path" 2>/dev/null || true
  fi
  return 0
}

new_tmp_beside() {
  mktemp "$(dirname "$1")/.stacutis-php2shell.XXXXXX" 2>/dev/null || {
    err "could not create a temp file next to $1"
    return 1
  }
}

# Undo this run's edits from its own backup: remove files it created and put
# back files it changed. Used by --rollback and after a failed write or a
# failed config test.
restore_backup_files() {
  local dir=$1 kind path src dest bad=0
  while IFS=' ' read -r kind path; do
    [[ "$kind" == "CREATED" ]] || continue
    case "$(basename "$path")" in
      *stacutis-php2shell*) ;;
      *)
        err "manifest contains an unexpected created path: $path"
        return 4
        ;;
    esac
    safe_logical_path "$path" || { err "refusing path $path"; return 4; }
    rm -f "$(rootp "$path")" || bad=1
    note_action "removed ${path}"
  done <"$dir/manifest"
  while IFS=' ' read -r kind path; do
    [[ "$kind" == "EXISTING" ]] || continue
    safe_logical_path "$path" || { err "refusing path $path"; return 4; }
    src="${dir}/files${path}"
    dest=$(rootp "$path")
    if [[ ! -e "$src" ]]; then
      err "backup is missing ${src}"
      return 4
    fi
    if [[ -d "$dest" && ! -L "$dest" ]]; then
      err "refusing to replace directory ${path}"
      return 4
    fi
    if mkdir -p "$(dirname "$dest")" && rm -f "$dest" && cp -a "$src" "$dest"; then
      note_action "restored ${path}"
    else
      err "could not restore ${path}"
      bad=1
    fi
  done <"$dir/manifest"
  [[ "$bad" -eq 0 ]] || return 4
  return 0
}

# Runs the services' own config checks before any restart. A broken config
# must not take the site down. Binaries are run only when trusted_to_run.
config_tests_pass() {
  if [[ -n "$TEST_ROOT" ]]; then
    if [[ -e "$(rootp /fixture/configtest-fail)" ]]; then
      err "config test failed: $(cat "$(rootp /fixture/configtest-fail)")"
      return 1
    fi
    return 0
  fi
  local i bin outp seen=$'\n' failed=0 c
  for i in "${!F_SAPI[@]}"; do
    [[ "${F_SAPI[i]}" == "fpm" ]] || continue
    bin=${F_PATH[i]}
    [[ "$bin" == *" (deleted"* || ! -x "$bin" ]] && continue
    [[ "$seen" == *$'\n'"$bin"$'\n'* ]] && continue
    seen="${seen}${bin}"$'\n'
    trusted_to_run "$bin" || continue
    if ! outp=$("$bin" -t 2>&1 </dev/null); then
      err "config test failed for ${bin}:"
      printf '%s\n' "$outp" | tail -n 5 >&2
      failed=1
    fi
  done
  if [[ -d /etc/apache2 || -d /etc/httpd ]]; then
    for c in apache2ctl apachectl httpd; do
      command -v "$c" >/dev/null 2>&1 || continue
      if ! outp=$("$c" -t 2>&1 </dev/null); then
        err "Apache config test failed (${c} -t):"
        printf '%s\n' "$outp" | tail -n 5 >&2
        failed=1
      fi
      break
    done
  fi
  return "$failed"
}

# After a failed write or config test: put the old files back and do not
# restart anything.
undo_run_edits() {
  [[ -n "$BACKUP_DIR" && -f "$BACKUP_DIR/manifest" ]] || return 1
  if restore_backup_files "$BACKUP_DIR"; then
    say "Restored the previous config files from ${BACKUP_STAMP}. No service was restarted."
    return 0
  fi
  err "could not fully restore from ${BACKUP_DIR}. Run --rollback ${BACKUP_STAMP} after fixing the cause."
  return 1
}

record_created() {
  local logical=$1
  safe_logical_path "$logical" || return 1
  case "$(basename "$logical")" in
    *stacutis-php2shell*) ;;
    *)
      err "refusing to record an unexpected created path: $logical"
      return 1
      ;;
  esac
  if [[ "$DRY_RUN" -eq 1 ]]; then
    say "dry-run: would create ${logical}"
    return 0
  fi
  printf 'CREATED %s\n' "$logical" >>"$BACKUP_DIR/manifest"
}

record_service() {
  local svc=$1
  if [[ "$DRY_RUN" -eq 1 ]]; then
    say "dry-run: would restart ${svc}"
    return 0
  fi
  [[ -n "$BACKUP_DIR" && -d "$BACKUP_DIR" ]] || return 0
  printf 'SERVICE %s\n' "$svc" >>"$BACKUP_DIR/manifest"
}

record_package_version() {
  local pkg=$1 ver=$2
  [[ "$DRY_RUN" -eq 1 ]] && return 0
  [[ -n "$BACKUP_DIR" ]] || return 0
  printf 'PACKAGE %s %s\n' "$pkg" "$ver" >>"$BACKUP_DIR/manifest"
}

list_services() {
  if [[ -n "$TEST_ROOT" ]]; then
    local f
    f=$(rootp /fixture/services)
    if [[ -r "$f" ]]; then
      cat "$f"
    fi
    return 0
  fi
  local name
  if [[ -d /run/systemd/system ]] && command -v systemctl >/dev/null 2>&1; then
    systemctl list-unit-files --type=service --no-legend --no-pager 2>/dev/null \
      | awk '{print $1}' | sed 's/\.service$//' || true
    systemctl list-units --type=service --all --no-legend --no-pager 2>/dev/null \
      | awk '{print $1}' | sed 's/\.service$//' || true
  fi
  if [[ -d /etc/init.d ]]; then
    for name in /etc/init.d/*; do
      [[ -e "$name" ]] || continue
      basename "$name"
    done
  fi
}

service_wanted() {
  case "$1" in
    php*-fpm|php-fpm*|ea-php*-php-fpm|plesk-php*-fpm|alt-php*-fpm|apache2|httpd|lsws|lshttpd|frankenphp*)
      return 0
      ;;
  esac
  return 1
}

service_is_active() {
  local svc=$1
  if [[ -n "$TEST_ROOT" ]]; then
    return 0
  fi
  if command -v systemctl >/dev/null 2>&1 && [[ -d /run/systemd/system ]]; then
    systemctl is-active --quiet "$svc" && return 0
    return 1
  fi
  if command -v rc-service >/dev/null 2>&1; then
    rc-service "$svc" status >/dev/null 2>&1 && return 0
  fi
  # SysV init scripts (Debian or Ubuntu without systemd, containers).
  if command -v service >/dev/null 2>&1; then
    service "$svc" status >/dev/null 2>&1 && return 0
  fi
  return 1
}

web_sapi_present() {
  local s
  for s in "${F_SAPI[@]+"${F_SAPI[@]}"}"; do
    case "$s" in
      fpm|modphp|cgi|frankenphp|litespeed) return 0 ;;
    esac
  done
  return 1
}

# restart_one SERVICE [restart|reload]. A reload is enough after a config-only
# change and keeps requests in flight. It falls back to a restart.
restart_one() {
  local svc=$1 action=${2:-restart}
  record_service "$svc"
  if [[ "$DRY_RUN" -eq 1 ]]; then
    return 0
  fi
  if [[ -n "$TEST_ROOT" ]]; then
    mkdir -p "$(rootp /fixture)"
    printf '%s\n' "$svc" >>"$(rootp /fixture/restarts.log)"
    note_action "test-root ${action} ${svc}"
    RESTARTS_DONE=$((RESTARTS_DONE + 1))
    return 0
  fi
  if command -v systemctl >/dev/null 2>&1 && [[ -d /run/systemd/system ]]; then
    if [[ "$action" == "reload" ]] && systemctl reload "$svc"; then
      note_action "reloaded ${svc}"
      RESTARTS_DONE=$((RESTARTS_DONE + 1))
      return 0
    fi
    if systemctl restart "$svc"; then
      note_action "restarted ${svc}"
      RESTARTS_DONE=$((RESTARTS_DONE + 1))
      return 0
    fi
  fi
  if command -v rc-service >/dev/null 2>&1; then
    if [[ "$action" == "reload" ]] && rc-service "$svc" reload; then
      note_action "reloaded ${svc}"
      RESTARTS_DONE=$((RESTARTS_DONE + 1))
      return 0
    fi
    if rc-service "$svc" restart; then
      note_action "restarted ${svc}"
      RESTARTS_DONE=$((RESTARTS_DONE + 1))
      return 0
    fi
  fi
  if command -v service >/dev/null 2>&1; then
    if [[ "$action" == "reload" ]] && service "$svc" reload; then
      note_action "reloaded ${svc}"
      RESTARTS_DONE=$((RESTARTS_DONE + 1))
      return 0
    fi
    if service "$svc" restart; then
      note_action "restarted ${svc}"
      RESTARTS_DONE=$((RESTARTS_DONE + 1))
      return 0
    fi
  fi
  warn "could not restart ${svc}"
  return 1
}

# True when SERVICE runs one of the vulnerable PHP builds found by the scan.
# A host with several PHP branches only restarts the ones that changed.
service_affected() {
  local svc=$1 i dotted compact base
  while IFS= read -r i; do
    case "${F_SAPI[i]}" in
      modphp)
        [[ "$svc" == apache2 || "$svc" == httpd ]] && return 0
        ;;
      litespeed)
        [[ "$svc" == lsws || "$svc" == lshttpd ]] && return 0
        ;;
      frankenphp)
        [[ "$svc" == frankenphp* ]] && return 0
        ;;
      fpm)
        [[ -n "${F_VERSION[i]}" ]] || { [[ "$svc" == *fpm* ]] && return 0; continue; }
        dotted=$(printf '%s\n' "${F_VERSION[i]}" | cut -d. -f1,2)
        compact=${dotted/./}
        case "$svc" in
          "php${dotted}-fpm"|"php${compact}-fpm"|"php-fpm${dotted}"|"php-fpm${compact}"|"php${compact}-php-fpm"|"ea-php${compact}-php-fpm"|"plesk-php${compact}-fpm"|"alt-php${compact}-fpm")
            return 0
            ;;
          php-fpm)
            base=$(basename "${F_PATH[i]%% (deleted*}")
            [[ "$base" == php-fpm ]] && return 0
            ;;
        esac
        ;;
    esac
  done < <(vulnerable_indexes)
  return 1
}

restart_affected() {
  local action=${1:-restart} svc seen=$'\n' failed=0
  RESTARTS_DONE=0
  while IFS= read -r svc; do
    [[ -n "$svc" ]] || continue
    service_wanted "$svc" || continue
    service_affected "$svc" || continue
    [[ "$seen" == *$'\n'"$svc"$'\n'* ]] && continue
    seen="${seen}${svc}"$'\n'
    if service_is_active "$svc"; then
      restart_one "$svc" "$action" || failed=1
    else
      say "service ${svc} is not active; leaving it stopped"
    fi
  done < <(list_services | awk 'NF && !seen[$0]++')
  if [[ "$failed" -eq 1 ]]; then
    return 1
  fi
  if [[ "$DRY_RUN" -eq 0 ]] && web_sapi_present && [[ "$RESTARTS_DONE" -eq 0 ]]; then
    warn "no PHP or web service was restarted. Old workers keep the previous code until a restart."
    return 1
  fi
  return 0
}

write_marked_file() {
  local logical=$1 begin=$2 end=$3 block=$4
  local path tmp
  safe_logical_path "$logical" || return 1
  path=$(rootp "$logical")
  if [[ -L "$path" ]]; then
    local real
    real=$(readlink -f "$path" 2>/dev/null || true)
    if [[ -n "$TEST_ROOT" && "$real" != "$TEST_ROOT"/* ]]; then
      err "refusing to follow a symlink outside the test root: $logical"
      return 1
    fi
    if [[ -z "$TEST_ROOT" ]] && ! safe_logical_path "$real"; then
      err "refusing to follow ${logical} to ${real}, outside config roots"
      return 1
    fi
    path=$real
  fi
  if [[ "$DRY_RUN" -eq 1 ]]; then
    say "dry-run: would update ${logical} between markers"
    emit_notice <<EOF2
${begin}
${block}
${end}
EOF2
    return 0
  fi
  mkdir -p "$(dirname "$path")" || { err "could not create $(dirname "$logical")"; return 1; }
  tmp=$(new_tmp_beside "$path") || return 1
  if [[ -f "$path" ]]; then
    if ! awk -v b="$begin" -v e="$end" '
      $0 == b {skip=1; next}
      $0 == e {skip=0; next}
      skip == 1 {next}
      /^[[:space:]]*$/ {blank++; next}
      {while (blank > 0) {print ""; blank--}; print}
    ' "$path" >"$tmp"; then
      rm -f "$tmp"
      err "could not read ${logical}"
      return 1
    fi
  else
    record_created "$logical" || { rm -f "$tmp"; return 1; }
  fi
  local sep=""
  [[ -s "$tmp" ]] && sep=$'\n'
  if ! {
    printf '%s%s\n' "$sep" "$begin"
    printf '%s\n' "$block"
    printf '%s\n' "$end"
  } >>"$tmp"; then
    rm -f "$tmp"
    err "could not write ${logical}"
    return 1
  fi
  install_tmp "$tmp" "$path" || return 1
  note_action "updated ${logical}"
}

dropin_block() {
  local major=$1 minor=$2
  local block="; stacutis-php2shell temporary settings. Not a PHP upgrade."
  block="${block}"$'\n'"session.upload_progress.enabled = 0"
  if [[ "$major" == "8" && "$minor" == "5" ]]; then
    block="${block}"$'\n'"fatal_error_backtraces = 0"
  fi
  if [[ "$UPLOAD_POLICY" == "none" ]]; then
    block="${block}"$'\n'"post_max_size = 8M"
    block="${block}"$'\n'"upload_max_filesize = 2M"
  elif [[ "$UPLOAD_POLICY" == "uploads" ]]; then
    block="${block}"$'\n'"post_max_size = 32M"
    block="${block}"$'\n'"upload_max_filesize = 8M"
  fi
  printf '%s\n' "$block"
}

fpm_admin_block() {
  local major=$1 minor=$2
  local block="; stacutis-php2shell. php_admin_* cannot be overridden by the app."
  block="${block}"$'\n'"php_admin_flag[session.upload_progress.enabled] = off"
  if [[ "$major" == "8" && "$minor" == "5" ]]; then
    block="${block}"$'\n'"php_admin_value[fatal_error_backtraces] = 0"
  fi
  if [[ "$UPLOAD_POLICY" == "none" ]]; then
    block="${block}"$'\n'"php_admin_value[post_max_size] = 8M"
    block="${block}"$'\n'"php_admin_value[upload_max_filesize] = 2M"
  elif [[ "$UPLOAD_POLICY" == "uploads" ]]; then
    block="${block}"$'\n'"php_admin_value[post_max_size] = 32M"
    block="${block}"$'\n'"php_admin_value[upload_max_filesize] = 8M"
  fi
  if [[ "$DO_UNLIMITED_MEM" -eq 1 ]]; then
    block="${block}"$'\n'"php_admin_value[memory_limit] = -1"
  fi
  printf '%s\n' "$block"
}

apache_admin_block() {
  local major=$1 minor=$2
  local inner="php_admin_flag session.upload_progress.enabled Off"
  if [[ "$major" == "8" && "$minor" == "5" ]]; then
    inner="${inner}"$'\n'"    php_admin_value fatal_error_backtraces 0"
  fi
  if [[ "$UPLOAD_POLICY" == "none" ]]; then
    inner="${inner}"$'\n'"    php_admin_value post_max_size 8M"
    inner="${inner}"$'\n'"    php_admin_value upload_max_filesize 2M"
  elif [[ "$UPLOAD_POLICY" == "uploads" ]]; then
    inner="${inner}"$'\n'"    php_admin_value post_max_size 32M"
    inner="${inner}"$'\n'"    php_admin_value upload_max_filesize 8M"
  fi
  if [[ "$DO_UNLIMITED_MEM" -eq 1 ]]; then
    inner="${inner}"$'\n'"    php_admin_value memory_limit -1"
  fi
  # PHP 8 registers php_module, PHP 7 registers php7_module.
  printf '<IfModule php_module>\n    %s\n</IfModule>\n' "$inner"
  printf '<IfModule php7_module>\n    %s\n</IfModule>\n' "$inner"
}

inject_pool_file() {
  local logical=$1 block=$2
  local path tmp stripped blockfile
  safe_logical_path "$logical" || return 1
  path=$(rootp "$logical")
  if [[ "$DRY_RUN" -eq 1 ]]; then
    say "dry-run: would update each FPM pool in ${logical}"
    printf '%s\n' "$block" | emit_notice
    return 0
  fi
  [[ -f "$path" ]] || { err "pool file is missing: ${logical}"; return 1; }
  if [[ -L "$path" ]]; then
    path=$(readlink -f "$path") || return 1
  fi
  tmp=$(new_tmp_beside "$path") || return 1
  stripped=$(tmpfile) || { rm -f "$tmp"; return 1; }
  blockfile=$(tmpfile) || { rm -f "$tmp" "$stripped"; return 1; }
  printf '%s\n' "$block" >"$blockfile"
  if ! awk -v b="; stacutis-php2shell begin" -v e="; stacutis-php2shell end" -v limit="$DO_MAX_REQUESTS" '
    function flush() { while (blank > 0) { print ""; blank-- } }
    $0 == b {skip=1; blank=0; next}
    $0 == e {skip=0; next}
    skip == 1 {next}
    /^[[:space:]]*$/ {blank++; next}
    limit == 1 && $0 ~ /^[[:space:]]*pm\.max_requests[[:space:]]*=/ {
      flush()
      print "; stacutis-php2shell previous: " $0
      next
    }
    {flush(); print}
    END {flush()}
  ' "$path" >"$stripped"; then
    rm -f "$tmp" "$stripped" "$blockfile"
    err "could not read ${logical}"
    return 1
  fi
  if ! awk -v bf="$blockfile" -v b="; stacutis-php2shell begin" -v e="; stacutis-php2shell end" '
    function emit(   line) {
      print ""
      print b
      while ((getline line < bf) > 0) print line
      close(bf)
      print e
    }
    /^\[/ {
      if (seen) emit()
      seen=1
      print
      next
    }
    {print}
    END { if (seen) emit() }
  ' "$stripped" >"$tmp"; then
    rm -f "$tmp" "$stripped" "$blockfile"
    err "could not write ${logical}"
    return 1
  fi
  rm -f "$stripped" "$blockfile"
  install_tmp "$tmp" "$path" || return 1
  note_action "updated pool ${logical}"
}

print_proxy_advice() {
  out ""
  out "${BOLD}Proxy limits, examples only${RESET}"
  out "This tool does not edit nginx, Apache, or a WAF."
  emit_notice <<'EOF'

The OOM advisory asks for limits on decoded request size, input field
count, multipart part count, header count, and nesting, including
requests with no usable Content-Length. It does not publish these
example numbers. The 8M body cap matches the advisory's no-upload
post_max_size. Part count and nesting are not built-in nginx knobs;
a WAF can do that.

AWS describes WAF rules in:
https://aws.amazon.com/blogs/security/using-aws-waf-to-apply-mitigations-for-php2shell-rce-vulnerabilities-cve-2026-109618-and-cve-2026-109619/

nginx
  client_max_body_size 8m;
  large_client_header_buffers 4 8k;

apache
  LimitRequestBody 8388608
  LimitRequestFields 100
  LimitRequestFieldSize 8190

The OOM advisory also says to reduce max_input_nesting_level and to bound
max_input_vars, multipart parts, headers inside each part, and uploads.
Those PHP settings are left for you to edit. Do not set RLIMIT_AS or
RLIMIT_DATA. A cgroup memory.max can bound the worker. memory_limit=-1
removes PHP's own guard and is still not a complete fix.
EOF
}

cgroup_memory_note() {
  local f val
  for f in /sys/fs/cgroup/memory.max /sys/fs/cgroup/memory/memory.limit_in_bytes; do
    if [[ -r "$f" ]]; then
      val=$(<"$f")
      say "cgroup memory file ${f} contains: ${val}"
      return 0
    fi
  done
  say "No cgroup memory.max was readable. memory_limit=-1 would drop PHP's own cap unless the host limits memory another way."
}

print_active_tradeoffs() {
  workaround_banner
  if [[ "$WORK_UPLOAD" -eq 1 ]]; then
    tradeoff "Upload progress off stops bars that use PHP_SESSION_UPLOAD_PROGRESS. It closes one confirmed path. Other ways into the bug stay open."
  fi
  if [[ "$WORK_FATAL" -eq 1 ]]; then
    tradeoff "On PHP 8.5, fatal errors lose this backtrace. It blocks one confirmed producer of the stale-state bug."
  fi
  if [[ -n "$UPLOAD_POLICY" ]]; then
    tradeoff "Posts and uploads larger than the new cap fail. The site cannot raise the limit afterward."
  fi
  if [[ "$DO_UNLIMITED_MEM" -eq 1 ]]; then
    tradeoff "memory_limit=-1 removes PHP's RAM cap. One request can grow until the cgroup limit or the OS OOM killer. An allocation failure can still reach the bug. RLIMIT_AS and RLIMIT_DATA are not set."
  fi
  if [[ "$DO_MAX_REQUESTS" -eq 1 ]]; then
    tradeoff "pm.max_requests=1 exits every FPM worker after one request. Under load that costs CPU, adds latency, and can fill the listen queue."
  fi
}

ask_workaround_flags() {
  if [[ "$ASSUME_YES" -eq 1 || "$DRY_RUN" -eq 1 ]]; then
    WORK_UPLOAD=1
    WORK_FATAL=1
    print_active_tradeoffs
    return 0
  fi
  WORK_UPLOAD=0
  WORK_FATAL=0
  workaround_banner
  tradeoff "Upload progress off stops bars that use PHP_SESSION_UPLOAD_PROGRESS. It closes one confirmed path. Other ways into the bug stay open."
  if confirm "Set session.upload_progress.enabled=0 in admin config?"; then
    WORK_UPLOAD=1
  fi
  tradeoff "On PHP 8.5, fatal errors lose this backtrace. It blocks one confirmed producer of the stale-state bug."
  if confirm "On PHP 8.5 only, set fatal_error_backtraces=0?"; then
    WORK_FATAL=1
  fi
  if [[ -z "$UPLOAD_POLICY" ]]; then
    tradeoff "Posts and uploads larger than the new cap fail. The site cannot raise the limit afterward. Answering no leaves request size alone."
    if confirm "Tighten post_max_size?"; then
      local reply
      printf 'File uploads required? y = post_max_size 32M and upload_max_filesize 8M; n = 8M and 2M [y/N] ' >&2
      read -r reply || reply=""
      if [[ "$reply" == "y" || "$reply" == "Y" ]]; then
        UPLOAD_POLICY="uploads"
      else
        UPLOAD_POLICY="none"
      fi
    fi
  else
    tradeoff "Posts and uploads larger than the new cap fail. The site cannot raise the limit afterward."
  fi
  if [[ "$DO_UNLIMITED_MEM" -eq 0 ]]; then
    cgroup_memory_note
    tradeoff "memory_limit=-1 removes PHP's RAM cap. One request can grow until the cgroup limit or the OS OOM killer. An allocation failure can still reach the bug. This tool will not set RLIMIT_AS or RLIMIT_DATA."
    if confirm "Lock memory_limit=-1 with php_admin_value on web SAPIs?"; then
      DO_UNLIMITED_MEM=1
    fi
  else
    tradeoff "memory_limit=-1 removes PHP's RAM cap. One request can grow until the cgroup limit or the OS OOM killer. An allocation failure can still reach the bug. RLIMIT_AS and RLIMIT_DATA are not set."
  fi
  if [[ "$DO_MAX_REQUESTS" -eq 0 ]]; then
    tradeoff "pm.max_requests=1 exits every FPM worker after one request. Under load that costs CPU, adds latency, and can fill the listen queue."
    if confirm "Set pm.max_requests=1 on vulnerable FPM pools?"; then
      DO_MAX_REQUESTS=1
    fi
  else
    tradeoff "pm.max_requests=1 exits every FPM worker after one request. Under load that costs CPU, adds latency, and can fill the listen queue."
  fi
}

vulnerable_indexes() {
  local i
  for i in "${!F_STATUS[@]}"; do
    if [[ "${F_STATUS[i]}" == "VULNERABLE" || "${F_STATUS[i]}" == "MITIGATED" ]]; then
      printf '%s\n' "$i"
    fi
  done
}

apply_workarounds() {
  local i major minor rest logical pool drop
  ask_workaround_flags
  if [[ "$WORK_UPLOAD" -eq 0 && "$WORK_FATAL" -eq 0 && -z "$UPLOAD_POLICY" && "$DO_UNLIMITED_MEM" -eq 0 && "$DO_MAX_REQUESTS" -eq 0 ]]; then
    say "No workaround selected. Nothing changed."
    return 0
  fi
  if [[ "$DRY_RUN" -eq 0 ]]; then
    if ! confirm "Back up configs, write the selected settings, and restart active PHP services?"; then
      say "Stopped before any change."
      return 1
    fi
  fi
  begin_backup || { err "no backup could be made. Nothing was changed."; return 4; }
  local failed=0
  local seen_drop=$'\n'
  while IFS= read -r i; do
    [[ -n "${F_VERSION[i]}" ]] || continue
    major=${F_VERSION[i]%%.*}
    rest=${F_VERSION[i]#*.}
    minor=${rest%%.*}
    drop=${F_DROPIN[i]}
    if [[ -n "$drop" && "$seen_drop" != *$'\n'"$drop"$'\n'* ]]; then
      seen_drop="${seen_drop}${drop}"$'\n'
      logical="${drop}/99-stacutis-php2shell.ini"
      if [[ "$DRY_RUN" -eq 0 && ! -d "$(rootp "$drop")" ]]; then
        mkdir -p "$(rootp "$drop")" || failed=1
      fi
      if [[ -f "$(rootp "$logical")" ]]; then
        backup_existing "$logical" || failed=1
      fi
      local block
      block=$(dropin_block "$major" "$minor")
      if [[ "$WORK_FATAL" -eq 0 ]]; then
        block=$(printf '%s\n' "$block" | awk '!/fatal_error_backtraces/')
      fi
      if [[ "$WORK_UPLOAD" -eq 0 ]]; then
        block=$(printf '%s\n' "$block" | awk '!/session.upload_progress/')
      fi
      if [[ "$failed" -eq 0 ]]; then
        write_marked_file "$logical" "; stacutis-php2shell begin" "; stacutis-php2shell end" "$block" || failed=1
      fi
    fi
    if [[ "${F_SAPI[i]}" == "fpm" || "${F_SAPI[i]}" == "frankenphp" || "${F_SAPI[i]}" == "litespeed" ]]; then
      local IFS=$'\x1e'
      for pool in ${F_POOLS[i]}; do
        IFS=$'\n\t'
        [[ -n "$pool" && "$failed" -eq 0 ]] || continue
        backup_existing "$pool" || { failed=1; continue; }
        local ablock
        ablock=$(fpm_admin_block "$major" "$minor")
        if [[ "$WORK_FATAL" -eq 0 ]]; then
          ablock=$(printf '%s\n' "$ablock" | awk '!/fatal_error_backtraces/')
        fi
        if [[ "$WORK_UPLOAD" -eq 0 ]]; then
          ablock=$(printf '%s\n' "$ablock" | awk '!/session.upload_progress/')
        fi
        if [[ "$DO_UNLIMITED_MEM" -eq 0 ]]; then
          ablock=$(printf '%s\n' "$ablock" | awk '!/memory_limit/')
        fi
        if [[ "$DO_MAX_REQUESTS" -eq 1 ]]; then
          ablock="${ablock}"$'\n'"pm.max_requests = 1"
        fi
        inject_pool_file "$pool" "$ablock" || failed=1
      done
      IFS=$'\n\t'
    fi
  done < <(vulnerable_indexes)

  if [[ "$MOD_PHP" -eq 1 ]]; then
    local a_logical=""
    if [[ -d "$(rootp /etc/apache2)" ]]; then
      a_logical="/etc/apache2/conf-available/stacutis-php2shell.conf"
    elif [[ -d "$(rootp /etc/httpd)" ]]; then
      a_logical="/etc/httpd/conf.d/stacutis-php2shell.conf"
    fi
    if [[ -n "$a_logical" ]]; then
      local a_major="" a_minor=""
      while IFS= read -r i; do
        if [[ "${F_SAPI[i]}" == "modphp" && -n "${F_VERSION[i]}" ]]; then
          a_major=${F_VERSION[i]%%.*}
          rest=${F_VERSION[i]#*.}
          a_minor=${rest%%.*}
        fi
      done < <(vulnerable_indexes)
      if [[ -z "$a_major" ]]; then
        # No mod_php version: use the newest vulnerable branch found, so an
        # 8.5 host still gets the 8.5 setting.
        while IFS= read -r i; do
          [[ -n "${F_VERSION[i]}" ]] || continue
          rest=${F_VERSION[i]#*.}
          local c_major=${F_VERSION[i]%%.*} c_minor=${rest%%.*}
          [[ "$c_major" =~ ^[0-9]+$ && "$c_minor" =~ ^[0-9]+$ ]] || continue
          if [[ -z "$a_major" ]] || (( c_major > a_major || (c_major == a_major && c_minor > a_minor) )); then
            a_major=$c_major
            a_minor=$c_minor
          fi
        done < <(vulnerable_indexes)
      fi
      if [[ "$failed" -eq 0 && -f "$(rootp "$a_logical")" ]]; then
        backup_existing "$a_logical" || failed=1
      fi
      local ab
      ab=$(apache_admin_block "$a_major" "$a_minor")
      if [[ "$failed" -eq 0 ]]; then
        write_marked_file "$a_logical" "# stacutis-php2shell begin" "# stacutis-php2shell end" "$ab" || failed=1
      fi
      if [[ "$a_logical" == /etc/apache2/conf-available/* ]]; then
        local link="/etc/apache2/conf-enabled/stacutis-php2shell.conf"
        if [[ "$failed" -eq 0 && "$DRY_RUN" -eq 0 && -d "$(rootp /etc/apache2/conf-enabled)" && ! -e "$(rootp "$link")" ]]; then
          if record_created "$link" && ln -s ../conf-available/stacutis-php2shell.conf "$(rootp "$link")"; then
            note_action "enabled apache conf ${link}"
          else
            failed=1
          fi
        elif [[ "$DRY_RUN" -eq 1 ]]; then
          say "dry-run: would symlink ${link}"
        fi
      fi
    else
      warn "mod_php is present and no Apache conf directory was found. The ini drop-in was still written when a PHP conf.d existed."
    fi
  fi

  if [[ "$failed" -eq 1 ]]; then
    err "a config write failed. Putting the previous files back."
    undo_run_edits
    seal_backup
    return 4
  fi
  print_proxy_advice
  seal_backup
  if [[ "$DRY_RUN" -eq 1 ]]; then
    say "dry-run: no files written, no services restarted."
    return 0
  fi
  if ! config_tests_pass; then
    err "the new settings did not pass the config test. Putting the previous files back."
    undo_run_edits
    return 4
  fi
  out ""
  out "${RED}Still VULNERABLE until PHP is upgraded.${RESET}"
  printf '\n%s%sStill VULNERABLE until PHP is upgraded.%s\n' "$BOLD" "$RED" "$RESET" >&2
  if ! restart_affected reload; then
    err "settings were written and at least one reload failed. Old workers may still be in memory."
    return 4
  fi
  return 0
}

# --- fix: package upgrade, WRITES, only reached after a yes ---

installed_packages_for_series() {
  local major=$1 minor=$2
  if [[ -n "$TEST_ROOT" ]]; then
    local table pkg ver path
    table=$(rootp /fixture/installed.tsv)
    [[ -r "$table" ]] || return 0
    while IFS=$'\t' read -r pkg ver path || [[ -n "$pkg" ]]; do
      [[ -z "$pkg" || "$pkg" == \#* ]] && continue
      case "$pkg" in
        "php${major}.${minor}"|"php${major}.${minor}-"*|"libapache2-mod-php${major}.${minor}"|"php${major}${minor}"|"php${major}${minor}-"*)
          printf '%s\t%s\n' "$pkg" "$ver"
          ;;
      esac
    done <"$table" | awk -F'\t' '!seen[$1]++'
    return 0
  fi
  if [[ "$PM" == "apt" ]]; then
    dpkg-query -W -f '${Package}\t${Version}\n' 2>/dev/null \
      | awk -F'\t' -v d="php${major}.${minor}" -v lib="libapache2-mod-php${major}.${minor}" '
        $1 == d || index($1, d "-") == 1 || $1 == lib {print}
      ' || true
  elif [[ "$PM" == "dnf" || "$PM" == "yum" ]]; then
    rpm -qa --queryformat '%{NAME}\t%{VERSION}-%{RELEASE}\n' 2>/dev/null \
      | awk -F'\t' -v c="php${major}${minor}" -v d="php${major}.${minor}" '
        $1 == "php" || $1 == "php-cli" || $1 == "php-fpm" || $1 == "php-common" ||
        index($1, c "-") == 1 || $1 == c || index($1, d) == 1 {print}
      ' || true
  elif [[ "$PM" == "apk" ]]; then
    # Lines look like: php83-fpm-8.3.15-r0 x86_64 {php83} (PHP-3.01) [installed]
    apk list --installed 2>/dev/null | awk -v c="php${major}${minor}" '
      {
        n = $1
        if (match(n, /-[0-9][^-]*-r[0-9]+$/) == 0) next
        name = substr(n, 1, RSTART - 1)
        ver = substr(n, RSTART + 1)
        if (name == c || index(name, c "-") == 1) print name "\t" ver
      }' || true
  fi
}

# True when apt or dnf is told to keep this package where it is.
package_is_held() {
  local pkg=$1
  [[ -z "$TEST_ROOT" ]] || { [[ -r "$(rootp /fixture/held)" ]] && grep -qxF "$pkg" "$(rootp /fixture/held)"; return; }
  case "$PM" in
    apt) apt-mark showhold 2>/dev/null | grep -qxF "$pkg" ;;
    dnf) dnf versionlock list 2>/dev/null | grep -q "^${pkg}-[0-9]" ;;
    *) return 1 ;;
  esac
}

candidate_version_of() {
  local pkg=$1
  if [[ -n "$TEST_ROOT" ]]; then
    local table p ver
    table=$(rootp /fixture/candidates.tsv)
    [[ -r "$table" ]] || return 1
    while IFS=$'\t' read -r p ver || [[ -n "$p" ]]; do
      if [[ "$p" == "$pkg" ]]; then
        printf '%s\n' "$ver"
        return 0
      fi
    done <"$table"
    return 1
  fi
  if [[ "$PM" == "apt" ]]; then
    apt-cache policy "$pkg" 2>/dev/null | awk '/Candidate:/ {print $2; exit}'
    return 0
  fi
  if [[ "$PM" == "dnf" ]]; then
    # Only an upgrade for this exact package, newest first.
    dnf -q repoquery --upgrades --latest-limit=1 --queryformat '%{version}-%{release}\n' "$pkg" 2>/dev/null \
      | awk 'NF {v=$0} END {if (v != "") print v}'
    return 0
  fi
  if [[ "$PM" == "yum" ]]; then
    yum -q list updates "$pkg" 2>/dev/null | awk -v p="$pkg" '
      { n = $1; sub(/\.[^.]*$/, "", n); if (n == p) {print $2; exit} }'
    return 0
  fi
  if [[ "$PM" == "apk" ]]; then
    # "apk list -u" names only a real upgrade: "php83-8.3.36-r0 x86_64 ...".
    apk list -u "$pkg" 2>/dev/null | awk -v p="$pkg" '
      index($1, p "-") == 1 {
        v = substr($1, length(p) + 2)
        if (v ~ /^[0-9]/) {print v; exit}
      }'
    return 0
  fi
  return 1
}

candidate_changelog_file() {
  local pkg=$1 dest=$2
  : >"$dest"
  if [[ -n "$TEST_ROOT" ]]; then
    append_changelog_file "$(rootp "/fixture/candidate-changelogs/${pkg}")" "$dest"
    return 0
  fi
  # dnf can print the changelog of the upgrade candidate from repo metadata,
  # without installing it. apt is handled after "apt-get update"; apk has
  # no changelog and is judged by the upstream version alone.
  if [[ "$PM" == "dnf" ]]; then
    dnf -q repoquery --changelogs --upgrades --latest-limit=1 "$pkg" >"$dest" 2>/dev/null || true
  fi
  return 0
}

package_is_acceptable_upgrade() {
  local pkg=$1 installed=$2 candidate=$3 series_major=$4 series_minor=$5
  local fixed
  parse_php_version_text "$candidate"
  if [[ "$PARSED_OK" -eq 1 && "$PARSED_PRE" -eq 0 ]]; then
    if [[ "$PARSED_MAJOR" != "$series_major" || "$PARSED_MINOR" != "$series_minor" ]]; then
      printf '%s\n' "no: candidate ${candidate} is a different branch; this tool will not change major versions"
      return 0
    fi
    if fixed=$(fixed_triple "$PARSED_MAJOR" "$PARSED_MINOR"); then
      if version_ge "$PARSED_TRIPLE" "$fixed"; then
        printf '%s\n' "yes: candidate upstream ${PARSED_TRIPLE} is at least ${fixed}"
        return 0
      fi
    fi
  fi
  local tmp state
  tmp=$(tmpfile)
  candidate_changelog_file "$pkg" "$tmp"
  if [[ -s "$tmp" ]]; then
    state=$(cve_state_file "$tmp")
    rm -f "$tmp"
    if [[ "$state" == "both" ]]; then
      printf '%s\n' "yes: candidate changelog names both CVEs"
      return 0
    fi
    printf '%s\n' "no: candidate ${candidate} is below the fixed upstream release and its changelog does not name both CVEs (${state})"
    return 0
  fi
  rm -f "$tmp"
  if [[ -z "$TEST_ROOT" && "$PM" == "apt" ]]; then
    printf '%s\n' "recheck-after-update"
    return 0
  fi
  printf '%s\n' "no: candidate ${candidate:-unknown} is not a confirmed fix (installed ${installed})"
}

repo_advice() {
  out ""
  out "${BOLD}If the repositories have no confirmed package${RESET}"
  emit_notice <<'EOF'
This tool will not add repositories and will not compile PHP.

apt
  Use the distribution security pocket if its package is a confirmed fix.
  A third-party archive some Ubuntu hosts already use is the ondrej PHP PPA:
  https://launchpad.net/~ondrej/+archive/ubuntu/php

dnf and yum
  Use the distribution security errata.
  The PHP project said on 21 October 2026 that rpms.remirepo.net would not
  have the updates that day. If this host uses remi, confirm the candidate
  yourself. This tool will not enable remi.

apk
  Upgrade only from Alpine repositories that are already configured.

Source builds
  Upstream source backports for 7.4, 8.0, and 8.1 exist for people who build
  PHP themselves. This tool does not build them.
  https://www.php.net/archive/2026.php#2026-10-21-5
EOF
}

print_fix_plan() {
  out ""
  out "${BOLD}Full fix${RESET}"
  out "Uses the system package manager only. PHP is not compiled."
  out "Package manager: ${PM}"
  local i major minor
  local -a pkgs=()
  while IFS= read -r i; do
    [[ -n "${F_VERSION[i]}" ]] || continue
    major=${F_VERSION[i]%%.*}
    local rest=${F_VERSION[i]#*.}
    minor=${rest%%.*}
    local class
    class=$(branch_class "$major" "$minor")
    out ""
    out "${BOLD}${F_SAPI[i]}${RESET}  ${F_VERSION[i]}  ${CYAN}(${class})${RESET}"
    out "  Package     ${F_PKG[i]} ${F_PKGVER[i]}"
    local pkg ver
    while IFS=$'\t' read -r pkg ver; do
      [[ -n "$pkg" ]] || continue
      pkgs+=("$pkg")
      local cand reason color shown
      cand=$(candidate_version_of "$pkg" || true)
      if package_is_held "$pkg"; then
        reason="no: held by the package manager. This tool will not release a hold."
      else
        reason=$(package_is_acceptable_upgrade "$pkg" "$ver" "$cand" "$major" "$minor")
      fi
      color=$RESET
      shown=$reason
      case "$reason" in
        yes:*) color=$GREEN; shown=${reason#yes: } ;;
        no:*) color=$RED; shown=${reason#no: } ;;
      esac
      shown=${shown^}
      out ""
      out "  ${BOLD}${pkg}${RESET}"
      out "    Installed    ${ver}"
      out "    Candidate    ${cand:-none}"
      out "    ${color}${shown}${RESET}"
    done < <(installed_packages_for_series "$major" "$minor")
  done < <(vulnerable_indexes)
  if [[ ${#pkgs[@]} -eq 0 ]]; then
    out ""
    out "No installed package matched the vulnerable PHP series."
    out "If PHP was compiled by hand, install a distro package yourself. This tool will not compile PHP."
  fi
  out ""
  out "${BOLD}Commands after you answer yes${RESET}"
  case "$PM" in
    apt)
      out "  apt-get update"
      out "  DEBIAN_FRONTEND=noninteractive apt-get install -y --only-upgrade <confirmed packages>"
      ;;
    dnf)
      out "  dnf makecache"
      out "  dnf upgrade -y <confirmed packages>"
      ;;
    yum)
      out "  yum makecache"
      out "  yum upgrade -y <confirmed packages>"
      ;;
    apk)
      out "  apk update"
      out "  apk upgrade <confirmed packages>"
      ;;
    *)
      out "No supported package manager was detected."
      ;;
  esac
  repo_advice
}

refresh_candidate_metadata() {
  if [[ -n "$TEST_ROOT" || "$DRY_RUN" -eq 1 ]]; then
    return 0
  fi
  case "$PM" in
    apt) apt-get -o DPkg::Lock::Timeout=120 update ;;
    dnf) dnf makecache -y ;;
    yum) yum makecache -y ;;
    apk) apk update ;;
    *) return 1 ;;
  esac
}

fetch_apt_changelog() {
  local pkg=$1 dest=$2
  : >"$dest"
  if [[ -n "$TEST_ROOT" ]]; then
    append_changelog_file "$(rootp "/fixture/candidate-changelogs/${pkg}")" "$dest"
    return 0
  fi
  # On failure apt prints its error text on stdout, so drop it.
  if ! apt-get changelog "$pkg" >"$dest" 2>/dev/null; then
    : >"$dest"
  fi
  # The changelog server can be unreachable or return 404 for fresh security
  # uploads. The signed candidate package itself carries the same changelog.
  if [[ ! -s "$dest" ]]; then
    : >"$dest"
    changelog_from_candidate_deb "$pkg" "$dest" || true
  fi
  # The changelog server can return 404 for new security uploads. If this
  # exact candidate is already installed, its local changelog is the same text.
  if [[ ! -s "$dest" ]]; then
    local inst cand doc
    inst=$(dpkg-query -W -f='${Version}' "$pkg" 2>/dev/null || true)
    cand=$(apt-cache policy "$pkg" 2>/dev/null | awk '/Candidate:/ {print $2; exit}')
    if [[ -n "$inst" && "$inst" == "$cand" ]]; then
      for doc in "/usr/share/doc/${pkg}/changelog.Debian.gz" "/usr/share/doc/${pkg}/changelog.gz"; do
        [[ -f "$doc" ]] && { append_changelog_file "$doc" "$dest"; break; }
      done
    fi
  fi
}

# changelog_from_candidate_deb PKG DEST [DEPTH]. Downloads the signed candidate
# .deb with "apt-get download" into a private temp dir and reads its changelog
# without installing or running anything. Debian packages often make one
# binary's doc directory a symlink to another's, so one hop is followed.
changelog_from_candidate_deb() {
  local pkg=$1 dest=$2 depth=${3:-0}
  local dir deb name listing target
  command -v dpkg-deb >/dev/null 2>&1 || return 1
  dir=$(mktemp -d "${WORK_TMP:-/tmp}/deb.XXXXXX" 2>/dev/null) || return 1
  if ! (cd "$dir" && apt-get download "$pkg" >/dev/null 2>&1); then
    rm -rf "$dir"
    return 1
  fi
  deb=""
  for name in "$dir"/*.deb; do
    [[ -f "$name" ]] && deb=$name
  done
  if [[ -z "$deb" ]]; then
    rm -rf "$dir"
    return 1
  fi
  for name in changelog.Debian.gz changelog.gz; do
    dpkg-deb --fsys-tarfile "$deb" 2>/dev/null \
      | tar -xOf - "./usr/share/doc/${pkg}/${name}" 2>/dev/null \
      | gzip -dc >>"$dest" 2>/dev/null || true
    [[ -s "$dest" ]] && break
  done
  if [[ ! -s "$dest" && "$depth" -eq 0 ]]; then
    listing=$(dpkg-deb --fsys-tarfile "$deb" 2>/dev/null | tar -tvf - "./usr/share/doc/${pkg}" 2>/dev/null || true)
    target=$(printf '%s\n' "$listing" | awk -v p="./usr/share/doc/${pkg}" '$0 ~ (p " -> ") {print $NF; exit}')
    target=${target##*/}
    if [[ "$target" =~ ^[a-z0-9][a-z0-9+.-]*$ && "$target" != "$pkg" ]]; then
      rm -rf "$dir"
      changelog_from_candidate_deb "$target" "$dest" 1
      return $?
    fi
  fi
  rm -rf "$dir"
  [[ -s "$dest" ]]
}

apply_simulated_upgrade() {
  local pkg=$1 cand=$2
  local table path line p ver f
  table=$(rootp /fixture/installed.tsv)
  local tmp
  tmp=$(tmpfile)
  while IFS=$'\t' read -r p ver path || [[ -n "$p" ]]; do
    if [[ "$p" == "$pkg" ]]; then
      printf '%s\t%s\t%s\n' "$p" "$cand" "$path"
      if [[ -n "$path" && -f "$(rootp "$path")" ]]; then
        f=$(rootp "$path")
        parse_php_version_text "$cand"
        if [[ "$PARSED_OK" -eq 1 ]]; then
          awk -v ver="$PARSED_TRIPLE" '{sub(/PHP [0-9]+\.[0-9]+\.[0-9]+/, "PHP " ver); print}' "$f" >"${f}.new"
          mv "${f}.new" "$f"
          chmod +x "$f"
        fi
      fi
    else
      printf '%s\t%s\t%s\n' "$p" "$ver" "$path"
    fi
  done <"$table" >"$tmp"
  mv "$tmp" "$table"
  if [[ -f "$(rootp "/fixture/candidate-changelogs/${pkg}")" ]]; then
    mkdir -p "$(rootp "/usr/share/doc/${pkg}")"
    cp "$(rootp "/fixture/candidate-changelogs/${pkg}")" "$(rootp "/usr/share/doc/${pkg}/changelog")"
  fi
}

do_fix() {
  require_root
  DO_LOG=1
  if [[ -z "$(vulnerable_indexes)" ]]; then
    say "No vulnerable PHP was found. Nothing to upgrade."
    return 0
  fi
  print_fix_plan
  if [[ "$PM" == "unknown" ]]; then
    err "no supported package manager; nothing was changed"
    return 4
  fi
  if [[ "$DRY_RUN" -eq 1 ]]; then
    say "dry-run: no packages installed, no backup written, no services restarted."
    return 0
  fi
  if ! confirm "Back up configs, refresh package lists (this uses the network), and install only a confirmed fix?"; then
    say "Stopped before any change."
    return 1
  fi
  begin_backup || { err "no backup could be made. Nothing was installed."; return 4; }
  local i bfail=0
  while IFS= read -r i; do
    if [[ -n "${F_MAININI[i]}" && -f "$(rootp "${F_MAININI[i]}")" ]]; then
      backup_existing "${F_MAININI[i]}" || bfail=1
    fi
    local pool
    local IFS=$'\x1e'
    for pool in ${F_POOLS[i]}; do
      IFS=$'\n\t'
      if [[ -n "$pool" ]]; then
        backup_existing "$pool" || bfail=1
      fi
    done
    IFS=$'\n\t'
    if [[ -n "${F_PKG[i]}" && "${F_PKG[i]}" != "unknown" ]]; then
      record_package_version "${F_PKG[i]}" "${F_PKGVER[i]}"
    fi
  done < <(vulnerable_indexes)
  if [[ "$bfail" -eq 1 ]]; then
    err "a config backup failed. Nothing was installed."
    seal_backup
    return 4
  fi

  if ! refresh_candidate_metadata; then
    err "could not refresh package metadata"
    seal_backup
    return 4
  fi

  local -a install_pkgs=()
  local major minor rest pkg ver cand reason tmp state fixed shown color
  while IFS= read -r i; do
    [[ -n "${F_VERSION[i]}" ]] || continue
    major=${F_VERSION[i]%%.*}
    rest=${F_VERSION[i]#*.}
    minor=${rest%%.*}
    while IFS=$'\t' read -r pkg ver; do
      [[ -n "$pkg" ]] || continue
      cand=$(candidate_version_of "$pkg" || true)
      if package_is_held "$pkg"; then
        reason="no: held by the package manager. This tool will not release a hold."
      else
        reason=$(package_is_acceptable_upgrade "$pkg" "$ver" "$cand" "$major" "$minor")
      fi
      if [[ "$reason" == recheck-after-update ]]; then
        tmp=$(tmpfile)
        fetch_apt_changelog "$pkg" "$tmp"
        if [[ -s "$tmp" ]]; then
          state=$(cve_state_file "$tmp")
        else
          state="nochangelog"
        fi
        rm -f "$tmp"
        parse_php_version_text "$cand"
        if [[ "$PARSED_OK" -eq 1 && "$PARSED_PRE" -eq 0 ]] && fixed=$(fixed_triple "$PARSED_MAJOR" "$PARSED_MINOR") && version_ge "$PARSED_TRIPLE" "$fixed"; then
          reason="yes: candidate upstream ${PARSED_TRIPLE} is at least ${fixed}"
        elif [[ "$state" == "both" ]]; then
          reason="yes: apt changelog names both CVEs"
        elif [[ "$state" == "nochangelog" ]]; then
          reason="no: apt-get changelog ${pkg} returned nothing, so ${cand:-the candidate} could not be checked. Check the network and ca-certificates, then run again"
        else
          reason="no: after apt-get update, ${pkg} candidate ${cand:-none} is not a confirmed fix"
        fi
      fi
      shown=$reason
      color=$RESET
      case "$reason" in
        yes:*) color=$GREEN; shown=${reason#yes: } ;;
        no:*) color=$RED; shown=${reason#no: } ;;
      esac
      out "${color}${pkg}:${RESET} ${shown^}"
      if [[ "$reason" == yes:* ]]; then
        install_pkgs+=("$pkg")
      fi
    done < <(installed_packages_for_series "$major" "$minor")
  done < <(vulnerable_indexes)

  if [[ ${#install_pkgs[@]} -eq 0 ]]; then
    err "no confirmed fixed package is available. Nothing was installed."
    out ""
    out "You can re-run with --workarounds while you arrange a package."
    seal_backup
    return 4
  fi

  local unique
  unique=$(printf '%s\n' "${install_pkgs[@]}" | awk '!seen[$0]++')
  mapfile -t install_pkgs < <(printf '%s\n' "$unique" | awk 'NF')

  if [[ -n "$TEST_ROOT" ]]; then
    local p
    for p in "${install_pkgs[@]}"; do
      cand=$(candidate_version_of "$p" || true)
      apply_simulated_upgrade "$p" "$cand"
      note_action "test-root simulated upgrade ${p} -> ${cand}"
    done
  else
    local pm_rc=0
    case "$PM" in
      apt)
        # Keep local config files, wait for a busy dpkg lock instead of failing.
        DEBIAN_FRONTEND=noninteractive apt-get install -y --only-upgrade \
          -o DPkg::Lock::Timeout=120 -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold \
          "${install_pkgs[@]}" || pm_rc=$?
        ;;
      dnf)
        dnf upgrade -y "${install_pkgs[@]}" || pm_rc=$?
        ;;
      yum)
        yum upgrade -y "${install_pkgs[@]}" || pm_rc=$?
        ;;
      apk)
        apk upgrade "${install_pkgs[@]}" || pm_rc=$?
        ;;
    esac
    if [[ "$pm_rc" -ne 0 ]]; then
      err "the ${PM} upgrade failed (exit ${pm_rc}). No service was restarted. Check the package state before you restart anything."
      seal_backup
      return 4
    fi
    note_action "upgraded: ${install_pkgs[*]}"
  fi

  seal_backup
  if ! config_tests_pass; then
    err "the upgrade finished but the config test failed. No service was restarted, so the old workers keep serving. Fix the config, then restart PHP."
    return 4
  fi
  if ! restart_affected restart; then
    err "upgrade finished and at least one restart failed. Workers may still be running the old binary."
    return 4
  fi
  return 0
}

do_work() {
  require_root
  DO_LOG=1
  apply_workarounds
}

do_rollback() {
  require_root
  DO_LOG=1
  local dir
  dir=$(rootp "/var/backups/stacutis/${ROLLBACK}")
  if [[ ! -f "$dir/manifest" ]]; then
    err "no backup manifest at ${dir}"
    return 4
  fi
  say "Rollback ${ROLLBACK} restores config files and restarts the services recorded in the manifest."
  say "It does not downgrade PHP packages. Package lines in the manifest are the versions from before the change, for you to reinstall yourself if you mean to."
  if [[ "$DRY_RUN" -eq 1 ]]; then
    say "dry-run: would restore from ${dir}"
    emit_notice <"$dir/manifest"
    return 0
  fi
  if ! confirm "Restore configs from ${ROLLBACK} and restart the recorded services?"; then
    say "Stopped before any change."
    return 1
  fi
  local rc=0 kind
  restore_backup_files "$dir" || rc=$?
  if [[ "$rc" -ne 0 ]]; then
    return "$rc"
  fi
  if ! config_tests_pass; then
    err "the restored configs do not pass the config test. No service was restarted."
    return 4
  fi
  local svc
  while IFS=' ' read -r kind svc _; do
    [[ "$kind" == "SERVICE" ]] || continue
    if service_is_active "$svc" || [[ -n "$TEST_ROOT" ]]; then
      restart_one "$svc" || warn "restart failed for ${svc}"
    fi
  done <"$dir/manifest"
  say "Rollback of configs finished. If a package upgrade happened after this backup, PHP itself is still the upgraded build."
  return 0
}

show_options() {
  print_fix_plan
  out ""
  out "${BOLD}Option 2, temporary settings${RESET}"
  out "Each setting waits for its own yes."
  out "Nothing is written to .user.ini, and ini_set is not called. Those do not apply early enough."
  workaround_banner
  out ""
  out "  ${BOLD}Upload progress off${RESET}"
  out "  session.upload_progress.enabled=0 in conf.d, FPM php_admin_flag, and Apache"
  tradeoff "Upload progress off stops bars that use PHP_SESSION_UPLOAD_PROGRESS. It closes one confirmed path. Other ways into the bug stay open."
  out ""
  out "  ${BOLD}Fatal backtraces off${RESET}  ${CYAN}PHP 8.5 only${RESET}"
  out "  fatal_error_backtraces=0"
  tradeoff "On PHP 8.5, fatal errors lose this backtrace. It blocks one confirmed producer of the stale-state bug."
  out ""
  out "  ${BOLD}Post size${RESET}  ${CYAN}only when you choose a policy${RESET}"
  out "  No uploads: post_max_size 8M and upload_max_filesize 2M"
  out "  Uploads: post_max_size 32M and upload_max_filesize 8M"
  out "  8M and 32M are the advisory's post_max_size figures. 2M and 8M are this tool's choices for a smaller upload_max_filesize."
  tradeoff "Posts and uploads larger than the new cap fail. The site cannot raise the limit afterward."
  out ""
  out "  ${BOLD}Optional, and not the default${RESET}"
  out "  memory_limit=-1 via php_admin_value only, with a cgroup cap. Never RLIMIT_AS or RLIMIT_DATA."
  tradeoff "memory_limit=-1 removes PHP's RAM cap. One request can grow until the cgroup limit or the OS OOM killer. An allocation failure can still reach the bug."
  out "  pm.max_requests=1, which the stale-state advisory mentions when performance does not matter"
  tradeoff "pm.max_requests=1 exits every FPM worker after one request. Under load that costs CPU, adds latency, and can fill the listen queue."
  print_proxy_advice
}

menu() {
  local choice
  while true; do
    out ""
    out "${BOLD}What do you want to do?${RESET}"
    out ""
    out "  ${GREEN}[1]${RESET}  Upgrade PHP with ${PM}"
    out "       ${CYAN}Recommended. Only a confirmed package is installed.${RESET}"
    out ""
    out "  ${YELLOW}[2]${RESET}  Temporary settings"
    out "       ${RED}Leaves the vulnerable PHP installed. Upload progress stops. Later questions can break large uploads, remove PHP's RAM cap, or recycle every FPM worker.${RESET}"
    out ""
    out "  ${BOLD}[3]${RESET}  Show exactly what each option will change"
    out ""
    out "  [4]  Exit without changes"
    printf '\n%sChoose 1-4:%s ' "$BOLD" "$RESET" >&2
    if ! read -r choice; then
      printf '\n' >&2
      return 0
    fi
    case "$choice" in
      1)
        local rc=0
        do_fix || rc=$?
        scan_all
        checked_again
        report_all
        if [[ "$rc" -eq 4 || "$rc" -eq 5 ]]; then
          exit "$rc"
        fi
        exit "$(scan_code)"
        ;;
      2)
        local rc=0
        do_work || rc=$?
        scan_all
        checked_again
        report_all
        if [[ "$rc" -eq 4 || "$rc" -eq 5 ]]; then
          exit "$rc"
        fi
        exit "$(scan_code)"
        ;;
      3) show_options ;;
      4) return 0 ;;
      *) say "Enter 1, 2, 3, or 4." ;;
    esac
  done
}

scan_all() {
  reset_findings
  parse_os_release
  detect_pm
  discover_dirs
  load_apache_modules
  discover_procs
  local i
  for i in "${!F_SAPI[@]}"; do
    fill_config_at "$i"
  done
  classify_all
  if [[ "$DO_CONTAINERS" -eq 1 ]]; then
    scan_containers
  else
    CONTAINER_ROWS=()
    CONTAINER_NOTES=()
  fi
  if [[ "$DO_IOC" -eq 1 ]]; then
    ioc_scan
  fi
}

report_all() {
  count_status
  if [[ "$LOG_FOR_SCAN" -eq 1 ]]; then
    log_line "scan ${OS_ID} vulnerable=${COUNT_VULN} mitigated=${COUNT_MIT} patched=${COUNT_PATCH} unknown=${COUNT_UNK}"
  fi
  human_report
  json_report
}

# harden_path: this script runs as root and calls package managers, apachectl
# and systemctl by name. Start from the standard system directories, then keep
# the caller's PATH entries only if they are absolute, exist, are owned by root
# and are not writable by group or others. This drops ".", empty entries and
# user-writable directories.
harden_path() {
  local safe=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
  local entry owner mode old_ifs=$IFS
  IFS=:
  for entry in $PATH; do
    [[ "$entry" == /* && -d "$entry" ]] || continue
    case ":${safe}:" in *":${entry}:"*) continue ;; esac
    owner=$(stat -c %u -- "$entry" 2>/dev/null || true)
    mode=$(stat -c %a -- "$entry" 2>/dev/null || true)
    [[ "$owner" == 0 && -n "$mode" && "${mode: -2}" != *[2367]* ]] || continue
    safe="${safe}:${entry}"
  done
  IFS=$old_ifs
  PATH=$safe
  export PATH
}

main() {
  WORK_TMP=$(mktemp -d 2>/dev/null || true)
  trap cleanup_tmp EXIT
  trap 'exit 130' INT TERM
  parse_args "$@"
  if [[ -z "$TEST_ROOT" ]]; then
    harden_path
  fi
  setup_colors
  stale_data_warning
  if [[ -z "$TEST_ROOT" && "$(id -u)" -ne 0 ]]; then
    warn "not running as root: some files and /proc entries may be unreadable, so results can be UNKNOWN or incomplete."
  fi
  if [[ "$LOG_FOR_SCAN" -eq 1 ]]; then
    DO_LOG=1
  fi
  if [[ -n "$ROLLBACK" ]]; then
    local rc=0
    do_rollback || rc=$?
    if [[ "$rc" -eq 0 ]]; then
      scan_all
      checked_again
      report_all
      exit "$(scan_code)"
    fi
    exit "$rc"
  fi
  local second_report=0
  if [[ "$DO_FIX" -eq 1 ]]; then
    second_report=1
  elif [[ "$DO_WORK" -eq 1 && "$DRY_RUN" -eq 0 ]]; then
    second_report=1
  fi
  scan_all
  if [[ "$JSON" -eq 0 || "$second_report" -eq 0 ]]; then
    report_all
  fi
  if [[ "$DO_FIX" -eq 1 ]]; then
    local rc=0
    do_fix || rc=$?
    scan_all
    checked_again
    report_all
    if [[ "$rc" -ne 0 ]]; then
      exit "$rc"
    fi
    if [[ "$DRY_RUN" -eq 0 && "$ANY_RUNNING_DELETED" -eq 1 ]]; then
      err "A running PHP process is still mapped to a deleted binary. On-disk status is not the code those workers are running."
      exit 4
    fi
    exit "$(scan_code)"
  fi
  if [[ "$DO_WORK" -eq 1 ]]; then
    local rc=0
    do_work || rc=$?
    if [[ "$DRY_RUN" -eq 0 ]]; then
      scan_all
      checked_again
      report_all
      out ""
      out "${RED}Still VULNERABLE until PHP is upgraded.${RESET}"
    fi
    if [[ "$rc" -ne 0 && "$rc" -ne 1 ]]; then
      exit "$rc"
    fi
    exit "$(scan_code)"
  fi
  if needs_menu && [[ "$JSON" -eq 0 && "$QUIET" -eq 0 && "$ASSUME_YES" -eq 0 && -t 0 && -t 1 ]]; then
    menu
  fi
  exit "$(scan_code)"
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  main "$@"
fi
