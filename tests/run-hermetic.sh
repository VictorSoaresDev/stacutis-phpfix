#!/usr/bin/env bash
# Hermetic tests for stacutis-php2shell. They use --test-root fixtures.
# They do not install PHP, do not call a package manager, and do not need root.
ROOT=$(CDPATH='' cd -- "$(dirname "$0")/.." && pwd)
SCRIPT="$ROOT/stacutis-php2shell.sh"
# shellcheck source=make-fixture.sh
source "$ROOT/tests/make-fixture.sh"

FAILS=0
ROOTS=()

cleanup() {
  local r
  if [[ ${#ROOTS[@]} -eq 0 ]]; then
    return 0
  fi
  for r in "${ROOTS[@]}"; do
    rm -rf "$r"
  done
}
trap cleanup EXIT

pass() { printf 'PASS %s\n' "$1"; }
fail() {
  printf 'FAIL %s\n' "$1" >&2
  FAILS=$((FAILS + 1))
}
want() {
  [[ -z "${ONLY:-}" || "$1" == *"$ONLY"* ]]
}
keep() {
  ROOTS+=("$1")
}

tree_cksum() {
  local root=$1
  (
    cd "$root" || exit 1
    find . \( -type f -o -type l \) | sort | while IFS= read -r f; do
      if [[ -L "$f" ]]; then
        printf 'L %s %s\n' "$f" "$(readlink "$f")"
      else
        printf 'F %s %s\n' "$f" "$(cksum "$f" | awk '{print $1, $2}')"
      fi
    done
  )
}

run_tool() {
  RUN_OUT=$(mktemp)
  RUN_ERR=$(mktemp)
  RUN_RC=0
  bash "$SCRIPT" "$@" >"$RUN_OUT" 2>"$RUN_ERR" || RUN_RC=$?
}

assert_eq() {
  local name=$1 got=$2 expect=$3
  if [[ "$got" == "$expect" ]]; then
    pass "$name"
  else
    fail "$name: expected [${expect}] got [${got}]"
  fi
}

assert_rc() {
  assert_eq "$1 exit" "$RUN_RC" "$2"
}

one_json() {
  python3 - "$RUN_OUT" <<'PY'
import json, sys
raw = open(sys.argv[1], encoding="utf-8").read()
dec = json.JSONDecoder()
try:
    obj, idx = dec.raw_decode(raw)
except json.JSONDecodeError as exc:
    sys.stderr.write("json decode failed: %s\n" % exc)
    sys.exit(1)
rest = raw[idx:].strip()
if rest:
    sys.stderr.write("trailing data after JSON: %s\n" % rest[:200])
    sys.exit(1)
if not isinstance(obj, dict):
    sys.exit(1)
PY
}

json_get() {
  python3 - "$RUN_OUT" "$1" <<'PY'
import json, sys
d = json.load(open(sys.argv[1], encoding="utf-8"))
cur = d
for part in sys.argv[2].split("."):
    if part.isdigit():
        cur = cur[int(part)]
    else:
        cur = cur[part]
if isinstance(cur, bool):
    print("true" if cur else "false")
elif cur is None:
    print("null")
else:
    print(cur)
PY
}

finding() {
  local version=$1 sapi=$2
  python3 - "$RUN_OUT" "$version" "$sapi" <<'PY'
import json, sys
d = json.load(open(sys.argv[1], encoding="utf-8"))
ver, sapi = sys.argv[2], sys.argv[3]
hits = [f for f in d["findings"] if f["version"] == ver and (sapi == "" or f["sapi"] == sapi)]
if len(hits) != 1:
    sys.stderr.write("findings for %s %s: %s\n" % (sapi, ver, [(f["sapi"], f["version"], f["status"]) for f in d["findings"]]))
    sys.exit(1)
f = hits[0]
print("\t".join([
    f["status"], f["kind"], f["changelog_note"], f["risk"],
    f["session_upload_progress_enabled"], f["session_upload_progress_source"],
    f["fatal_error_backtraces"], f["fatal_error_backtraces_source"],
    "true" if f["prerelease"] else "false",
    f["pm_max_requests"],
]))
PY
}

classify_of() {
  bash -c 'source "$1"; IFS=$'"'"' \t\n'"'"'; classify_result "$2" "$3" "$4" "$5"' _ "$SCRIPT" "$1" "$2" "$3" "$4"
}

expect_classify() {
  local name=$1 text=$2 back=$3 up=$4 fat=$5 expect=$6
  local got
  got=$(classify_of "$text" "$back" "$up" "$fat") || got="CLASSIFY_FAILED:${got}"
  if [[ "$got" == "$expect" ]]; then
    pass "$name"
  else
    fail "$name: expected [${expect}] got [${got}]"
  fi
}

vuln_fpm() {
  local series=${1:-8.3} ver=${2:-8.3.6}
  local root bin
  root=$(fixture_new)
  keep "$root"
  bin="$root/usr/sbin/php-fpm${series}"
  fixture_php_bin "$bin" "$ver"
  fixture_add_pkg "$root" "php${series}-fpm" "${ver}-1" "/usr/sbin/php-fpm${series}"
  fixture_fpm_tree "$root" "$series"
  printf 'php%s-fpm\n' "$series" >"$root/fixture/services"
  printf '%s\n' "$root"
}

if want "unit"; then
  expect_classify "8.2.34 vulnerable" "PHP 8.2.34 (cli)" "unchecked" 0 0 \
    "VULNERABLE|none|8.2.34 is older than the fixed release 8.2.35|no-changelog"
  expect_classify "8.2.35 patched" "PHP 8.2.35 (cli)" "unchecked" 0 0 \
    "PATCHED|version|8.2.35 is at least the fixed release 8.2.35|no-changelog"
  expect_classify "8.2.36 patched" "PHP 8.2.36 (cli)" "none" 0 0 \
    "PATCHED|version|8.2.36 is at least the fixed release 8.2.35|changelog-without-cve"
  expect_classify "8.3.35 vulnerable" "PHP 8.3.35 (cli)" "unchecked" 0 0 \
    "VULNERABLE|none|8.3.35 is older than the fixed release 8.3.36|no-changelog"
  expect_classify "8.3.36 patched" "PHP 8.3.36 (cli)" "unchecked" 0 0 \
    "PATCHED|version|8.3.36 is at least the fixed release 8.3.36|no-changelog"
  expect_classify "8.4.26 vulnerable" "PHP 8.4.26 (cli)" "unchecked" 0 0 \
    "VULNERABLE|none|8.4.26 is older than the fixed release 8.4.27|no-changelog"
  expect_classify "8.4.27 patched" "PHP 8.4.27 (cli)" "unchecked" 0 0 \
    "PATCHED|version|8.4.27 is at least the fixed release 8.4.27|no-changelog"
  expect_classify "8.5.11 vulnerable" "PHP 8.5.11 (cli)" "unchecked" 0 0 \
    "VULNERABLE|none|8.5.11 is older than the fixed release 8.5.12|no-changelog"
  expect_classify "8.5.12 patched" "PHP 8.5.12 (cli)" "unchecked" 0 0 \
    "PATCHED|version|8.5.12 is at least the fixed release 8.5.12|no-changelog"
  expect_classify "8.5.12RC1 vulnerable" "PHP 8.5.12RC1 (cli)" "unchecked" 0 0 \
    "VULNERABLE|none|pre-release is not the security release|no-changelog"
  expect_classify "8.4.27-dev not patched" "PHP 8.4.27-dev (cli)" "unchecked" 0 0 \
    "VULNERABLE|none|pre-release is not the security release|no-changelog"
  expect_classify "ubuntu suffix not prerelease" "PHP 8.1.2-1ubuntu2.22 (cli)" "unchecked" 0 0 \
    "VULNERABLE|none|branch has no upstream fixed release|no-changelog"
  expect_classify "8.1 backport" "PHP 8.1.2 (cli)" "both" 0 0 \
    "PATCHED|backport|local package changelog names both CVEs|"
  expect_classify "version wins over changelog" "PHP 8.3.36 (cli)" "both" 0 0 \
    "PATCHED|version|8.3.36 is at least the fixed release 8.3.36|"
  expect_classify "partial changelog" "PHP 8.3.6 (cli)" "one" 0 0 \
    "VULNERABLE|none|8.3.6 is older than the fixed release 8.3.36|partial-changelog"
  expect_classify "8.6 unknown" "PHP 8.6.0 (cli)" "unchecked" 0 0 \
    "UNKNOWN|none|branch is outside the 2026-10-22 fixed-release table.|no-changelog"
  expect_classify "8.6 rc unknown" "PHP 8.6.0RC3 (cli)" "unchecked" 0 0 \
    "UNKNOWN|none|branch is outside the 2026-10-22 fixed-release table. This build is a pre-release.|no-changelog"
  expect_classify "empty unknown" "" "unchecked" 0 0 \
    "UNKNOWN|none|version could not be parsed|no-changelog"
  expect_classify "8.0 eol" "PHP 8.0.30 (cli)" "unchecked" 0 0 \
    "VULNERABLE|none|branch has no upstream fixed release|no-changelog"
  expect_classify "7.4 eol" "PHP 7.4.33 (cli)" "unchecked" 0 0 \
    "VULNERABLE|none|branch has no upstream fixed release|no-changelog"
  expect_classify "8.3 upload off mitigated" "PHP 8.3.6 (cli)" "unchecked" 1 0 \
    "MITIGATED|none|stale-state settings are off and the install is still vulnerable|no-changelog"
  expect_classify "8.5 upload off fatal on" "PHP 8.5.11 (cli)" "unchecked" 1 0 \
    "VULNERABLE|none|8.5.11 is older than the fixed release 8.5.12|no-changelog"
  expect_classify "8.5 both off mitigated" "PHP 8.5.11 (cli)" "unchecked" 1 1 \
    "MITIGATED|none|stale-state settings are off and the install is still vulnerable|no-changelog"
  expect_classify "garbage unknown" "not php" "none" 0 0 \
    "UNKNOWN|none|version could not be parsed|changelog-without-cve"
  pre=$(bash -c 'source "$1"; parse_php_version_text "$2"; printf "%s %s %s\n" "$PARSED_OK" "$PARSED_PRE" "$PARSED_TRIPLE"' _ "$SCRIPT" "PHP 8.1.2-1ubuntu2.22 (cli)")
  assert_eq "ubuntu parse not prerelease" "$pre" "1 0 8.1.2"
  off=$(bash -c 'source "$1"; if explicit_off "$2" "$3"; then echo yes; else echo no; fi' _ "$SCRIPT" "Off" "ini")
  assert_eq "explicit off ini" "$off" "yes"
  off=$(bash -c 'source "$1"; if explicit_off "$2" "$3"; then echo yes; else echo no; fi' _ "$SCRIPT" "On" "default")
  assert_eq "default On is not explicit off" "$off" "no"
  off=$(bash -c 'source "$1"; if explicit_off "$2" "$3"; then echo yes; else echo no; fi' _ "$SCRIPT" "0" "userini")
  assert_eq "userini does not count" "$off" "no"
  cve_tmp=$(mktemp)
  cat >"$cve_tmp" <<'EOF'
CVE-2026-109618 not affected
CVE-2026-109619 not vulnerable
EOF
  state=$(bash -c 'source "$1"; cve_state_file "$2"' _ "$SCRIPT" "$cve_tmp")
  assert_eq "not-affected changelog" "$state" "none"
  printf '%s\n' "Fixed CVE-2026-109618" >"$cve_tmp"
  state=$(bash -c 'source "$1"; cve_state_file "$2"' _ "$SCRIPT" "$cve_tmp")
  assert_eq "one cve" "$state" "one"
  printf '%s\n' "CVE-2026-109618 ignored" "CVE-2026-109619 no-dsa" >"$cve_tmp"
  state=$(bash -c 'source "$1"; cve_state_file "$2"' _ "$SCRIPT" "$cve_tmp")
  assert_eq "ignored and no-dsa" "$state" "none"
  printf '%s\n' "CVE-2026-109618" "CVE-2026-109619" >"$cve_tmp"
  state=$(bash -c 'source "$1"; cve_state_file "$2"' _ "$SCRIPT" "$cve_tmp")
  assert_eq "both cves" "$state" "both"
  rm -f "$cve_tmp"
fi

stubs=$(mktemp -d)
ROOTS+=("$stubs")
forbid_log="$stubs/forbidden.log"
: >"$forbid_log"
for cmd in apt-get apt-cache dpkg dpkg-query dnf yum rpm apk systemctl docker journalctl; do
  cat >"$stubs/$cmd" <<EOF
#!/bin/sh
printf '%s\n' "FORBIDDEN \$0 \$*" >>"$forbid_log"
exit 99
EOF
  chmod +x "$stubs/$cmd"
done
export PATH="$stubs:$PATH"

host_log="/var/log/stacutis-php2shell.log"
host_log_before="absent"
if [[ -e "$host_log" ]]; then
  host_log_before=$(cksum "$host_log" | awk '{print $1, $2}')
fi

if want "usage"; then
  run_tool --help
  assert_rc "--help" 0
  grep -q -- '--test-root' "$RUN_OUT" && pass "--help mentions test-root" || fail "--help missing test-root"
  run_tool --version
  assert_rc "--version" 0
  grep -q '1.0.0' "$RUN_OUT" && pass "version string" || fail "version string"
  grep -q '2026-10-22' "$RUN_OUT" && pass "cve data date" || fail "cve data date"
  grep -q 'CVE-2026-109618' "$RUN_OUT" && grep -q 'CVE-2026-109619' "$RUN_OUT" && pass "version cves" || fail "version cves"
  run_tool --not-a-flag || true
  assert_rc "unknown flag" 2
  run_tool --rollback not-a-stamp || true
  assert_rc "bad rollback stamp" 2
  run_tool --fix --workarounds || true
  assert_rc "fix and workarounds" 2
  run_tool --upload-policy none || true
  assert_rc "upload policy without workarounds" 2
  run_tool --test-root / || true
  assert_rc "test-root slash" 2
  bare=$(mktemp -d)
  keep "$bare"
  run_tool --test-root "$bare" || true
  assert_rc "test-root without marker" 2
fi

if want "nophp"; then
  root=$(fixture_new)
  keep "$root"
  : >"$root/fixture/services"
  run_tool --json --test-root "$root"
  assert_rc "no php" 0
  one_json && pass "no php json" || fail "no php json"
  assert_eq "no php count" "$(json_get counts.vulnerable)" "0"
  assert_eq "ioc null" "$(json_get ioc)" "null"
fi

if want "scan-matrix"; then
  root=$(fixture_new)
  keep "$root"
  : >"$root/fixture/services"
  fixture_php_bin "$root/usr/bin/php8.2" "8.2.34"
  fixture_add_pkg "$root" "php8.2-cli" "8.2.34-1" "/usr/bin/php8.2"
  fixture_php_bin "$root/usr/sbin/php-fpm8.3" "8.3.36"
  fixture_add_pkg "$root" "php8.3-fpm" "8.3.36-1" "/usr/sbin/php-fpm8.3"
  fixture_fpm_tree "$root" "8.3"
  fixture_php_bin "$root/usr/bin/php8.1" "8.1.2"
  fixture_add_pkg "$root" "php8.1-cli" "8.1.2-1ubuntu2.22" "/usr/bin/php8.1"
  fixture_changelog "$root" "php8.1-cli" <<'EOF'
php8.1 (8.1.2-1ubuntu2.22) jammy-security; urgency=medium
  * CVE-2026-109618
  * CVE-2026-109619
EOF
  fixture_php_bin "$root/usr/bin/php8.4" "8.4.26"
  fixture_add_pkg "$root" "php8.4-cli" "8.4.26-1" "/usr/bin/php8.4"
  fixture_changelog "$root" "php8.4-cli" <<'EOF'
php8.4 (8.4.26-1) unstable; urgency=medium
  * CVE-2026-109618 fixed in a later upload
EOF
  snap=$(tree_cksum "$root")
  run_tool --json --test-root "$root"
  assert_rc "matrix scan" 1
  one_json && pass "matrix one json" || fail "matrix one json"
  [[ "$(tree_cksum "$root")" == "$snap" ]] && pass "scan writes nothing" || fail "scan writes nothing"
  [[ ! -d "$root/var/backups" ]] && pass "scan creates no backup" || fail "scan creates no backup"
  [[ ! -e "$root/var/log/stacutis-php2shell.log" ]] && pass "scan creates no log" || fail "scan creates no log"
  [[ ! -s "$forbid_log" ]] && pass "scan makes no package-manager call" || fail "scan called: $(cat "$forbid_log")"
  row=$(finding "8.2.34" "cli") || row="MISSING"
  assert_eq "8.2.34 status" "${row%%$'\t'*}" "VULNERABLE"
  row=$(finding "8.3.36" "fpm") || row="MISSING"
  assert_eq "8.3.36 status" "${row%%$'\t'*}" "PATCHED"
  [[ "$row" == *$'\t'"version"$'\t'* ]] && pass "8.3.36 kind version" || fail "8.3.36 kind: $row"
  row=$(finding "8.1.2" "cli") || row="MISSING"
  assert_eq "8.1.2 backport status" "${row%%$'\t'*}" "PATCHED"
  [[ "$row" == *$'\t'"backport"$'\t'* ]] && pass "8.1.2 kind backport" || fail "8.1.2 kind: $row"
  row=$(finding "8.4.26" "cli") || row="MISSING"
  assert_eq "partial still vulnerable" "${row%%$'\t'*}" "VULNERABLE"
  [[ "$row" == *"partial-changelog"* ]] && pass "partial note" || fail "partial note: $row"
fi

if want "not-affected"; then
  root=$(fixture_new)
  keep "$root"
  fixture_php_bin "$root/usr/bin/php8.1" "8.1.2"
  fixture_add_pkg "$root" "php8.1-cli" "8.1.2-1" "/usr/bin/php8.1"
  fixture_changelog "$root" "php8.1-cli" <<'EOF'
  * CVE-2026-109618: not affected
  * CVE-2026-109619 not vulnerable
EOF
  : >"$root/fixture/services"
  run_tool --json --test-root "$root"
  assert_rc "not-affected still vulnerable" 1
  row=$(finding "8.1.2" "cli") || row="MISSING"
  assert_eq "not-affected status" "${row%%$'\t'*}" "VULNERABLE"
  [[ "$row" == *"changelog-without-cve"* ]] && pass "not-affected note" || fail "not-affected note: $row"
fi

if want "gz-backport"; then
  root=$(fixture_new)
  keep "$root"
  fixture_php_bin "$root/usr/bin/php8.1" "8.1.2"
  fixture_add_pkg "$root" "php8.1-cli" "8.1.2-1" "/usr/bin/php8.1"
  mkdir -p "$root/usr/share/doc/php8.1-cli"
  printf '%s\n' "CVE-2026-109618" "CVE-2026-109619" | gzip -c >"$root/usr/share/doc/php8.1-cli/changelog.Debian.gz"
  : >"$root/fixture/services"
  run_tool --json --test-root "$root"
  assert_rc "gz backport exit" 0
  row=$(finding "8.1.2" "cli") || row="MISSING"
  assert_eq "gz backport status" "${row%%$'\t'*}" "PATCHED"
fi

if want "mitigated-config"; then
  root=$(vuln_fpm 8.3 8.3.6)
  ini="$root/etc/php/8.3/fpm/php.ini"
  cat >"$ini" <<'EOF'
session.upload_progress.enabled = Off
memory_limit = 128M
EOF
  cat >"$root/etc/php/8.3/fpm/pool.d/www.conf" <<'EOF'
[www]
user = www-data
pm.max_requests = 500
php_admin_flag[session.upload_progress.enabled] = off

[extra]
user = www-data
php_admin_flag[session.upload_progress.enabled] = off
EOF
  run_tool --test-root "$root"
  assert_rc "config mitigated" 1
  grep -q 'MITIGATED (still vulnerable)' "$RUN_OUT" && pass "human mitigated label" || fail "human mitigated label"
  grep -q 'Still VULNERABLE until PHP is upgraded' "$RUN_OUT" && pass "human still vulnerable" || fail "human still vulnerable"
  grep -q $'\033' "$RUN_OUT" && fail "color on a pipe" || pass "no color on a pipe"
  run_tool --json --test-root "$root"
  row=$(finding "8.3.6" "fpm") || row="MISSING"
  assert_eq "pool admin mitigated" "${row%%$'\t'*}" "MITIGATED"
fi

if want "8.5-fatal"; then
  root=$(vuln_fpm 8.5 8.5.11)
  cat >"$root/etc/php/8.5/fpm/php.ini" <<'EOF'
session.upload_progress.enabled = Off
fatal_error_backtraces = On
EOF
  printf 'php8.5-fpm\n' >"$root/fixture/services"
  run_tool --json --test-root "$root"
  row=$(finding "8.5.11" "fpm") || row="MISSING"
  assert_eq "8.5 fatal still on" "${row%%$'\t'*}" "VULNERABLE"
  cat >"$root/etc/php/8.5/fpm/php.ini" <<'EOF'
session.upload_progress.enabled = Off
fatal_error_backtraces = Off
EOF
  run_tool --json --test-root "$root"
  row=$(finding "8.5.11" "fpm") || row="MISSING"
  assert_eq "8.5 both off" "${row%%$'\t'*}" "MITIGATED"
fi

if want "prerelease-scan"; then
  root=$(vuln_fpm 8.5 "8.5.12RC1")
  run_tool --json --test-root "$root"
  assert_rc "prerelease scan" 1
  row=$(finding "8.5.12" "fpm") || row="MISSING"
  assert_eq "rc status" "${row%%$'\t'*}" "VULNERABLE"
  [[ "$row" == *$'\t'"true"$'\t'* ]] && pass "rc prerelease flag" || fail "rc prerelease flag: $row"
fi

if want "unknown-only"; then
  root=$(fixture_new)
  keep "$root"
  fixture_php_bin "$root/usr/bin/php8.6" "8.6.0RC3"
  fixture_add_pkg "$root" "php8.6-cli" "8.6.0~rc3" "/usr/bin/php8.6"
  : >"$root/fixture/services"
  run_tool --json --test-root "$root"
  assert_rc "unknown only" 3
  row=$(finding "8.6.0" "cli") || row="MISSING"
  assert_eq "8.6 status" "${row%%$'\t'*}" "UNKNOWN"
fi

if want "garbage"; then
  root=$(fixture_new)
  keep "$root"
  mkdir -p "$root/usr/bin"
  printf '#!/bin/sh\nprintf "nope\\n"\nexit 0\n' >"$root/usr/bin/php"
  chmod 755 "$root/usr/bin/php"
  : >"$root/fixture/services"
  run_tool --json --test-root "$root"
  assert_rc "garbage version" 3
fi

if want "modphp"; then
  root=$(vuln_fpm 8.3 8.3.6)
  fixture_php_bin "$root/usr/bin/php8.3" "8.3.6"
  fixture_add_pkg "$root" "php8.3-cli" "8.3.6-1" "/usr/bin/php8.3"
  printf ' php_module (shared)\n' >"$root/fixture/apache-modules"
  run_tool --json --test-root "$root"
  assert_eq "mod_php flag" "$(json_get mod_php)" "true"
  row=$(finding "8.3.6" "modphp") || row="MISSING"
  assert_eq "modphp vulnerable" "${row%%$'\t'*}" "VULNERABLE"
  [[ "$row" == *$'\t'"highest"$'\t'* ]] && pass "modphp highest risk" || fail "modphp risk: $row"
  root2=$(fixture_new)
  keep "$root2"
  fixture_php_bin "$root2/usr/bin/php8.2" "8.2.34"
  fixture_php_bin "$root2/usr/sbin/php-fpm8.3" "8.3.6"
  fixture_add_pkg "$root2" "php8.2-cli" "8.2.34-1" "/usr/bin/php8.2"
  fixture_add_pkg "$root2" "php8.3-fpm" "8.3.6-1" "/usr/sbin/php-fpm8.3"
  fixture_fpm_tree "$root2" "8.3"
  printf 'php_module (shared)\n' >"$root2/fixture/apache-modules"
  : >"$root2/fixture/services"
  run_tool --json --test-root "$root2"
  python3 - "$RUN_OUT" <<'PY'
import json, sys
d = json.load(open(sys.argv[1], encoding="utf-8"))
mods = [f for f in d["findings"] if f["sapi"] == "modphp"]
assert len(mods) == 1, mods
assert mods[0]["status"] == "UNKNOWN", mods[0]
assert mods[0]["version"] == "", mods[0]
PY
  if [[ $? -eq 0 ]]; then pass "mixed modphp unknown"; else fail "mixed modphp unknown"; fi
fi

if want "dropin-order"; then
  root=$(vuln_fpm 8.3 8.3.6)
  printf '%s\n' 'session.upload_progress.enabled = On' >"$root/etc/php/8.3/fpm/conf.d/10-on.ini"
  printf '%s\n' 'session.upload_progress.enabled = Off' >"$root/etc/php/8.3/fpm/conf.d/99-off.ini"
  printf '%s\n' 'session.upload_progress.enabled = Off' >"$root/var/www/html/.user.ini"
  run_tool --json --test-root "$root"
  row=$(finding "8.3.6" "fpm") || row="MISSING"
  assert_eq "sorted drop-in off wins" "${row%%$'\t'*}" "MITIGATED"
fi

if want "yes-alone"; then
  root=$(vuln_fpm)
  snap=$(tree_cksum "$root")
  run_tool --yes --test-root "$root"
  assert_rc "--yes alone" 1
  [[ "$(tree_cksum "$root")" == "$snap" ]] && pass "--yes writes nothing" || fail "--yes writes nothing"
  grep -q 'Choose 1-4' "$RUN_OUT" "$RUN_ERR" && fail "menu without a tty" || pass "no menu without a tty"
fi

if want "dry-run"; then
  root=$(vuln_fpm)
  snap=$(tree_cksum "$root")
  run_tool --dry-run --fix --yes --test-root "$root"
  assert_rc "dry-run fix" 1
  [[ "$(tree_cksum "$root")" == "$snap" ]] && pass "dry-run fix writes nothing" || fail "dry-run fix writes nothing"
  [[ ! -s "$forbid_log" ]] && pass "dry-run fix no network tools" || fail "dry-run fix called a package tool"
  run_tool --dry-run --workarounds --yes --upload-policy none --test-root "$root"
  assert_rc "dry-run work" 1
  [[ "$(tree_cksum "$root")" == "$snap" ]] && pass "dry-run work writes nothing" || fail "dry-run work writes nothing"
  grep -q 'RLIMIT_AS' "$RUN_OUT" && pass "proxy advice names RLIMIT_AS" || fail "proxy advice names RLIMIT_AS"
fi

if want "fix-refuse"; then
  root=$(vuln_fpm)
  snap=$(tree_cksum "$root")
  run_tool --fix --test-root "$root"
  assert_rc "fix without yes" 1
  [[ "$(tree_cksum "$root")" == "$snap" ]] && pass "declined fix writes nothing" || fail "declined fix writes nothing"
fi

if want "work"; then
  root=$(vuln_fpm)
  run_tool --json --workarounds --yes --upload-policy none --test-root "$root"
  assert_rc "workarounds" 1
  one_json && pass "work one json" || fail "work one json"
  grep -q 'Still VULNERABLE until PHP is upgraded' "$RUN_ERR" && pass "work still vulnerable" || fail "work still vulnerable stderr"
  row=$(finding "8.3.6" "fpm") || row="MISSING"
  assert_eq "work status mitigated" "${row%%$'\t'*}" "MITIGATED"
  ini="$root/etc/php/8.3/fpm/conf.d/99-stacutis-php2shell.ini"
  grep -q 'session.upload_progress.enabled = 0' "$ini" && pass "drop-in upload off" || fail "drop-in upload off"
  grep -q 'post_max_size = 8M' "$ini" && pass "drop-in post 8M" || fail "drop-in post 8M"
  grep -q 'upload_max_filesize = 2M' "$ini" && pass "drop-in upload 2M" || fail "drop-in upload 2M"
  grep -q 'fatal_error_backtraces' "$ini" && fail "8.3 drop-in has fatal backtraces" || pass "8.3 drop-in omits fatal backtraces"
  grep -q 'memory_limit' "$ini" && fail "drop-in has memory_limit" || pass "drop-in omits memory_limit"
  pool="$root/etc/php/8.3/fpm/pool.d/www.conf"
  grep -q 'php_admin_flag\[session.upload_progress.enabled\] = off' "$pool" && pass "pool admin flag" || fail "pool admin flag"
  count=$(grep -c 'php_admin_flag\[session.upload_progress.enabled\] = off' "$pool")
  assert_eq "both pools patched" "$count" "2"
  grep -q 'php_admin_value\[post_max_size\] = 8M' "$pool" && pass "pool post 8M" || fail "pool post 8M"
  grep -q 'memory_limit' "$pool" && fail "pool has memory_limit" || pass "pool omits memory_limit"
  grep -q 'php8.3-fpm' "$root/fixture/restarts.log" && pass "fpm restarted" || fail "fpm restarted"
  blog=$(find "$root/var/backups/stacutis" -mindepth 1 -maxdepth 1 -type d | head -1)
  [[ -n "$blog" ]] && pass "backup dir exists" || fail "backup dir exists"
  mode=$(stat -c %a "$blog")
  assert_eq "backup dir mode" "$mode" "700"
  bad=$(find "$blog" -type f -perm /077 -print | head)
  [[ -z "$bad" ]] && pass "backup files are private" || fail "backup files are private: $bad"
  logmode=$(stat -c %a "$root/var/log/stacutis-php2shell.log")
  assert_eq "log mode" "$logmode" "600"
  stamp=$(basename "$blog")
  run_tool --json --rollback "$stamp" --yes --test-root "$root"
  assert_rc "rollback" 1
  one_json && pass "rollback one json" || fail "rollback one json"
  [[ ! -e "$ini" ]] && pass "rollback removes drop-in" || fail "rollback removes drop-in"
  grep -q 'stacutis-php2shell' "$pool" && fail "rollback restores pool" || pass "rollback restores pool"
  row=$(finding "8.3.6" "fpm") || row="MISSING"
  assert_eq "rollback vulnerable again" "${row%%$'\t'*}" "VULNERABLE"
fi

if want "work-uploads"; then
  root=$(vuln_fpm)
  run_tool --workarounds --yes --upload-policy uploads --allow-unlimited-memory --max-requests-1 --test-root "$root"
  assert_rc "work extras" 1
  ini="$root/etc/php/8.3/fpm/conf.d/99-stacutis-php2shell.ini"
  pool="$root/etc/php/8.3/fpm/pool.d/www.conf"
  grep -q 'post_max_size = 32M' "$ini" && pass "uploads post 32M" || fail "uploads post 32M"
  grep -q 'upload_max_filesize = 8M' "$ini" && pass "uploads file 8M" || fail "uploads file 8M"
  grep -q 'memory_limit' "$ini" && fail "memory_limit leaked into ini" || pass "memory_limit stays out of ini"
  grep -q 'php_admin_value\[memory_limit\] = -1' "$pool" && pass "memory_limit admin only" || fail "memory_limit admin only"
  grep -q 'pm.max_requests = 1' "$pool" && pass "max requests 1" || fail "max requests 1"
  grep -q 'stacutis-php2shell previous: pm.max_requests = 500' "$pool" && pass "old max requests kept" || fail "old max requests kept"
fi

if want "work-85"; then
  root=$(vuln_fpm 8.5 8.5.11)
  run_tool --json --workarounds --yes --test-root "$root"
  assert_rc "8.5 work" 1
  row=$(finding "8.5.11" "fpm") || row="MISSING"
  assert_eq "8.5 work mitigated" "${row%%$'\t'*}" "MITIGATED"
  ini="$root/etc/php/8.5/fpm/conf.d/99-stacutis-php2shell.ini"
  grep -q 'fatal_error_backtraces = 0' "$ini" && pass "8.5 fatal off" || fail "8.5 fatal off"
  grep -q 'post_max_size' "$ini" && fail "post size without policy" || pass "post size skipped without policy"
fi

if want "work-norestart"; then
  root=$(vuln_fpm)
  : >"$root/fixture/services"
  run_tool --workarounds --yes --upload-policy none --test-root "$root"
  assert_rc "work without a service" 4
  grep -q 'no PHP or web service was restarted' "$RUN_ERR" && pass "loud missed restart" || fail "loud missed restart"
fi

if want "fix"; then
  root=$(vuln_fpm)
  fixture_add_candidate "$root" "php8.3-fpm" "8.3.36-1ubuntu1"
  : >"$forbid_log"
  run_tool --json --fix --yes --test-root "$root"
  assert_rc "simulated fix" 0
  one_json && pass "fix one json" || fail "fix one json"
  row=$(finding "8.3.36" "fpm") || row="MISSING"
  assert_eq "fix patched" "${row%%$'\t'*}" "PATCHED"
  [[ "$row" == *$'\t'"version"$'\t'* ]] && pass "fix kind version" || fail "fix kind: $row"
  grep -q 'PHP 8.3.36' "$root/usr/sbin/php-fpm8.3" && pass "binary rewritten" || fail "binary rewritten"
  grep -q 'php8.3-fpm' "$root/fixture/restarts.log" && pass "fix restarted" || fail "fix restarted"
  [[ ! -s "$forbid_log" ]] && pass "simulated fix does not call apt" || fail "simulated fix called: $(cat "$forbid_log")"
fi

if want "fix-eol"; then
  root=$(fixture_new)
  keep "$root"
  fixture_php_bin "$root/usr/sbin/php-fpm8.1" "8.1.2"
  fixture_add_pkg "$root" "php8.1-fpm" "8.1.2-1" "/usr/sbin/php-fpm8.1"
  fixture_fpm_tree "$root" "8.1"
  printf 'php8.1-fpm\n' >"$root/fixture/services"
  fixture_add_candidate "$root" "php8.1-fpm" "8.3.36-1"
  run_tool --fix --yes --test-root "$root"
  assert_rc "eol major upgrade refused" 4
  grep -q 'PHP 8.1.2' "$root/usr/sbin/php-fpm8.1" && pass "eol binary unchanged" || fail "eol binary unchanged"
  rootb=$(fixture_new)
  keep "$rootb"
  fixture_php_bin "$rootb/usr/sbin/php-fpm8.1" "8.1.2"
  fixture_add_pkg "$rootb" "php8.1-fpm" "8.1.2-1" "/usr/sbin/php-fpm8.1"
  fixture_fpm_tree "$rootb" "8.1"
  printf 'php8.1-fpm\n' >"$rootb/fixture/services"
  fixture_add_candidate "$rootb" "php8.1-fpm" "8.1.2-2"
  fixture_candidate_changelog "$rootb" "php8.1-fpm" <<'EOF'
php8.1 (8.1.2-2) bookworm-security; urgency=high
  * CVE-2026-109618
  * CVE-2026-109619
EOF
  run_tool --json --fix --yes --test-root "$rootb"
  assert_rc "eol backport upgrade" 0
  row=$(finding "8.1.2" "fpm") || row="MISSING"
  assert_eq "eol candidate changelog patched" "${row%%$'\t'*}" "PATCHED"
  [[ "$row" == *$'\t'"backport"$'\t'* ]] && pass "eol kind backport" || fail "eol kind: $row"
fi

if want "fix-nocandidate"; then
  root=$(vuln_fpm)
  run_tool --fix --yes --test-root "$root"
  assert_rc "no candidate" 4
  grep -q 'PHP 8.3.6' "$root/usr/sbin/php-fpm8.3" && pass "no candidate leaves binary" || fail "no candidate leaves binary"
  grep -q 'will not add repositories' "$RUN_ERR" "$RUN_OUT" && pass "repo advice" || fail "repo advice"
fi

if want "deleted"; then
  root=$(vuln_fpm)
  fixture_add_candidate "$root" "php8.3-fpm" "8.3.36-1"
  mkdir -p "$root/proc/4242"
  ln -s "$root/usr/sbin/php-fpm8.3 (deleted)" "$root/proc/4242/exe"
  run_tool --json --fix --yes --test-root "$root"
  assert_rc "deleted binary after fix" 4
  grep -q 'deleted binary' "$RUN_ERR" && pass "deleted binary message" || fail "deleted binary message"
  assert_eq "deleted flag" "$(json_get running_deleted_binary)" "true"
  row=$(finding "8.3.36" "fpm") || row="MISSING"
  assert_eq "on-disk patched while deleted runs" "${row%%$'\t'*}" "PATCHED"
fi

if want "ioc"; then
  root=$(vuln_fpm)
  mkdir -p "$root/var/log/apache2" "$root/proc/10" "$root/proc/11" "$root/proc/net"
  printf '%s\n' 'UNIQUE_ACCESS_TOKEN PHP_SESSION_UPLOAD_PROGRESS multipart' >"$root/var/log/apache2/access.log"
  printf '%s\n' 'segfault in php-fpm' >"$root/var/log/php8.3-fpm.log"
  printf '%s\n' '<?php eval(base64_decode("SECRET_PAYLOAD_XYZ"));' >"$root/var/www/html/shell.php"
  printf 'www-data:x:33:33::/var/www:/usr/sbin/nologin\n' >"$root/etc/passwd"
  printf '%s\n' 'php-fpm' >"$root/proc/10/comm"
  printf '%s\n' 'PPid: 1' >"$root/proc/10/status"
  ln -s "$root/usr/sbin/php-fpm8.3" "$root/proc/10/exe"
  printf '%s\n' 'curl' >"$root/proc/11/comm"
  printf '%s\n' 'PPid: 10' >"$root/proc/11/status"
  ln -s "/usr/bin/curl" "$root/proc/11/exe"
  cat >"$root/proc/net/tcp" <<'EOF'
  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 0100007F:0050 0100007F:1F90 01 00000000:00000000 00:00000000 00000000     33        0 1234 1 0000000000000000 100 0 0 10 0
EOF
  run_tool --json --ioc --test-root "$root"
  assert_rc "ioc keeps vulnerable exit" 1
  [[ -f "$root/var/www/html/shell.php" ]] && pass "ioc does not delete" || fail "ioc does not delete"
  grep -q 'SECRET_PAYLOAD_XYZ' "$RUN_OUT" "$RUN_ERR" && fail "ioc leaked file body" || pass "ioc hides file body"
  grep -q 'UNIQUE_ACCESS_TOKEN' "$RUN_OUT" "$RUN_ERR" && fail "ioc leaked access line" || pass "ioc hides access line"
  python3 - "$RUN_OUT" <<'PY'
import json, sys
d = json.load(open(sys.argv[1], encoding="utf-8"))
ioc = d["ioc"]
assert ioc is not None
assert ioc["since"] == "2026-10-17"
assert any("eval_base64" in x for x in ioc["webshell_hits"]), ioc["webshell_hits"]
assert any("PHP_SESSION_UPLOAD_PROGRESS" not in x and "access.log" in x for x in ioc["upload_progress_requests"])
assert any("segfault" not in x and "php8.3-fpm.log" in x for x in ioc["crash_lines"])
assert any("curl" in x for x in ioc["child_processes"]), ioc["child_processes"]
assert any("www-data" in x and "ESTABLISHED" in x for x in ioc["outbound"]), ioc["outbound"]
PY
  if [[ $? -eq 0 ]]; then pass "ioc records"; else fail "ioc records"; fi
  run_tool --json --test-root "$root"
  assert_eq "ioc omitted" "$(json_get ioc)" "null"
fi

if want "containers"; then
  root=$(vuln_fpm)
  printf '%s\n' 'abc123	php:8.3-fpm	web' >"$root/fixture/docker-ps"
  : >"$forbid_log"
  run_tool --json --containers --test-root "$root"
  one_json && pass "containers json" || fail "containers json"
  python3 - "$RUN_OUT" <<'PY'
import json, sys
d = json.load(open(sys.argv[1], encoding="utf-8"))
rows = d["containers"]["rows"]
assert any("abc123" in x for x in rows), rows
PY
  if [[ $? -eq 0 ]]; then pass "container listed"; else fail "container listed"; fi
  [[ ! -s "$forbid_log" ]] && pass "containers do not call docker" || fail "containers called docker"
fi

if want "quiet"; then
  root=$(vuln_fpm)
  run_tool --quiet --test-root "$root"
  assert_rc "quiet" 1
  assert_eq "quiet line" "$(tr -d '\r' <"$RUN_OUT")" "stacutis-php2shell: vulnerable=1 mitigated=0 patched=0 unknown=0"
fi

if want "rollback-guard"; then
  root=$(vuln_fpm)
  stamp="20261022T120000Z"
  dir="$root/var/backups/stacutis/$stamp"
  mkdir -p "$dir"
  printf '%s\n' "STACUTIS_BACKUP 1" "CREATED /etc/passwd" >"$dir/manifest"
  printf 'keep\n' >"$root/etc/passwd"
  run_tool --rollback "$stamp" --yes --test-root "$root"
  assert_rc "rollback rejects passwd" 4
  [[ "$(cat "$root/etc/passwd")" == "keep" ]] && pass "passwd kept" || fail "passwd kept"
fi

if want "log-flag"; then
  root=$(vuln_fpm)
  run_tool --log --test-root "$root"
  [[ -f "$root/var/log/stacutis-php2shell.log" ]] && pass "--log creates a log" || fail "--log creates a log"
fi

if want "rhel-note"; then
  root=$(fixture_new)
  keep "$root"
  fixture_php_bin "$root/usr/sbin/php-fpm" "8.3.6"
  fixture_add_pkg "$root" "php-fpm" "8.3.6-1.el9" "/usr/sbin/php-fpm"
  mkdir -p "$root/etc/php.d" "$root/etc/php-fpm.d"
  printf '%s\n' 'session.upload_progress.enabled = On' 'memory_limit = 128M' >"$root/etc/php.ini"
  printf '%s\n' '[www]' 'user = apache' 'pm.max_requests = 0' >"$root/etc/php-fpm.d/www.conf"
  printf 'php-fpm\n' >"$root/fixture/services"
  run_tool --test-root "$root"
  grep -q 'shared /etc/php.ini' "$RUN_OUT" && pass "shared ini note" || fail "shared ini note"
  assert_rc "rhel layout vulnerable" 1
fi

if want "c1-backport-owner"; then
  # A patched distro package must not vouch for an unpackaged binary.
  root=$(fixture_new)
  keep "$root"
  fixture_php_bin "$root/usr/bin/php8.2" "8.2.7"
  fixture_add_pkg "$root" "php8.2-cli" "8.2.7-1~deb12u9" "/usr/bin/php8.2"
  fixture_changelog "$root" "php8.2-cli" <<'CL'
php8.2 (8.2.7-1~deb12u9) bookworm-security; urgency=medium
  * CVE-2026-109618
  * CVE-2026-109619
CL
  fixture_php_bin "$root/usr/local/bin/php" "8.2.10"
  run_tool --json --test-root "$root"
  assert_eq "c1 distro build backported" "$(finding 8.2.7 cli | cut -f1)" "PATCHED"
  assert_eq "c1 unpackaged build vulnerable" "$(finding 8.2.10 cli | cut -f1)" "VULNERABLE"
  assert_rc "c1 scan" 1
fi

if want "c2-no-exec-untrusted"; then
  root=$(fixture_new)
  keep "$root"
  mkdir -p "$root/home/mallory" "$root/proc/4242"
  cat >"$root/home/mallory/php-fpm8.3" <<EOF2
#!/bin/sh
# X-Powered-By: PHP/8.3.1
touch "$root/MARKER"
printf 'PHP 9.9.9 (cli)\n'
EOF2
  chmod 755 "$root/home/mallory/php-fpm8.3"
  fixture_owner "$root" "/home/mallory/php-fpm8.3" 1000
  ln -s "/home/mallory/php-fpm8.3" "$root/proc/4242/exe"
  mkdir -p "$root/usr/local/bin"
  cat >"$root/usr/local/bin/php" <<EOF2
#!/bin/sh
# X-Powered-By: PHP/8.2.11
touch "$root/MARKER2"
printf 'PHP 9.9.9 (cli)\n'
EOF2
  chmod 775 "$root/usr/local/bin/php"
  run_tool --json --test-root "$root"
  [[ ! -e "$root/MARKER" ]] && pass "c2 proc exe not run" || fail "c2 proc exe not run"
  [[ ! -e "$root/MARKER2" ]] && pass "c2 group-writable not run" || fail "c2 group-writable not run"
  assert_eq "c2 static version from user binary" "$(finding 8.3.1 fpm | cut -f1)" "VULNERABLE"
  assert_eq "c2 static version from writable binary" "$(finding 8.2.11 cli | cut -f1)" "VULNERABLE"
fi

host_log_after="absent"
if [[ -e "$host_log" ]]; then
  host_log_after=$(cksum "$host_log" | awk '{print $1, $2}')
fi
if [[ "$host_log_before" == "$host_log_after" ]]; then
  pass "host log untouched"
else
  fail "host log changed"
fi

if [[ "$FAILS" -eq 0 ]]; then
  printf 'ALL PASS\n'
  exit 0
fi
printf '%s FAILED\n' "$FAILS" >&2
exit 1
