#!/usr/bin/env bash
# Fixture helpers for tests/run-hermetic.sh. Source this file. Do not run it
# against a live server. Every path it creates stays under the directory it
# returns.

fixture_new() {
  local root
  root=$(mktemp -d)
  mkdir -p "$root/fixture" "$root/etc" "$root/usr/bin" "$root/usr/sbin" \
    "$root/usr/share/doc" "$root/var/www/html" "$root/var/log"
  printf 'fixture\n' >"$root/fixture/IS_TEST_ROOT"
  printf 'apt\n' >"$root/fixture/package-manager"
  printf 'php8.3-fpm\n' >"$root/fixture/services"
  cat >"$root/etc/os-release" <<'EOF'
ID=ubuntu
VERSION_ID="22.04"
PRETTY_NAME="Ubuntu 22.04 fixture"
EOF
  : >"$root/fixture/installed.tsv"
  : >"$root/fixture/candidates.tsv"
  printf '%s\n' "$root"
}

fixture_php_bin() {
  local path=$1 ver=$2
  mkdir -p "$(dirname "$path")"
  cat >"$path" <<EOF
#!/bin/sh
printf '%s\n' "PHP ${ver} (cli) (built: Jan  1 2026 00:00:00) ( NTS )"
printf '%s\n' "Copyright (c) The PHP Group"
exit 0
EOF
  chmod 755 "$path"
}

fixture_add_pkg() {
  printf '%s\t%s\t%s\n' "$2" "$3" "$4" >>"$1/fixture/installed.tsv"
}

fixture_add_candidate() {
  printf '%s\t%s\n' "$2" "$3" >>"$1/fixture/candidates.tsv"
}

fixture_fpm_tree() {
  local root=$1 series=$2
  local base="$root/etc/php/${series}/fpm"
  mkdir -p "$base/conf.d" "$base/pool.d"
  if [[ ! -f "$base/php.ini" ]]; then
    cat >"$base/php.ini" <<'EOF'
session.upload_progress.enabled = On
memory_limit = 128M
post_max_size = 8M
upload_max_filesize = 2M
EOF
  fi
  if [[ ! -f "$base/pool.d/www.conf" ]]; then
    cat >"$base/pool.d/www.conf" <<'EOF'
[www]
user = www-data
pm = dynamic
pm.max_requests = 500

[extra]
user = www-data
pm.max_requests = 100
EOF
  fi
}

fixture_changelog() {
  local root=$1 pkg=$2
  mkdir -p "$root/fixture/changelogs"
  cat >"$root/fixture/changelogs/$pkg"
}

fixture_candidate_changelog() {
  local root=$1 pkg=$2
  mkdir -p "$root/fixture/candidate-changelogs"
  cat >"$root/fixture/candidate-changelogs/$pkg"
}
