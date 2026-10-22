#!/bin/sh
# Build and run the hermetic suite on the distros in the test plan.
# This script needs a working Docker daemon. It does not deploy anything.
set -eu
root=$(CDPATH='' cd -- "$(dirname "$0")/../.." && pwd)
cd "$root"
for image in ubuntu:22.04 ubuntu:24.04 debian:12 almalinux:9 alpine:3.20; do
  tag=$(printf '%s' "$image" | tr ':/' '--')
  docker build \
    -f tests/docker/Dockerfile \
    --build-arg BASE_IMAGE="$image" \
    -t "stacutis-php2shell-test:${tag}" \
    "$root"
  docker run --rm "stacutis-php2shell-test:${tag}"
done
