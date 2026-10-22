# Hermetic test image. It does not install a distro PHP package: repository
# versions move, and the assertions live in tests/run-hermetic.sh against
# fixture binaries. ARG BASE_IMAGE is one of ubuntu:22.04, ubuntu:24.04,
# debian:12, almalinux:9, alpine:3.20.
ARG BASE_IMAGE=debian:12
FROM ${BASE_IMAGE}

# The scanner needs bash. python3 is only for the test runner's JSON checks.
# Alpine's first package set is bash plus python3, on top of BusyBox.
RUN if command -v apk >/dev/null 2>&1; then \
      apk add --no-cache bash python3; \
    elif command -v apt-get >/dev/null 2>&1; then \
      apt-get update \
      && apt-get install -y --no-install-recommends bash python3 ca-certificates \
      && rm -rf /var/lib/apt/lists/*; \
    elif command -v dnf >/dev/null 2>&1; then \
      dnf install -y bash python3 \
      && dnf clean all; \
    else \
      echo "unsupported base image" >&2; \
      exit 1; \
    fi

WORKDIR /src
COPY stacutis-php2shell.sh /src/stacutis-php2shell.sh
COPY tests /src/tests
CMD ["bash", "tests/run-hermetic.sh"]
