#!/usr/bin/env bash
# Variant r-retries2: lower net.ipv4.tcp_retries2 in R's network namespace (docker exec cannot: /proc/sys is read-only there, so the
# colima VM's nsenter is used; in a real deployment use compose `sysctls:` or the host's sysctl.d). Run after the topology is up.
set -eu
PID=$(docker inspect -f '{{.State.Pid}}' an-wg-r)
colima ssh -- sudo nsenter -t "$PID" -n sysctl -w net.ipv4.tcp_retries2="${1:-6}"
