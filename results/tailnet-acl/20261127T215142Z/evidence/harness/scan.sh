#!/bin/bash
# scan.sh TARGET : tcp connect scan with 30 parallel probes, 2 s timeout; 60000 is included as a sentinel (must be open) at several positions
echo "scan start $(date -u +%T) target=$1"
(seq 1 500; echo 60000; seq 501 1024; echo 60000; seq 8000 8100; echo 60000; seq 18600 18700; seq 58400 58500; echo 60000; seq 59990 60010) | xargs -P 30 -I{} sh -c "nc -z -w 2 $1 {} >/dev/null 2>&1 && echo open {}" | sort -n | uniq -c
echo "scan done $(date -u +%T)"
