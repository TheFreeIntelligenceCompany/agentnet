#!/usr/bin/env bash
# Run ON the box: box-fw.sh MODE <mac tailnet ip>
#   du-allow | du-block   rules in DOCKER-USER (filter) - the "obvious" place for a docker-published port
#   raw-allow | raw-block | raw-clear   rules in the raw table PREROUTING (before conntrack/nat and before tailscale's ts-forward)
#   show
# tcp/60000 (R's libp2p port) on the box's tailnet IPv4: accepted only from the Mac's tailnet IPv4, from the box itself and from
# node B (172.28.66.22, the only other container); dropped otherwise.
set -euo pipefail
ACT="$1"; MAC="${2:-}"; SELF="$(sudo tailscale ip -4)"; R=172.28.66.10; C=an-ts
del() { while sudo iptables "$@" 2>/dev/null; do :; done; }
clean_du() { for s in "$MAC" "$SELF"; do for j in ACCEPT DROP; do del -D DOCKER-USER -s "$s" -d $R -p tcp --dport 60000 -m comment --comment $C -j $j; done; done
             del -D DOCKER-USER -d $R -p tcp --dport 60000 -m comment --comment $C -j DROP; }
clean_raw() { for s in "$MAC" "$SELF" 172.28.66.22; do for j in ACCEPT DROP; do del -t raw -D PREROUTING -s "$s" -d "$SELF" -p tcp --dport 60000 -m comment --comment $C -j $j; done; done
              del -t raw -D PREROUTING -d "$SELF" -p tcp --dport 60000 -m comment --comment $C -j DROP; }
case "$ACT" in
  du-allow|du-block)
    clean_du; V=ACCEPT; [ "$ACT" = du-block ] && V=DROP
    sudo iptables -I DOCKER-USER 1 -d $R -p tcp --dport 60000 -m comment --comment $C -j DROP
    sudo iptables -I DOCKER-USER 1 -s "$SELF" -d $R -p tcp --dport 60000 -m comment --comment $C -j ACCEPT
    sudo iptables -I DOCKER-USER 1 -s "$MAC" -d $R -p tcp --dport 60000 -m comment --comment $C -j $V
    date -u +%FT%T.%3NZ ;;
  raw-allow|raw-block)
    clean_raw; V=ACCEPT; [ "$ACT" = raw-block ] && V=DROP
    sudo iptables -t raw -I PREROUTING 1 -d "$SELF" -p tcp --dport 60000 -m comment --comment $C -j DROP
    sudo iptables -t raw -I PREROUTING 1 -s 172.28.66.22 -d "$SELF" -p tcp --dport 60000 -m comment --comment $C -j ACCEPT
    sudo iptables -t raw -I PREROUTING 1 -s "$SELF" -d "$SELF" -p tcp --dport 60000 -m comment --comment $C -j ACCEPT
    sudo iptables -t raw -I PREROUTING 1 -s "$MAC" -d "$SELF" -p tcp --dport 60000 -m comment --comment $C -j $V
    date -u +%FT%T.%3NZ ;;
  raw-clear) clean_raw; clean_du ;;
  show) sudo iptables -t raw -L PREROUTING -nvx --line-numbers; sudo iptables -L DOCKER-USER -nvx --line-numbers; sudo iptables -L FORWARD -nvx --line-numbers ;;
esac
