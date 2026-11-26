# Small tools image shared by the network simulations (spike/relay-wireguard, spike/relay-nat).
# Built locally as an-net-tools:local. Contains NO keys. Used for: WireGuard sidecars, NAT gateways,
# the key-less intruder, packet capture. SIMULATION TOOLING ONLY.
FROM alpine:3.20
RUN apk add --no-cache wireguard-tools iptables ip6tables conntrack-tools tcpdump iproute2 curl netcat-openbsd bind-tools busybox-extras jq
