#!/usr/bin/env bash
# Generate this run's DISPOSABLE secrets into ./.run (gitignored): WireGuard key pairs for r/a/b, libp2p nodekeys, wg configs, env file.
# Nothing here is ever committed; run.sh deletes the files in .run on exit unless KEEP_RUN=1.
set -euo pipefail
cd "$(dirname "$0")/.."
IMG=${TOOLS_IMG:-an-net-tools:local}
mkdir -p .run; chmod 700 .run
rm -f .run/*
wgk() { docker run --rm "$IMG" wg genkey; }
pub() { printf '%s' "$1" | docker run --rm -i "$IMG" wg pubkey; }
for m in r a b; do
  priv=$(wgk); echo "$priv" > ".run/$m.key"; pub "$priv" > ".run/$m.pub"; chmod 600 ".run/$m.key"
done
RK=$(cat .run/r.key); AK=$(cat .run/a.key); BK=$(cat .run/b.key)
RP=$(cat .run/r.pub); AP=$(cat .run/a.pub); BP=$(cat .run/b.pub)
cat > .run/wg-r.conf <<CFG
[Interface]
PrivateKey = $RK
ListenPort = 51820
[Peer]
PublicKey = $AP
AllowedIPs = 10.66.0.2/32
[Peer]
PublicKey = $BP
AllowedIPs = 10.66.0.3/32
CFG
cat > .run/wg-a.conf <<CFG
[Interface]
PrivateKey = $AK
[Peer]
PublicKey = $RP
AllowedIPs = 10.66.0.1/32
Endpoint = 172.29.70.10:51820
PersistentKeepalive = 25
CFG
cat > .run/wg-b.conf <<CFG
[Interface]
PrivateKey = $BK
[Peer]
PublicKey = $RP
AllowedIPs = 10.66.0.1/32
Endpoint = 172.29.70.10:51820
PersistentKeepalive = 25
CFG
chmod 600 .run/wg-*.conf
{
  echo "R_KEY=$(openssl rand -hex 32)"
  echo "A_KEY=$(openssl rand -hex 32)"
  echo "B_KEY=$(openssl rand -hex 32)"
  echo "I_KEY=$(openssl rand -hex 32)"
  echo "R_PEER_ID=pending"
} > .run/env
chmod 600 .run/env
echo "keys generated in $(pwd)/.run (gitignored)"
