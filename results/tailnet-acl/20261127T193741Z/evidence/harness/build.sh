#!/bin/bash
set -ex
sudo apt-get update -qq
sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -qq libssl-dev pkg-config clang libclang-dev python3-websockets tcpdump iptables
cd ~ && rm -rf an && git clone --depth 1 https://github.com/TheFreeIntelligenceCompany/agentnet an
git -C an rev-parse HEAD
cd an && cargo build --release --locked -p agentnet-cli
ls -la target/release/agentnet
echo BUILD_DONE
