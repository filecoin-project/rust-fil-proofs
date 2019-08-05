#!/usr/bin/env bash

set -e

CMDS=$(cat <<EOF
cd \$(mktemp -d)
git clone -q https://github.com/filecoin-project/rust-fil-proofs.git
cd rust-fil-proofs
git checkout -q master
RUSTFLAGS="-C target-cpu=native" /root/.cargo/bin/cargo build --release --all > /dev/null 2>&1
RUSTFLAGS="-C target-cpu=native" /root/.cargo/bin/cargo run --bin micro --release ${@:2} 2>/dev/null
EOF
)

ssh -q $1 "$CMDS"
