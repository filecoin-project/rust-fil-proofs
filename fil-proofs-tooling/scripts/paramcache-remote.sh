#!/usr/bin/env bash

set -e

CMDS=$(cat <<EOF
cd \$(mktemp -d)
git clone https://github.com/filecoin-project/rust-fil-proofs.git
cd rust-fil-proofs
git checkout -q $1
./fil-proofs-tooling/scripts/retry.sh 42 10 60000 \
    ./fil-proofs-tooling/scripts/with-lock.sh 42 /tmp/benchmark \
    ./fil-proofs-tooling/scripts/with-dots.sh \
    RUST_LOG=info cargo run --release --package filecoin-proofs --bin=paramcache -- ${@:3}
EOF
)

ssh -q $2 "$CMDS"
