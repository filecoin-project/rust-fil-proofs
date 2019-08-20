#!/usr/bin/env bash

set -e

CMDS=$(cat <<EOF
cd \$(mktemp -d)
git clone -q https://github.com/filecoin-project/rust-fil-proofs.git
cd rust-fil-proofs
git checkout -q feat/821-and-814-benchmark-improvements
./fil-proofs-tooling/scripts/retry.sh 42 10 60000 \
    ./fil-proofs-tooling/scripts/with-lock.sh 42 /tmp/benchmark \
    ./fil-proofs-tooling/scripts/micro.sh ${@:2}
EOF
)

ssh -q $1 "$CMDS"
