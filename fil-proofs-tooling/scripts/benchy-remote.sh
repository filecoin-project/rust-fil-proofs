#!/usr/bin/env bash

set -e

CMDS=$(cat <<EOF
cd \$(mktemp -d)
git clone -q https://github.com/filecoin-project/rust-fil-proofs.git
cd rust-fil-proofs
git checkout -q master
./fil-proofs-tooling/scripts/benchy.sh ${@:2}
EOF
)

ssh -q $1 "$CMDS"
