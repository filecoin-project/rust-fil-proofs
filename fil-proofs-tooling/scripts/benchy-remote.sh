#!/usr/bin/env bash

set -e

SEC_SINCE_EPOCH=$(date +'%s')
BENCHY_OUTPUT_FILE_NAME="benchy-${SEC_SINCE_EPOCH}.json"

ssh -q $1 <<EOF
cd \$(mktemp -d)
git clone -q https://github.com/filecoin-project/rust-fil-proofs.git
cd rust-fil-proofs
git checkout -q master
cargo build --quiet --release --all > /dev/null 2>&1
echo ""
echo "running benchy.sh ${@:2}"
echo ""
./fil-proofs-tooling/scripts/benchy.sh ${@:2} > "/var/tmp/${BENCHY_OUTPUT_FILE_NAME}"
EOF

scp -q $1:"/var/tmp/${BENCHY_OUTPUT_FILE_NAME}" "$(pwd)/${BENCHY_OUTPUT_FILE_NAME}"

echo "benchy results written to $(pwd)/${BENCHY_OUTPUT_FILE_NAME}"
