#!/usr/bin/env bash

set -Eeuo pipefail

if [ -z "$1" ]; then
  TAR_FILE=`mktemp`.tar.gz
else
  TAR_FILE=$1
fi

TAR_PATH=`mktemp -d`

mkdir -p $TAR_PATH
mkdir -p $TAR_PATH/bin
mkdir -p $TAR_PATH/misc

cp filecoin-proofs/parameters.json $TAR_PATH/misc/
cp target/release/paramcache $TAR_PATH/bin/
cp target/release/paramfetch $TAR_PATH/bin/

pushd $TAR_PATH

tar -czf $TAR_FILE ./*

popd

rm -rf $TAR_PATH

echo $TAR_FILE
