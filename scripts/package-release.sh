#!/usr/bin/env bash

if [ -z "$1" ]; then
  TAR_FILE=`mktemp`.tar.gz
else
  TAR_FILE=$1
fi

TAR_PATH=`mktemp -d`

mkdir -p $TAR_PATH
mkdir -p $TAR_PATH/bin
mkdir -p $TAR_PATH/include
mkdir -p $TAR_PATH/lib/pkgconfig
mkdir -p $TAR_PATH/misc

cp parameters.json $TAR_PATH/misc/
cp target/release/paramcache $TAR_PATH/bin/
cp target/release/paramfetch $TAR_PATH/bin/
cp target/release/libfilecoin_proofs.h $TAR_PATH/include/
cp target/release/libfilecoin_proofs.a $TAR_PATH/lib/
cp target/release/libfilecoin_proofs.pc $TAR_PATH/lib/pkgconfig

pushd $TAR_PATH

tar -czf $TAR_FILE ./*

popd

rm -rf $TAR_PATH

echo $TAR_FILE
