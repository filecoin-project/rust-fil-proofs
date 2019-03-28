#!/usr/bin/env bash

TAR_PATH=/tmp/release
TAR_FILE=/tmp/release.tar.gz

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
