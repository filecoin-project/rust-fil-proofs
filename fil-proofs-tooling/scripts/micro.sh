#!/usr/bin/env bash

RUSTFLAGS="-Awarnings -C target-cpu=native"
cargo run --quiet --bin micro --release ${@}
