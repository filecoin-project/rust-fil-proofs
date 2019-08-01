#!/usr/bin/env bash

stat ./target/release/benchy >/dev/null || { printf '%s\n' "error: missing ./target/release/benchy" >&2; exit 1; }

BENCHY_OUT=$(mktemp)
TIME_OUT=$(mktemp)

BIN="time"
CMD="-f '{ \"outputs\": { \"maxResidentSetSizeKb\": %M } }' ./target/release/benchy zigzag --size=1024 > ${BENCHY_OUT} 2> ${TIME_OUT}"

if [[ $(env time --version 2>&1) != *"GNU"* ]]; then
    if [[ $(env gtime --version 2>&1) != *"GNU"* ]]; then
        printf '%s\n' "error: GNU time not installed" >&2
        exit 1
    else
        BIN="gtime"
    fi
fi

eval "${BIN} ${CMD}"

jq -s '.[0] * .[1]' "${BENCHY_OUT}" "${TIME_OUT}"
