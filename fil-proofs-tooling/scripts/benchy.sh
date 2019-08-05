#!/usr/bin/env bash

which jq >/dev/null || { printf '%s\n' "error: jq" >&2; exit 1; }

BENCHY_OUT=$(mktemp)
TIME_OUT=$(mktemp)

BIN="env time"
CMD="-f '{ \"outputs\": { \"maxResidentSetSizeKb\": %M } }' cargo run --bin benchy --release -- ${@} > ${BENCHY_OUT} 2> ${TIME_OUT}"

if [[ $(env time --version 2>&1) != *"GNU"* ]]; then
    if [[ $(/usr/bin/time --version 2>&1) != *"GNU"* ]]; then
        if [[ $(env gtime --version 2>&1) != *"GNU"* ]]; then
            printf '%s\n' "error: GNU time not installed" >&2
            exit 1
        else
            BIN="gtime"
        fi
    else
        BIN="/usr/bin/time"
    fi
fi

eval "${BIN} ${CMD}"

jq -s '.[0] * .[1]' "${BENCHY_OUT}" "${TIME_OUT}"
