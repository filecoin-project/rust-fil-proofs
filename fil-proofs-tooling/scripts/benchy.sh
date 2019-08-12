#!/usr/bin/env bash

which jq >/dev/null || { printf '%s\n' "error: jq" >&2; exit 1; }

BENCHY_STDOUT=$(mktemp)
GTIME_STDERR=$(mktemp)
JQ_STDERR=$(mktemp)

GTIME_BIN="env time"
CMD="-f '{ \"outputs\": { \"max-resident-set-size-kb\": %M } }' cargo run --quiet --bin benchy --release -- ${@} > ${BENCHY_STDOUT} 2> ${GTIME_STDERR}"

if [[ $(env time --version 2>&1) != *"GNU"* ]]; then
    if [[ $(/usr/bin/time --version 2>&1) != *"GNU"* ]]; then
        if [[ $(env gtime --version 2>&1) != *"GNU"* ]]; then
            printf '%s\n' "error: GNU time not installed" >&2
            exit 1
        else
            GTIME_BIN="gtime"
        fi
    else
        GTIME_BIN="/usr/bin/time"
    fi
fi

eval "RUSTFLAGS=\"-Awarnings -C target-cpu=native\" ${GTIME_BIN} ${CMD}"

jq -s '.[0] * .[1]' $BENCHY_STDOUT $GTIME_STDERR 2> $JQ_STDERR

if [[ ! $? -eq 0 ]]; then
    >&2 echo "*********************************************"
    >&2 echo "* benchy failed - dumping debug information *"
    >&2 echo "*********************************************"
    >&2 echo ""
    >&2 echo "<COMMAND>"
    >&2 echo "${GTIME_BIN} ${CMD}"
    >&2 echo "</COMMAND>"
    >&2 echo ""
    >&2 echo "<GTIME_STDERR>"
    >&2 echo "$(cat $GTIME_STDERR)"
    >&2 echo "</GTIME_STDERR>"
    >&2 echo ""
    >&2 echo "<BENCHY_STDOUT>"
    >&2 echo "$(cat $BENCHY_STDOUT)"
    >&2 echo "</BENCHY_STDOUT>"
    >&2 echo ""
    >&2 echo "<JQ_STDERR>"
    >&2 echo "$(cat $JQ_STDERR)"
    >&2 echo "</JQ_STDERR>"
fi
