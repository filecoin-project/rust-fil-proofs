#!/usr/bin/env bash

which jq >/dev/null || { printf '%s\n' "error: jq" >&2; exit 1; }

BENCHY_STDOUT=$(mktemp)
GTIME_STDERR=$(mktemp)
JQ_STDERR=$(mktemp)

GTIME_BIN="env time"
GTIME_ARG="-f '{ \"max-resident-set-size-kb\": %M }' cargo run --quiet --bin benchy --release -- ${@}"

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

CMD="${GTIME_BIN} ${GTIME_ARG}"

eval "RUST_BACKTRACE=1 RUSTFLAGS=\"-Awarnings -C target-cpu=native\" ${CMD}" > $BENCHY_STDOUT 2> $GTIME_STDERR

GTIME_EXIT_CODE=$?

jq -s '.[0] * .[1]' $BENCHY_STDOUT $GTIME_STDERR 2> $JQ_STDERR

JQ_EXIT_CODE=$?

if [[ ! $GTIME_EXIT_CODE -eq 0 || ! $JQ_EXIT_CODE -eq 0 ]]; then
    >&2 echo "*********************************************"
    >&2 echo "* benchy failed - dumping debug information *"
    >&2 echo "*********************************************"
    >&2 echo ""
    >&2 echo "<COMMAND>"
    >&2 echo "${CMD}"
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
    exit 1
fi
