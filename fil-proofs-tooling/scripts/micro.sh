#!/usr/bin/env bash

MICRO_SDERR=$(mktemp)
MICRO_SDOUT=$(mktemp)
JQ_STDERR=$(mktemp)

CMD="cargo run --bin micro --release ${@}"

eval "RUST_BACKTRACE=1 RUSTFLAGS=\"-Awarnings -C target-cpu=native\" ${CMD}" 1> $MICRO_SDOUT 2> $MICRO_SDERR

MICRO_EXIT_CODE=$?

cat $MICRO_SDOUT | jq '.' 2> $JQ_STDERR

JQ_EXIT_CODE=$?

if [[ ! $MICRO_EXIT_CODE -eq 0 || ! $JQ_EXIT_CODE -eq 0 ]]; then
    >&2 echo "********************************************"
    >&2 echo "* micro failed - dumping debug information *"
    >&2 echo "********************************************"
    >&2 echo ""
    >&2 echo "<COMMAND>"
    >&2 echo "${CMD}"
    >&2 echo "</COMMAND>"
    >&2 echo ""
    >&2 echo "<MICRO_SDERR>"
    >&2 echo "$(cat $MICRO_SDERR)"
    >&2 echo "</MICRO_SDERR>"
    >&2 echo ""
    >&2 echo "<MICRO_SDOUT>"
    >&2 echo "$(cat $MICRO_SDOUT)"
    >&2 echo "</MICRO_SDOUT>"
    >&2 echo ""
    >&2 echo "<JQ_STDERR>"
    >&2 echo "$(cat $JQ_STDERR)"
    >&2 echo "</JQ_STDERR>"
    exit 1
fi
