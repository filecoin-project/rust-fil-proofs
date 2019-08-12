#!/usr/bin/env bash

MICRO_SDERR=$(mktemp)
MICRO_SDOUT=$(mktemp)
JQ_STDERR=$(mktemp)

CMD="cargo run --quiet --bin micro --release ${@}"

eval "RUSTFLAGS=\"-Awarnings -C target-cpu=native\" ${CMD}" 1> $MICRO_SDOUT 2> $MICRO_SDERR

cat $MICRO_SDOUT | jq '.' 2> $JQ_STDERR

if [[ ! $? -eq 0 ]]; then
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
fi
