#!/usr/bin/env bash

trap cleanup EXIT

cleanup() {
  kill $DOT_PID
}

(
  sleep 1
  while true; do
    (printf "." >&2)
    sleep 1
  done
) &
DOT_PID=$!

$@
