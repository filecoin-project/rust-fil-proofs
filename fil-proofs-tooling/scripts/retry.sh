#!/usr/bin/env bash

# Inspired by https://gist.github.com/reacocard/28611bfaa2395072119464521d48729a

set -o errexit
set -o nounset
set -o pipefail

# Retry a command on a particular exit code, up to a max number of attempts,
# with exponential backoff.
# Invocation:
#   err_retry exit_code attempts sleep_multiplier <command>
# exit_code: The exit code to retry on.
# attempts: The number of attempts to make.
# sleep_millis: Multiplier for sleep between attempts. Examples:
#     If multiplier is 1000, sleep intervals are 1, 4, 9, 16, etc. seconds.
#     If multiplier is 5000, sleep intervals are 5, 20, 45, 80, 125, etc. seconds.

exit_code=$1
attempts=$2
sleep_millis=$3
shift 3

for attempt in `seq 1 $attempts`; do
    # This weird construction lets us capture return codes under -o errexit
    "$@" && rc=$? || rc=$?

    if [[ ! $rc -eq $exit_code ]]; then
        exit $rc
    fi

    if [[ $attempt -eq $attempts ]]; then
        exit $rc
    fi

    sleep_ms="$(($attempt * $attempt * $sleep_millis))"

    sleep_seconds=$(echo "scale=2; ${sleep_ms}/1000" | bc)

    (>&2 echo "sleeping ${sleep_seconds}s and then retrying ($((attempt + 1))/${attempts})")

    sleep "${sleep_seconds}"
done
