#!/usr/bin/env bash

# Inspired by http://mywiki.wooledge.org/BashFAQ/045

failure_code=$1
lockdir=$2
shift 2

if mkdir "$lockdir" > /dev/null 2>&1
then
    echo >&2 "successfully acquired lock (${lockdir})"

    # Unlock (by removing dir) when the script finishes
    trap 'echo >&2 "relinquishing lock (${lockdir})"; rm -rf "$lockdir"' EXIT

    # Execute command
    "$@"
else
    echo >&2 "failed to acquire lock (${lockdir})"
    exit $failure_code
fi
