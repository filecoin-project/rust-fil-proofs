#!/usr/bin/env bash

# Inspired by http://mywiki.wooledge.org/BashFAQ/045

failure_code=$1
lockdir=$2
shift 2

# Check to make sure that the process which owns the lock, if one exists, is
# still alive. If the process is not alive, release the lock.
for lockdir_pid in $(find "$lockdir" -type f -exec basename {} \; 2> /dev/null)
do
    if ! ps -p "${lockdir_pid}" > /dev/null
    then
        (>&2 echo "cleaning up leaked lock (pid=${lockdir_pid}, path=${lockdir})")
        rm -rf "${lockdir}"
    fi
done

if mkdir "$lockdir" > /dev/null 2>&1
then
    (>&2 echo "successfully acquired lock (pid=$$, path=${lockdir})")

    # Create a file to track the process id that acquired the lock. This
    # is used to prevent leaks if the lock isn't relinquished correctly.
    touch "$lockdir/$$"

    # Unlock (by removing dir and pid file) when the script finishes.
    trap '(>&2 echo "relinquishing lock (${lockdir})"); rm -rf "$lockdir"' EXIT

    # Execute command
    "$@"
else
    (>&2 echo "failed to acquire lock (path=${lockdir})")
    exit "$failure_code"
fi
