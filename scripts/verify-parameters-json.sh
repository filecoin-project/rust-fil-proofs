#!/bin/sh

# This script verifies that a given `.params` file (and the corresponding
# `.vk` file) is part of `parameters.json` and has the correct digest.
#
# This script runs on POSIX compatible shells. You need to have standard
# utilities (`basename`, `head`, `grep`) as well as have `jq` and `b2sum`
# installed.
#
# The inputs are a `parameter.json` file and a `.params' file.

if [ "${#}" -ne 2 ]; then
    echo "Verify that a given .params file (and the corresponding .vk file)"
    echo "is part of parameters.json and has the correct digest."
    echo ""
    echo "Usage: $(basename "${0}") parameters.json parameter-file.params"
    exit 1
fi

if ! command -v b2sum >/dev/null 2>&1
then
    echo "ERROR: 'b2sum' needs to be installed."
    exit 1
fi

if ! command -v jq >/dev/null 2>&1
then
    echo "ERROR: 'jq' needs to be installed."
    exit 1
fi

PARAMS_JSON=${1}
PARAMS_ID="${2%.*}"

PARAMS_FILE="${PARAMS_ID}.params"
VK_FILE="${PARAMS_ID}.vk"

# Transforms the `parameters.json` into a string that consists of digest and
# filename pairs.
PARAMS_JSON_DATA=$(jq -r 'to_entries[] | "\(.value.digest) \(.key)"' "${PARAMS_JSON}")

VK_HASH_SHORT=$(b2sum "${VK_FILE}"|head --bytes 32)
if echo "${PARAMS_JSON_DATA}"|grep --silent "${VK_HASH_SHORT} ${VK_FILE}"; then
    echo "ok Correct digest of VK file was found in ${PARAMS_JSON}."
else
    echo "not ok ERROR: Digest of VK file was *not* found/correct in ${PARAMS_JSON}."
    exit 1
fi

PARAMS_HASH_SHORT=$(b2sum "${PARAMS_FILE}"|head --bytes 32)
if echo "${PARAMS_JSON_DATA}"|grep --silent "${PARAMS_HASH_SHORT} ${PARAMS_FILE}"; then
    echo "ok Correct digest of params file was found in ${PARAMS_JSON}."
else
    echo "not ok ERROR: Digest of params file was *not* found/correct in ${PARAMS_JSON}."
    exit 1
fi

echo "# Verification successfully completed."
