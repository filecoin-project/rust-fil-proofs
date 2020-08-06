#!/bin/sh

# This script verifies that the conversion from the trusted setup phase2
# results to the published parameters is correct.
#
# It verifies that:
#
# - The `.vk` file is just an extract of the phase2 result, without further
#   modifications
# - The individual parts (`.params` and `.contribs`) are combined
#   byte-identical to the phase2 result
#
# This script runs on POSIX compatible shells. You need to have standard
# utilities (`basename`, `head`, `wc`) as well as `b2sum` installed.
#
# The input is a `.params` file.

if [ "${#}" -ne 1 ]; then
    echo "Verify that the conversion from the trusted setup phase2 results"
    echo "to the published parameters is correct. It verifies that:"
    echo " - The .vk file is just an extract of the phase2 result, without"
    echo "   further modifications"
    echo " - The individual parts (.params and .contribs) are combined"
    echo "   byte-identical to the phase2 result"
    echo ""
    echo "Usage: $(basename "${0}") parameter-file.params"
    exit 1
fi

if ! command -v b2sum >/dev/null 2>&1
then
    echo "ERROR: 'b2sum' needs to be installed."
    exit 1
fi

PARAMS_ID="${1%.*}"

PARAMS_FILE="${PARAMS_ID}.params"
VK_FILE="${PARAMS_ID}.vk"
CONTRIBS_FILE="${PARAMS_ID}.contribs"
INFO_FILE="${PARAMS_ID}.info"
PHASE2_FILE=$(cat "${INFO_FILE}")


# Verify that the .vk file is extracted from the trusted setup phase2 file

VK_SIZE=$(wc --bytes < "${VK_FILE}")
VK_HASH=$(b2sum "${VK_FILE}"|head --bytes 128)
# The hash of the vk data embedded in the trusted setup phase2 result
PHASE2_VK_HASH=$(head --bytes "${VK_SIZE}" "${PHASE2_FILE}"|b2sum|head --bytes 128)
if [ "${VK_HASH}" = "${PHASE2_VK_HASH}" ]; then
    echo "ok VK hashes match."
else
    echo "not ok ERROR: VK hashes do *not* match."
    exit 1
fi


# Verify that the trusted setup phase2 file can be re-assembled from its parts

# The .params file already contain the contents of the .vk file. We only need
# to combine .params and .contribs for verification.
COMBINED_HASH=$(cat "${PARAMS_FILE}" "${CONTRIBS_FILE}"|b2sum|head --bytes 128)
PHASE2_HASH=$(b2sum "${PHASE2_FILE}"|head --bytes 128)
if [ "${COMBINED_HASH}" = "${PHASE2_HASH}" ]; then
    echo "ok Combined file matches phase2 file ${PHASE2_FILE}."
else
    echo "not ok ERROR: Combined file and phase2 file ${PHASE2_FILE} do *not* match."
    exit 1
fi


echo "# Verification successfully completed."
