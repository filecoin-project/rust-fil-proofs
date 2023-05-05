#!/bin/sh
set -eu
#set -o xtrace


# Usage help if nothing is piped in.
if [ -t 0 ]; then
    cat << EOF
Usage: echo '{}' | $(basename "${0}")

Perform a PreCommit 1 and PreCommit 2 for a single sector.

It prints to stdout the result CommR formatted as JSON, e.g.
{"comm_r":"0x9dabeaa4e2b53153152ac485c6b8ede4d750be12d0fae4fa265161dc0ff5502a"}

The input parameters are given by piping in JSON with the following keys:
 - output_dir: The directory where all files (layers as well as trees) are stored.
 - porep_id: The PoRep ID formatted in hex with leading 0x.
 - replica_id: The Replica ID formatted in hex with leading 0x.
 - sector_size: The size of the sector in bytes.

Example JSON:
{
  "output_dir": "/path/to/some/dir",
  "porep_id": "0x0500000000000000000000000000000000000000000000000000000000000000",
  "replica_id": "0xd93f7c0618c236179361de2164ce34ffaf26ecf3be7bf7e6b8f0cfcf886ad0d0",
  "sector_size: "2048"
}
EOF
     exit 1
fi


# Define default options for commands
CARGO="${CARGO:=cargo run --release}"
JQ='jq -r'
JO='jo --'

export FIL_PROOFS_USE_MULTICORE_SDR=1
export FIL_PROOFS_USE_GPU_COLUMN_BUILDER=1
export FIL_PROOFS_USE_GPU_TREE_BUILDER=1
export FIL_PROOFS_VERIFY_CACHE=1
export RUST_LOG=trace


# Make sure all tools we need for this scripts are installed.
if ! command -v jq > /dev/null
then
    echo "'jq' not found." && exit 2
fi
if ! command -v jo > /dev/null
then
    echo "'jo' not found." && exit 3
fi


# Parse the input data.
read -r input_args
output_dir=$(echo "${input_args}" | ${JQ} '.output_dir')
porep_id=$(echo "${input_args}" | ${JQ} '.porep_id')
replica_id=$(echo "${input_args}" | ${JQ} '.replica_id')
sector_size=$(echo "${input_args}" | ${JQ} '.sector_size')

if [ "${output_dir}" = 'null' ]; then
    echo "'output_dir' not set." && exit 4
fi
if [ "${porep_id}" = 'null' ]; then
    echo "'porep_id' not set." && exit 5
fi
if [ "${replica_id}" = 'null' ]; then
    echo "'replica_id' not set." && exit 6
fi
if [ "${sector_size}" = 'null' ]; then
    echo "'sector_size' not set." && exit 8
fi


# Get the default values for the given sector size.
default_values=$(jo sector_size="${sector_size}" | ${CARGO} --bin default-values)
>&2 echo "Default values: ${default_values}"
num_layers=$(echo "${default_values}" | ${JQ} '.num_layers')


# Run SDR.
mkdir -p "${output_dir}"
sdr=$(${JO} num_layers="${num_layers}" output_dir="${output_dir}" -s porep_id="${porep_id}" -s replica_id="${replica_id}" sector_size="${sector_size}" | ${CARGO} --bin sdr)
>&2 echo "SDR: ${sdr}"


# Tree building for the coloumn commitment.
tree_c=$(${JO} input_dir="${output_dir}" num_layers="${num_layers}" output_dir="${output_dir}" sector_size="${sector_size}" | ${CARGO} --bin tree-c)
>&2 echo "TreeC: ${tree_c}"
comm_c=$(echo "${tree_c}" | ${JQ} '.comm_c')


# The sector key is the last layer of the SDR process.
sector_key_path="${output_dir}/sc-02-data-layer-${num_layers}.dat"


# Tree building for the replica commitment.
tree_r_last=$(${JO} output_dir="${output_dir}" replica_path="${sector_key_path}" sector_size="${sector_size}" | ${CARGO} --bin tree-r-last)
>&2 echo "TreeRLast: ${tree_r_last}"
comm_r_last=$(echo "${tree_r_last}" | ${JQ} '.comm_r_last')


# Calculate the resulting CommR
comm_r=$(${JO} -s comm_c="${comm_c}" -s comm_r_last="${comm_r_last}" | ${CARGO} --bin comm-r)
>&2 echo "CommR: ${comm_r}"
echo "${comm_r}"
