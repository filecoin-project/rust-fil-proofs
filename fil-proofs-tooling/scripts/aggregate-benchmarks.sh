#!/usr/bin/env bash

set -e

zigzag_path=$1
micro_path=$2
hash_constraints_path=$3

jq --sort-keys -s '{ benchmarks: { "zigzag-benchmarks": { outputs: { "max-resident-set-size-kb": .[0] } } } } * .[1]' \
  <(jq '.["max-resident-set-size-kb"]' $zigzag_path) \
  <(jq -s '.[0] * { benchmarks: { "hash-constraints": .[1], "zigzag-benchmarks": .[2], "micro-benchmarks": .[3] } }' \
    <(jq 'del (.benchmarks)' $micro_path) \
    <(jq '.benchmarks' $hash_constraints_path) \
    <(jq '.benchmarks' $zigzag_path) \
    <(jq '.benchmarks' $micro_path))
