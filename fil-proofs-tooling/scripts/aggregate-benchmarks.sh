#!/usr/bin/env bash

set -e

stacked_path=$1
micro_path=$2
hash_constraints_path=$3
rational_post_path=$4

jq --sort-keys -s '{ benchmarks: { "stacked-benchmarks": { outputs: { "max-resident-set-size-kb": .[0] } } } } * .[1]' \
  <(jq '.["max-resident-set-size-kb"]' $stacked_path) \
  <(jq -s '.[0] * { benchmarks: { "hash-constraints": .[1], "stacked-benchmarks": .[2], "micro-benchmarks": .[3], "rational-post-benchmarks": .[4] } }' \
    <(jq 'del (.benchmarks)' $micro_path) \
    <(jq '.benchmarks' $hash_constraints_path) \
    <(jq '.benchmarks' $stacked_path) \
    <(jq '.benchmarks' $micro_path) \
    <(jq '.benchmarks' $rational_post_path))
