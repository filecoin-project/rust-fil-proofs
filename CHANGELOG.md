# Changelog

All notable changes to rust-fil-proofs will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://book.async.rs/overview/stability-guarantees.html).

## Unreleased

## 3.0.0 - 2020-06-08

- Publish v27 parameters: [#1158](https://github.com/filecoin-project/rust-fil-proofs/pull/1158)
- Update toolchain to rust stable: [#1149](https://github.com/filecoin-project/rust-fil-proofs/pull/1149)
- Allow tree_r_last to be built on the GPU: [#1138](https://github.com/filecoin-project/rust-fil-proofs/pull/1138)
  - Improve performance of building tree_c on the GPU
  - Properly remove tree_c when no longer needed
  - Update circuit test constraints
- Update neptune dependency version: [#1159](https://github.com/filecoin-project/rust-fil-proofs/pull/1159)
- Update total challenge count and increase partitions: [#1153](https://github.com/filecoin-project/rust-fil-proofs/pull/1153)
- Improve UX of paramcache: [#1152](https://github.com/filecoin-project/rust-fil-proofs/pull/1152)
- Add porep_id to construct replica_id and graph seeds: [#1144](https://github.com/filecoin-project/rust-fil-proofs/pull/1144)
- Include layer index before node when creating label preimage: [#1139](https://github.com/filecoin-project/rust-fil-proofs/pull/1139)
- Circuit optimizations for oct/quad insertion: [#1125](https://github.com/filecoin-project/rust-fil-proofs/pull/1125)

## 2.0.0 - 2020-05-27

- Add a method 'unseal_range' to unseal a sector to a file descriptor
- Calculate required config count based on tree shape
- Update merkle tree cached tree usage (fixing an incorrect size usage)
- Replace merkle_light 'height' property usage with 'row_count'
- Update stacked bench usage of recent replica changes

## 1.0.0 - 2020-05-19

- Initial stable release

[Unreleased]:
https://github.com/filecoin-project/rust-fil-proofs/compare/v3.0.0...HEAD
[3.0.0]: https://github.com/filecoin-project/rust-fil-proofs/tree/v3.0.0
[2.0.0]: https://github.com/filecoin-project/rust-fil-proofs/tree/v2.0.0
[1.0.0]: https://github.com/filecoin-project/rust-fil-proofs/tree/v1.0.0
