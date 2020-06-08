# Changelog

All notable changes to rust-fil-proofs will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://book.async.rs/overview/stability-guarantees.html).

## Unreleased

## 3.0.0 - 2020-06-08

- Publish v27 parameters
- Allow tree_r_last to be built on the GPU
- Improve performance of building tree_c on the GPU
- Properly remove tree_c when no longer needed
- Update neptune dependency version
- Update circuit test constraints
- Update total challenge count and increase partitions
- Improve UX of paramcache
- Add porep_id to construct replica_id and graph seeds
- Include layer index before node when creating label preimage
- Circuit optimizations for oct/quad insertion

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
