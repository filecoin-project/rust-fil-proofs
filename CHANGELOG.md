# Changelog

All notable changes to rust-fil-proofs will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://book.async.rs/overview/stability-guarantees.html).

## Unreleased

## 4.0.4 - 2020-07-15

- Default parent cache path to use FIL_PROOFS_CACHE_DIR if set [1207](https://github.com/filecoin-project/rust-fil-proofs/pull/1207)
- Investigate CI metrics capture [1212](https://github.com/filecoin-project/rust-fil-proofs/pull/1212) and [1213] (https://github.com/filecoin-project/rust-fil-proofs/pull/1213)
- Additional README updates and corrections [1211](https://github.com/filecoin-project/rust-fil-proofs/pull/1211)
- Update README [1208](https://github.com/filecoin-project/rust-fil-proofs/pull/1208)
- Swap buffers instead of memcpy in generate_labels [1197](https://github.com/filecoin-project/rust-fil-proofs/pull/1197)
- Apply suggested security audit fixes [1196](https://github.com/filecoin-project/rust-fil-proofs/pull/1196)
- Make pieces::Stack methods private [1202](https://github.com/filecoin-project/rust-fil-proofs/pull/1202)
- Remove dead code [1201](https://github.com/filecoin-project/rust-fil-proofs/pull/1201)
- Test feistel implementation is a valid permutation [1193](https://github.com/filecoin-project/rust-fil-proofs/pull/1193)

## 4.0.3 - 2020-07-01

- Add fauxrep to API for fake sealing [1194](https://github.com/filecoin-project/rust-fil-proofs/pull/1194)
- Streaming phase2 contribution and fast I/O [1188](https://github.com/filecoin-project/rust-fil-proofs/pull/1188)
- Add omitted changelog updates [1190](https://github.com/filecoin-project/rust-fil-proofs/pull/1190)

## 4.0.2 - 2020-06-25

- Allow parameters map to be accessible externally [1186](https://github.com/filecoin-project/rust-fil-proofs/pull/1186)
- Extend update_tree_r_cache command with new features [1175](https://github.com/filecoin-project/rust-fil-proofs/pull/1175)
- Add OpenCL to the build instructions [1112](https://github.com/filecoin-project/rust-fil-proofs/pull/1112)
- Use file locking for cache generation [1179](https://github.com/filecoin-project/rust-fil-proofs/pull/1179)
- Add logging to all public API functions [1137](https://github.com/filecoin-project/rust-fil-proofs/pull/1137)
- Upgrade some dependencies [1126](https://github.com/filecoin-project/rust-fil-proofs/pull/1126)
- Fix clippy warnings [1147](https://github.com/filecoin-project/rust-fil-proofs/pull/1147)
- Partial caching for SDR [1163](https://github.com/filecoin-project/rust-fil-proofs/pull/1163)
- Add tool to rebuild tree_r_last from a replica [1170](https://github.com/filecoin-project/rust-fil-proofs/pull/1170)
- Verify consistent use of porep_id when sealing [1167](https://github.com/filecoin-project/rust-fil-proofs/pull/1167)

## 4.0.1 - 2020-06-22

- This release is a hotfix that pinned dependencies to avoid a build break [1182](https://github.com/filecoin-project/rust-fil-proofs/pull/1182)

## 4.0.0 - 2020-06-15

- Change default rows_to_discard for cached oct-trees [1165](https://github.com/filecoin-project/rust-fil-proofs/pull/1165)
- Remove validate commit message [1164](https://github.com/filecoin-project/rust-fil-proofs/pull/1164)
- Modularized window-post bench [1162](https://github.com/filecoin-project/rust-fil-proofs/pull/1162)
- Updated reported PoSt constraints (in comments) [1161](https://github.com/filecoin-project/rust-fil-proofs/pull/1161)

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

[Unreleased]: https://github.com/filecoin-project/rust-fil-proofs/compare/v4.0.4...HEAD
[4.0.4]: https://github.com/filecoin-project/rust-fil-proofs/tree/releases/v4.0.4
[4.0.3]: https://github.com/filecoin-project/rust-fil-proofs/tree/releases/v4.0.3
[4.0.2]: https://github.com/filecoin-project/rust-fil-proofs/tree/releases/v4.0.2
[4.0.1]: https://github.com/filecoin-project/rust-fil-proofs/tree/releases/v4.0.0
[3.0.0]: https://github.com/filecoin-project/rust-fil-proofs/tree/releases/v3.0.0
[2.0.0]: https://github.com/filecoin-project/rust-fil-proofs/tree/releases/v2.0.0
[1.0.0]: https://github.com/filecoin-project/rust-fil-proofs/tree/releases/v1.0.0
