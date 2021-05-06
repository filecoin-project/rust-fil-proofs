# Changelog

All notable changes to rust-fil-proofs will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://book.async.rs/overview/stability-guarantees.html).

## Unreleased

## [7.0.1] - 2021-05-06

- Added Apple M1 asm support via updated sha2 dependency [#1457](https://github.com/filecoin-project/rust-fil-proofs/pull/1457)
- Remove additional build warnings and update CI nightly toolchain [#1456](https://github.com/filecoin-project/rust-fil-proofs/pull/1456)
- Fix aarch64/Linux build regression [#1455](https://github.com/filecoin-project/rust-fil-proofs/pull/1455)
- Fix changelog errors and typos [#1451](https://github.com/filecoin-project/rust-fil-proofs/pull/1451)
- Fix initial value for cache_count [#1454](https://github.com/filecoin-project/rust-fil-proofs/pull/1454)

## [7.0.0] - 2021-04-28

- Split up non-gpu tests for improved CI [#1448](https://github.com/filecoin-project/rust-fil-proofs/pull/1448)
- Use latest version of dialoguer [#1447](https://github.com/filecoin-project/rust-fil-proofs/pull/1447)
- Fix circuitinfo's binary name [#1443](https://github.com/filecoin-project/rust-fil-proofs/pull/1443)
- Remove deprecated calls and clean-up warnings; add parallelization [#1436](https://github.com/filecoin-project/rust-fil-proofs/pull/1436)
- Migrate gpu2 to default gpu code; Update rust toolchain to 1.51.0 [#1441](https://github.com/filecoin-project/rust-fil-proofs/pull/1441)
- Improve unsealing memory performance [#1401](https://github.com/filecoin-project/rust-fil-proofs/pull/1401)
- Update codeowners to current [#1432](https://github.com/filecoin-project/rust-fil-proofs/pull/1432)
- Update config.json for the benches [#1431](https://github.com/filecoin-project/rust-fil-proofs/pull/1431)

## [6.1.0] - 2021-03-09

- Update bellperson to the latest version [#1430](https://github.com/filecoin-project/rust-fil-proofs/pull/1430)
- Remove unused metrics capture CI job [#1428](https://github.com/filecoin-project/rust-fil-proofs/pull/1428)
- Split up pc1/pc2 in the Window PoSt bench [#1427](https://github.com/filecoin-project/rust-fil-proofs/pull/1427)
- Use `compress,asm` features of sha2 for aarch64 [#1404](https://github.com/filecoin-project/rust-fil-proofs/pull/1404)
- Add gpu2, an optional feature that uses `neptune`'s opencl backend [#1397](https://github.com/filecoin-project/rust-fil-proofs/pull/1397)
- Clean-up imports and remove globs [#1394](https://github.com/filecoin-project/rust-fil-proofs/pull/1394)
- Remove `storage-proofs` sub-crate [#1393](https://github.com/filecoin-project/rust-fil-proofs/pull/1393)
- Re-factor parameter related binaries [#1392](https://github.com/filecoin-project/rust-fil-proofs/pull/1392)
- Fix merkle bench for poseidon hashing [#1389](https://github.com/filecoin-project/rust-fil-proofs/pull/1389)
- Move `phase2` code into its own crate [#1388](https://github.com/filecoin-project/rust-fil-proofs/pull/1388)
- Move `fr32` into its own crate [#1387](https://github.com/filecoin-project/rust-fil-proofs/pull/1387)
- Ensure that builds without gpu support work [#1386](https://github.com/filecoin-project/rust-fil-proofs/pull/1386)
- Increase parallelism in fallback PoSt [#1384](https://github.com/filecoin-project/rust-fil-proofs/pull/1384)
- Move checkout_cores test behing a single-threaded feature [#1383](https://github.com/filecoin-project/rust-fil-proofs/pull/1383)
- Improve the cache preservation in Window PoSt bench [#1382](https://github.com/filecoin-project/rust-fil-proofs/pull/1382)
- Correct some typos in the Changelog [#1381](https://github.com/filecoin-project/rust-fil-proofs/pull/1381)

## [6.0.0] - 2020-12-01

- Add PoR gadget that does not add a public input [#1374](https://github.com/filecoin-project/rust-fil-proofs/pull/1374)
- Update README and fix some typos [#1377](https://github.com/filecoin-project/rust-fil-proofs/pull/1377)
- Update bellperson using new blstrs, which in turn now uses`blst@0.3.2` [#1376](https://github.com/filecoin-project/rust-fil-proofs/pull/1376)
- Fix tree_c and tree_r_last generation in GPU mode [#1375](https://github.com/filecoin-project/rust-fil-proofs/pull/1375)
- Add API version enum for determining runtime behaviour [#1362](https://github.com/filecoin-project/rust-fil-proofs/pull/1362)
- Parallelize CI test runs across packages [#1358](https://github.com/filecoin-project/rust-fil-proofs/pull/1358)
- Update paramcache run for metrics capture CI job [#1363](https://github.com/filecoin-project/rust-fil-proofs/pull/1363)
- Re-organize filecoin-proofs source [#1352](https://github.com/filecoin-project/rust-fil-proofs/pull/1352)
- Move hashers into `filecoin-hashers` crate [#1356](https://github.com/filecoin-project/rust-fil-proofs/pull/1356)
- Speed up Fr32Reader [#1341](https://github.com/filecoin-project/rust-fil-proofs/pull/1341)
- Serialize GPU tree building with GPU lock [#1335](https://github.com/filecoin-project/rust-fil-proofs/pull/1335)
- Disable `phase2` tests that require external files [#1342](https://github.com/filecoin-project/rust-fil-proofs/pull/1342)
- Move `phase2` into its own crate [#1340](https://github.com/filecoin-project/rust-fil-proofs/pull/1340)
- Raise soft fdlimit to max at runtime (OS X/Linux) [#1338](https://github.com/filecoin-project/rust-fil-proofs/pull/1338)
- Improve clippy lints (rust 2018 idioms) [#1337](https://github.com/filecoin-project/rust-fil-proofs/pull/1337)

## [5.4.0] - 2020-11-02

- Fix graph generation [#1336](https://github.com/filecoin-project/rust-fil-proofs/pull/1336)

## [5.3.0] - 2020-10-29

- Integrate blst backend and proof verification optimizations [#1332](https://github.com/filecoin-project/rust-fil-proofs/pull/1332)
- Remove unused pedersen hasher [#1331](https://github.com/filecoin-project/rust-fil-proofs/pull/1331)
- Sanity check commitments [#1330](https://github.com/filecoin-project/rust-fil-proofs/pull/1330)
- Install hwloc to fix metrics capture on CI [#1328](https://github.com/filecoin-project/rust-fil-proofs/pull/1328)
- Remove no longer used exports [#1315](https://github.com/filecoin-project/rust-fil-proofs/pull/1315)
- Add tests for resumable sealing [#1309](https://github.com/filecoin-project/rust-fil-proofs/pull/1309)
- Add circuitinfo CLI tool to count circuit constraints [#1325](https://github.com/filecoin-project/rust-fil-proofs/pull/1325)
- Remove mutex from settings access [#1321](https://github.com/filecoin-project/rust-fil-proofs/pull/1321)
- Add SECURITY.md [#1317](https://github.com/filecoin-project/rust-fil-proofs/pull/1317)
- Update hwloc dependency for CI [#1316](https://github.com/filecoin-project/rust-fil-proofs/pull/1316)

## [5.2.3] - 2020-10-13

- Update neptune dependency version

## [5.2.2] - 2020-10-13

- Add notes about param and cache verification [#1313](https://github.com/filecoin-project/rust-fil-proofs/pull/1313)
- Update incorrect log message [#1312](https://github.com/filecoin-project/rust-fil-proofs/pull/1312)
- Bind threads to cores in multicore SDR [#1305](https://github.com/filecoin-project/rust-fil-proofs/pull/1305)
- Add hwloc dependency to CI [#1307](https://github.com/filecoin-project/rust-fil-proofs/pull/1307)

## [5.2.1] - 2020-10-01

- Pin neptune to version 1.2.x [#1302](https://github.com/filecoin-project/rust-fil-proofs/pull/1302)
- Add correct sizes for metrics capture CI [#1301](https://github.com/filecoin-project/rust-fil-proofs/pull/1301)
- Ensure all PoSt code paths are tested [#1299](https://github.com/filecoin-project/rust-fil-proofs/pull/1299)
- Add byte_unit dep for handling benchy input sizes [#1297](https://github.com/filecoin-project/rust-fil-proofs/pull/1297)
- Implement prefetch macro for aarch64 [#1294](https://github.com/filecoin-project/rust-fil-proofs/pull/1294)

## [5.2.0] - 2020-09-28

- Add Seal resume by skipping existing layers [#1292](https://github.com/filecoin-project/rust-fil-proofs/pull/1292)
- Use two producers in all layers [#1296](https://github.com/filecoin-project/rust-fil-proofs/pull/1296)
- Re-export some methods that moved for api access [#1291](https://github.com/filecoin-project/rust-fil-proofs/pull/1291)
- Update rustc to 1.46.0 [#1290](https://github.com/filecoin-project/rust-fil-proofs/pull/1290)
- Optimize Phase 1 (Replication) [#1289](https://github.com/filecoin-project/rust-fil-proofs/pull/1289)
- Add Seal resume testing to the Window PoSt bench [#1288](https://github.com/filecoin-project/rust-fil-proofs/pull/1288)
- Add labeling test vectors [#1285](https://github.com/filecoin-project/rust-fil-proofs/pull/1285)
- Remove artificial requirement that sector count be 1 for single vanilla proof [#1283](https://github.com/filecoin-project/rust-fil-proofs/pull/1283)
- Add Parent Cache and parameter verification and settings to enable [#1265](https://github.com/filecoin-project/rust-fil-proofs/pull/1265)
- Improve SectorId logging [#1280](https://github.com/filecoin-project/rust-fil-proofs/pull/1280)
- Split up Window PoSt API into separate calls [#1278](https://github.com/filecoin-project/rust-fil-proofs/pull/1278)
- Destructure settings [#1273](https://github.com/filecoin-project/rust-fil-proofs/pull/1273)

## [5.1.4] - 2020-09-08

- Add FaultySectors error to Fallback PoSt [#1274](https://github.com/filecoin-project/rust-fil-proofs/pull/1274)

## [5.1.3] - 2020-09-07

- Make fil-blst usage in Window PoSt possible [#1272](https://github.com/filecoin-project/rust-fil-proofs/pull/1272)

## [5.1.2] - 2020-09-03

- Accelerate SNARK verification [#1271](https://github.com/filecoin-project/rust-fil-proofs/pull/1271)
- Decompress proofs in parallel [#1268](https://github.com/filecoin-project/rust-fil-proofs/pull/1268)
- Eliminate wasteful public-input conversions [#1267](https://github.com/filecoin-project/rust-fil-proofs/pull/1267)
- Remove usage of unwrap [#1260](https://github.com/filecoin-project/rust-fil-proofs/pull/1260)
- Pin params to the filecoin collab cluster [#1263](https://github.com/filecoin-project/rust-fil-proofs/pull/1263)

## [5.1.1] - 2020-08-12

- Only perform subgroup check on 'after' params [#1258](https://github.com/filecoin-project/rust-fil-proofs/pull/1258)

## [5.1.0] - 2020-08-12

- Add Phase2 cli verify raw g1 point command [#1256](https://github.com/filecoin-project/rust-fil-proofs/pull/1256)

## [5.0.0] - 2020-08-10

- Publish v28 parameters and update Changelog for release [#1254](https://github.com/filecoin-project/rust-fil-proofs/pull/1254)
- Fix benchmark examples in README [#1253](https://github.com/filecoin-project/rust-fil-proofs/pull/1253)
- Remove unused dependencies [#1124](https://github.com/filecoin-project/rust-fil-proofs/pull/1124) and [#1252](https://github.com/filecoin-project/rust-fil-proofs/pull/1252)
- Add script to validate parameter checksums in parameters.json [#1251](https://github.com/filecoin-project/rust-fil-proofs/pull/1251)
- phase2-cli force small-raw contributions [#1248](https://github.com/filecoin-project/rust-fil-proofs/pull/1248)
- phase2-cli parse command [#1247](https://github.com/filecoin-project/rust-fil-proofs/pull/1247)
- phase2-cli merge command [#1242](https://github.com/filecoin-project/rust-fil-proofs/pull/1242)
- phase2-cli paramgen and filename parsing [#1240](https://github.com/filecoin-project/rust-fil-proofs/pull/1240)
- Verify transitions from non-raw to raw parameters in phase2-cli [#1239](https://github.com/filecoin-project/rust-fil-proofs/pull/1239)
- Add a check parameter command that maps parameter files [#1238](https://github.com/filecoin-project/rust-fil-proofs/pull/1238)
- Add tool to split phase2 parameters [#1235](https://github.com/filecoin-project/rust-fil-proofs/pull/1235)

## [4.0.5] - 2020-07-28

- Include proofs and snark security audit documents, with updated references [#1233](https://github.com/filecoin-project/rust-fil-proofs/pull/1233)
- Remove `stacked` benchmark from benchy (broken) [#1229](https://github.com/filecoin-project/rust-fil-proofs/pull/1229)
- Update range for feistel tests [#1228](https://github.com/filecoin-project/rust-fil-proofs/pull/1228)
- Allow for compilation on aarch64 [#1204](https://github.com/filecoin-project/rust-fil-proofs/pull/1204)
- Implement `fauxrep2`: a testable fake replication API [#1218](https://github.com/filecoin-project/rust-fil-proofs/pull/1218)
- Fix CI `metrics_capture` jobs from consistently failing [#1215](https://github.com/filecoin-project/rust-fil-proofs/pull/1215)
- Correct `rows_to_discard` value during post [#1220](https://github.com/filecoin-project/rust-fil-proofs/pull/1220)

## [4.0.4] - 2020-07-15

- Default parent cache path to use FIL_PROOFS_CACHE_DIR if set [#1207](https://github.com/filecoin-project/rust-fil-proofs/pull/1207)
- Investigate CI metrics capture [#1212](https://github.com/filecoin-project/rust-fil-proofs/pull/1212) and [#1213](https://github.com/filecoin-project/rust-fil-proofs/pull/1213)
- Additional README updates and corrections [#1211](https://github.com/filecoin-project/rust-fil-proofs/pull/1211)
- Update README [#1208](https://github.com/filecoin-project/rust-fil-proofs/pull/1208)
- Swap buffers instead of memcpy in generate_labels [#1197](https://github.com/filecoin-project/rust-fil-proofs/pull/1197)
- Apply suggested security audit fixes [#1196](https://github.com/filecoin-project/rust-fil-proofs/pull/1196)
- Make pieces::Stack methods private [#1202](https://github.com/filecoin-project/rust-fil-proofs/pull/1202)
- Remove dead code [#1201](https://github.com/filecoin-project/rust-fil-proofs/pull/1201)
- Test feistel implementation is a valid permutation [#1193](https://github.com/filecoin-project/rust-fil-proofs/pull/1193)

## [4.0.3] - 2020-07-01

- Add fauxrep to API for fake sealing [#1194](https://github.com/filecoin-project/rust-fil-proofs/pull/1194)
- Streaming phase2 contribution and fast I/O [#1188](https://github.com/filecoin-project/rust-fil-proofs/pull/1188)
- Add omitted changelog updates [#1190](https://github.com/filecoin-project/rust-fil-proofs/pull/1190)

## [4.0.2] - 2020-06-25

- Allow parameters map to be accessible externally [#1186](https://github.com/filecoin-project/rust-fil-proofs/pull/1186)
- Extend update_tree_r_cache command with new features [#1175](https://github.com/filecoin-project/rust-fil-proofs/pull/1175)
- Add OpenCL to the build instructions [#1112](https://github.com/filecoin-project/rust-fil-proofs/pull/1112)
- Use file locking for cache generation [#1179](https://github.com/filecoin-project/rust-fil-proofs/pull/1179)
- Add logging to all public API functions [#1137](https://github.com/filecoin-project/rust-fil-proofs/pull/1137)
- Upgrade some dependencies [#1126](https://github.com/filecoin-project/rust-fil-proofs/pull/1126)
- Fix clippy warnings [#1147](https://github.com/filecoin-project/rust-fil-proofs/pull/1147)
- Partial caching for SDR [#1163](https://github.com/filecoin-project/rust-fil-proofs/pull/1163)
- Add tool to rebuild tree_r_last from a replica [#1170](https://github.com/filecoin-project/rust-fil-proofs/pull/1170)
- Verify consistent use of porep_id when sealing [#1167](https://github.com/filecoin-project/rust-fil-proofs/pull/1167)

## [4.0.1] - 2020-06-22

- This release is a hotfix that pinned dependencies to avoid a build break [#1182](https://github.com/filecoin-project/rust-fil-proofs/pull/1182)

## [4.0.0] - 2020-06-15

- Change default rows_to_discard for cached oct-trees [#1165](https://github.com/filecoin-project/rust-fil-proofs/pull/1165)
- Remove validate commit message [#1164](https://github.com/filecoin-project/rust-fil-proofs/pull/1164)
- Modularized window-post bench [#1162](https://github.com/filecoin-project/rust-fil-proofs/pull/1162)
- Updated reported PoSt constraints (in comments) [#1161](https://github.com/filecoin-project/rust-fil-proofs/pull/1161)

## [3.0.0] - 2020-06-08

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

## [2.0.0] - 2020-05-27

- Add a method 'unseal_range' to unseal a sector to a file descriptor
- Calculate required config count based on tree shape
- Update merkle tree cached tree usage (fixing an incorrect size usage)
- Replace merkle_light 'height' property usage with 'row_count'
- Update stacked bench usage of recent replica changes

## [1.0.0] - 2020-05-19

- Initial stable release

[Unreleased]: https://github.com/filecoin-project/rust-fil-proofs/compare/v7.0.1...HEAD
[7.0.1]: https://github.com/filecoin-project/rust-fil-proofs/tree/releases/v7.0.1
[7.0.0]: https://github.com/filecoin-project/rust-fil-proofs/tree/releases/v7.0.0
[6.1.0]: https://github.com/filecoin-project/rust-fil-proofs/tree/releases/v6.1.0
[6.0.0]: https://github.com/filecoin-project/rust-fil-proofs/tree/releases/v6.0.0
[5.4.0]: https://github.com/filecoin-project/rust-fil-proofs/tree/releases/v5.4.0
[5.3.0]: https://github.com/filecoin-project/rust-fil-proofs/tree/releases/v5.3.0
[5.2.3]: https://github.com/filecoin-project/rust-fil-proofs/tree/releases/v5.2.3
[5.2.2]: https://github.com/filecoin-project/rust-fil-proofs/tree/releases/v5.2.2
[5.2.1]: https://github.com/filecoin-project/rust-fil-proofs/tree/releases/v5.2.1
[5.2.0]: https://github.com/filecoin-project/rust-fil-proofs/tree/releases/v5.2.0
[5.1.4]: https://github.com/filecoin-project/rust-fil-proofs/tree/releases/v5.1.4
[5.1.3]: https://github.com/filecoin-project/rust-fil-proofs/tree/releases/v5.1.3
[5.1.2]: https://github.com/filecoin-project/rust-fil-proofs/tree/releases/v5.1.2
[5.1.1]: https://github.com/filecoin-project/rust-fil-proofs/tree/releases/v5.1.1
[5.1.0]: https://github.com/filecoin-project/rust-fil-proofs/tree/releases/v5.1.0
[5.0.0]: https://github.com/filecoin-project/rust-fil-proofs/tree/releases/v5.0.0
[4.0.5]: https://github.com/filecoin-project/rust-fil-proofs/tree/releases/v4.0.5
[4.0.4]: https://github.com/filecoin-project/rust-fil-proofs/tree/releases/v4.0.4
[4.0.3]: https://github.com/filecoin-project/rust-fil-proofs/tree/releases/v4.0.3
[4.0.2]: https://github.com/filecoin-project/rust-fil-proofs/tree/releases/v4.0.2
[4.0.1]: https://github.com/filecoin-project/rust-fil-proofs/tree/releases/v4.0.0
[3.0.0]: https://github.com/filecoin-project/rust-fil-proofs/tree/releases/v3.0.0
[2.0.0]: https://github.com/filecoin-project/rust-fil-proofs/tree/releases/v2.0.0
[1.0.0]: https://github.com/filecoin-project/rust-fil-proofs/tree/releases/v1.0.0
