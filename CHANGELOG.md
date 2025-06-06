# Changelog

All notable changes to rust-fil-proofs will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://book.async.rs/overview/stability-guarantees.html).

## Unreleased

## [19.0.0] - 2025-05-26

- **BREAKING CHANGE:** Remove unused functions `clear_layer_data()` and `clear_caches` from the public API. The signatures of `clear_cache()` and `clear_synthetic_proofs()` have been updated to no longer be generic over the tree type. These functions are not used internally, so the removal and signature change helps clean up the public API. [#1771](https://github.com/filecoin-project/rust-fil-proofs/pull/1771)
- Fix compilation issues on aarch64 in the `fr32` crate. [#1772](https://github.com/filecoin-project/rust-fil-proofs/pull/1772)
- Upgrade the `hwloc` dependency in the `storage-proofs-porep` crate to ensure proper hardware locality support. [#1766](https://github.com/filecoin-project/rust-fil-proofs/pull/1766)
- Add seal regression testing support in the core module, improving our internal testing capabilities. [#1765](https://github.com/filecoin-project/rust-fil-proofs/pull/1765)

## [18.1.0] - 2024-06-18

- Change FIP92 min value to updated value [#1758](https://github.com/filecoin-project/rust-fil-proofs/pull/1758)

## [18.0.0] - 2024-05-17

- Expose an API suitable for NI-PoRep proof aggregation [#1757](https://github.com/filecoin-project/rust-fil-proofs/pull/1757)
- Increase NI-PoRep min challenges for test sectors [#1756](https://github.com/filecoin-project/rust-fil-proofs/pull/1756)
- Remove challenge seed from NI-PoRep SnarkPack transcript [#1755](https://github.com/filecoin-project/rust-fil-proofs/pull/1755)
- Remove repetitive words [#1753](https://github.com/filecoin-project/rust-fil-proofs/pull/1753)

## [17.0.0] - 2024-04-25

- Improve error handling for threaded verification errors [#1748](https://github.com/filecoin-project/rust-fil-proofs/pull/1748)
- Remove historical but unused PoSt code [#1744](https://github.com/filecoin-project/rust-fil-proofs/pull/1744)
- Separate published and supported sector sizes [#1747](https://github.com/filecoin-project/rust-fil-proofs/pull/1747)
- Misc re-factors [#1745](https://github.com/filecoin-project/rust-fil-proofs/pull/1745)
- Add API features flag to benchy [#1743](https://github.com/filecoin-project/rust-fil-proofs/pull/1743)
- Add NI-PoRep functionality with tests [#1734](https://github.com/filecoin-project/rust-fil-proofs/pull/1734)
- Use newer internal testing API [#1742](https://github.com/filecoin-project/rust-fil-proofs/pull/1742)
- Change rust version [#1741](https://github.com/filecoin-project/rust-fil-proofs/pull/1741)
- Add SuperSnaps functionality with tests [#1729](https://github.com/filecoin-project/rust-fil-proofs/pull/1729)
- Re-factor challenge type to enum [#1739](https://github.com/filecoin-project/rust-fil-proofs/pull/1739)
- Simplify testing of API features [#1740](https://github.com/filecoin-project/rust-fil-proofs/pull/1740)
- Re-factor layer retrieval [#1735](https://github.com/filecoin-project/rust-fil-proofs/pull/1735)
- Re-factor StackedCircuit API [#1732](https://github.com/filecoin-project/rust-fil-proofs/pull/1732)
- Re-factor challenges selection [#1731](https://github.com/filecoin-project/rust-fil-proofs/pull/1731)
- Remove optional internal API [#1733](https://github.com/filecoin-project/rust-fil-proofs/pull/1733)
- Re-factor SynthPoRep [#1720](https://github.com/filecoin-project/rust-fil-proofs/pull/1720)
- Fix typo in README [#1738](https://github.com/filecoin-project/rust-fil-proofs/pull/1738)

## [16.1.0] - 2023-11-08

- Update lifecycle upgrade 'big-tests' [#1737](https://github.com/filecoin-project/rust-fil-proofs/pull/1737)
- Add optional support for sealing without requiring t_aux [#1717](https://github.com/filecoin-project/rust-fil-proofs/pull/1717)
- Re-factor p_aux/t_aux handling [#1721](https://github.com/filecoin-project/rust-fil-proofs/pull/1721)
- Add a parameter id test [#1728](https://github.com/filecoin-project/rust-fil-proofs/pull/1728)
- Additional CI improvements [#1727](https://github.com/filecoin-project/rust-fil-proofs/pull/1727)
- Re-factor cache cleaning [#1723](https://github.com/filecoin-project/rust-fil-proofs/pull/1723)
- Re-factor rows to discard values [#1724](https://github.com/filecoin-project/rust-fil-proofs/pull/1724)
- CI improvements [#1726](https://github.com/filecoin-project/rust-fil-proofs/pull/1726)
- Re-factors and clean-ups [#1719](https://github.com/filecoin-project/rust-fil-proofs/pull/1719)
- Simplify a StoreConfig usage [#1716](https://github.com/filecoin-project/rust-fil-proofs/pull/1716)

## [16.0.0] - 2023-09-05

- Add optional support for SupraSeal C2 proving [#1709](https://github.com/filecoin-project/rust-fil-proofs/pull/1709)
- Add support and API for SyntheticPoRep [#1701](https://github.com/filecoin-project/rust-fil-proofs/pull/1701)
- Downgrade harmless warning to trace logging [#1714](https://github.com/filecoin-project/rust-fil-proofs/pull/1714)
- Use more efficient MultiProof reader [#1713](https://github.com/filecoin-project/rust-fil-proofs/pull/1713)

## [15.0.0] - 2023-06-30

- Add SyntheticPoRep audit results to repo [#1710](https://github.com/filecoin-project/rust-fil-proofs/pull/1710)
- Remove DRG PoRep (historical code; unused on mainnet) [#1684](https://github.com/filecoin-project/rust-fil-proofs/pull/1684)
- Document the TreeRLast tree generation [#1699](https://github.com/filecoin-project/rust-fil-proofs/pull/1699)
- Optimize add_piece method [#1707](https://github.com/filecoin-project/rust-fil-proofs/pull/1707)
- Refactor replicate_phase2 arguments [#1700](https://github.com/filecoin-project/rust-fil-proofs/pull/1700)
- Add public API to generate tree_r_last and tree_c [#1705](https://github.com/filecoin-project/rust-fil-proofs/pull/1705)
- Add method to decode a range from an updated sector [#1704](https://github.com/filecoin-project/rust-fil-proofs/pull/1704)
- Clarify h and h_select usage [#1696](https://github.com/filecoin-project/rust-fil-proofs/pull/1696)
- Add new from trait for PoseidonDomain [#1703](https://github.com/filecoin-project/rust-fil-proofs/pull/1703)
- Ensure that number of layers matches column arity [#1702](https://github.com/filecoin-project/rust-fil-proofs/pull/1702)
- Clean up some code and mutability usage [#1698](https://github.com/filecoin-project/rust-fil-proofs/pull/1698)
- Remove superfluous API generic [#1695](https://github.com/filecoin-project/rust-fil-proofs/pull/1695)
- copy_parents_data optimization using base parents only [#1660](https://github.com/filecoin-project/rust-fil-proofs/pull/1660)
- Update to the newest version of ff dependency [#1691](https://github.com/filecoin-project/rust-fil-proofs/pull/1691)
- Replace heim dep with sysinfo [#1694](https://github.com/filecoin-project/rust-fil-proofs/pull/1694)
- rustix dependency update [#1693](https://github.com/filecoin-project/rust-fil-proofs/pull/1693)
- TreeD size and rows to discard calculation fix [#1692](https://github.com/filecoin-project/rust-fil-proofs/pull/1692)
- Benchy fix for output results without git info [#1688](https://github.com/filecoin-project/rust-fil-proofs/pull/1688)
- Add parallel tasks to WindowPoSt bench [#1686](https://github.com/filecoin-project/rust-fil-proofs/pull/1686)
- Return last layer from Labels [#1685](https://github.com/filecoin-project/rust-fil-proofs/pull/1685)
- Support optional API features for ranges of API versions [#1683](https://github.com/filecoin-project/rust-fil-proofs/pull/1683)

## [14.0.0] - 2023-03-17

- Allow PC1 unreplicated data to be /dev/zero [#1681](https://github.com/filecoin-project/rust-fil-proofs/pull/1681)
- Add additional tests for faulty sector reporting [#1680](https://github.com/filecoin-project/rust-fil-proofs/pull/1680)
- Make builds on stable and aarch64 possible [#1679](https://github.com/filecoin-project/rust-fil-proofs/pull/1679)
- Fix the open grindability issue [#1661](https://github.com/filecoin-project/rust-fil-proofs/pull/1661)
- Add the v13 Cargo.lock file [#1673](https://github.com/filecoin-project/rust-fil-proofs/pull/1673)

## [13.0.0] - 2023-03-06

- Disable broken coverage job CI coverage job [#1669](https://github.com/filecoin-project/rust-fil-proofs/pull/1669)
- Update rust-toolchain to 1.67.1 [#1668](https://github.com/filecoin-project/rust-fil-proofs/pull/1668)
- Clean up tree definitions [#1655](https://github.com/filecoin-project/rust-fil-proofs/pull/1655)
- Introduce PoRepConfig::new_groth16() [#1635](https://github.com/filecoin-project/rust-fil-proofs/pull/1635)
- Fix broken links in README.md [#1649](https://github.com/filecoin-project/rust-fil-proofs/pull/1649)
- Update ec-gpu-gen [#1638](https://github.com/filecoin-project/rust-fil-proofs/pull/1638)
- Use current process binding to limit thread cores [#1633](https://github.com/filecoin-project/rust-fil-proofs/pull/1633)
- Ensure that WindowPoSt works on read-only files [#1630](https://github.com/filecoin-project/rust-fil-proofs/pull/1630)
- Added Tarpaulin Coverage [#1628](https://github.com/filecoin-project/rust-fil-proofs/pull/1628)
- Use memmap2 instead of mapr [#1624](https://github.com/filecoin-project/rust-fil-proofs/pull/1624)
- Update CircleCI to xcode 13.4.1 [#1625](https://github.com/filecoin-project/rust-fil-proofs/pull/1625)
- Update rust-toolchain to 1.62.0 [#1623](https://github.com/filecoin-project/rust-fil-proofs/pull/1623)

## [12.0.0] - 2022-08-04

- Add additional sector logging [#1610](https://github.com/filecoin-project/rust-fil-proofs/pull/1610)
- Make it possible bind to cores using multicore SDR if units > groups [#1588](https://github.com/filecoin-project/rust-fil-proofs/pull/1588)
- Update repo dependencies and forward port v11.x release updates [#1615](https://github.com/filecoin-project/rust-fil-proofs/pull/1615)
- Update rust-toolchain to 1.59.0 [#1607](https://github.com/filecoin-project/rust-fil-proofs/pull/1607)
- Correct comment in SDR code [#1603](https://github.com/filecoin-project/rust-fil-proofs/pull/1603)
- Remove unused dependencies [#1600](https://github.com/filecoin-project/rust-fil-proofs/pull/1600)
- CI: run storage-proofs-update tests [#1599](https://github.com/filecoin-project/rust-fil-proofs/pull/1599)
- CI: split GPU tree building test runs [#1594](https://github.com/filecoin-project/rust-fil-proofs/pull/1594)
- CI: improve tests on MacOS [#1597](https://github.com/filecoin-project/rust-fil-proofs/pull/1597)
- Remove unused dependencies from storage-proofs-update [#1593](https://github.com/filecoin-project/rust-fil-proofs/pull/1593)
- Add SectorUpdate Compount tests to ignored [#1592](https://github.com/filecoin-project/rust-fil-proofs/pull/1592)
- Update fil_logger due to failures [#1591](https://github.com/filecoin-project/rust-fil-proofs/pull/1591)
- Update CLI to properly use default values [#1590](https://github.com/filecoin-project/rust-fil-proofs/pull/1590)
- CI: run most tests on specified rust-toolchain [#1587](https://github.com/filecoin-project/rust-fil-proofs/pull/1587)
- CI: run no GPU tests in release mode [#1586](https://github.com/filecoin-project/rust-fil-proofs/pull/1586)
- CI: remove redundant test [#1585](https://github.com/filecoin-project/rust-fil-proofs/pull/1585)
- Update repo dependencies and cleanups [#1584](https://github.com/filecoin-project/rust-fil-proofs/pull/1584)
- Increase parallelism in Window PoSt [#1580](https://github.com/filecoin-project/rust-fil-proofs/pull/1580)
- CI: Use parameter cache on MacOS [#1583](https://github.com/filecoin-project/rust-fil-proofs/pull/1583)
- CI: Resolve timeout due to ipget issue [#1582](https://github.com/filecoin-project/rust-fil-proofs/pull/1582)
- Update rust-toolchain to 1.56.0 [#1576](https://github.com/filecoin-project/rust-fil-proofs/pull/1576)
- Extend winning_post bench to allow fake sealing [#1571](https://github.com/filecoin-project/rust-fil-proofs/pull/1571)
- Update byte-unit version [#1574](https://github.com/filecoin-project/rust-fil-proofs/pull/1574)
- Fix incorrect sector size in README [#1566](https://github.com/filecoin-project/rust-fil-proofs/pull/1566)
- Re-use method for parameter verification [#1567](https://github.com/filecoin-project/rust-fil-proofs/pull/1567)

## [11.1.1] - 2022-06-15

- Lock versions to the correct minor number [#1614](https://github.com/filecoin-project/rust-fil-proofs/pull/1614)

## [11.1.0] - 2022-06-13

- Updates for aggregate proof versioning support [#1612](https://github.com/filecoin-project/rust-fil-proofs/pull/1612)

## [11.0.2] - 2022-02-09

- Fix cache clearing by resetting the cache path first [#1563](https://github.com/filecoin-project/rust-fil-proofs/pull/1563)
- Test updates and clean-ups [#1562](https://github.com/filecoin-project/rust-fil-proofs/pull/1562)

## [11.0.1] - 2022-02-03

- NOTE: This release contains the SnapDeals related API and funtionality. The parameters referenced in the parameters.json are now mainnet ready.
- Update SnapDeal Production Parameters [#1559](https://github.com/filecoin-project/rust-fil-proofs/pull/1559)
- Add Poseidon version of SnapDeals (concept, not full impl) [#1547](https://github.com/filecoin-project/rust-fil-proofs/pull/1547)
- Fix empty sector update proof priority and add debugging [#1558](https://github.com/filecoin-project/rust-fil-proofs/pull/1558)
- Correctly set the cache path for empty sector update proofs [#1557](https://github.com/filecoin-project/rust-fil-proofs/pull/1557)
- Update project codeowners file [#1555](https://github.com/filecoin-project/rust-fil-proofs/pull/1555)
- Add releases dir with Cargo.lock files for future releases [#1554](https://github.com/filecoin-project/rust-fil-proofs/pull/1554)
- Make paramcache arguments mututally exclusive [#1552](https://github.com/filecoin-project/rust-fil-proofs/pull/1552)

## [11.0.0] - 2022-01-10

- NOTE: This release contains the SnapDeals related API and funtionality, however the parameters referenced in the parameters.json are NOT
mainnet ready and will be replaced in a future version.  This release is intended for testing SnapDeals only.
- Update paramcache to properly generate .meta files for Empty Sector Update parameters [#1551](https://github.com/filecoin-project/rust-fil-proofs/pull/1551)
- Add support for Empty Sector Update proofs (SnapDeal) [#1519](https://github.com/filecoin-project/rust-fil-proofs/pull/1519)
- Expose multicore sdr feature explicitly [#1510](https://github.com/filecoin-project/rust-fil-proofs/pull/1510)
- Reset multicore sdr consumer [#1535](https://github.com/filecoin-project/rust-fil-proofs/pull/1535)
- Update heim dep to current master branch [#1539](https://github.com/filecoin-project/rust-fil-proofs/pull/1539)

## [10.1.0] - 2021-10-25

- Allow window post proving on a single partition basis [#1526](https://github.com/filecoin-project/rust-fil-proofs/pull/1526)
- Update bellperson, neptune, and rust-toolchain [#1529](https://github.com/filecoin-project/rust-fil-proofs/pull/1529)
- Reduce verbose info logging [#1530](https://github.com/filecoin-project/rust-fil-proofs/pull/1530)
- Improve benchy by printing help when no command is given [#1527](https://github.com/filecoin-project/rust-fil-proofs/pull/1527)
- Fall back to CPU if GPU is not available [#1517](https://github.com/filecoin-project/rust-fil-proofs/pull/1517)
- remove FIL_PROOFS_CUDA_NVCC_ARGS env var [#1520](https://github.com/filecoin-project/rust-fil-proofs/pull/1520)
- Split GPU Tree builder CI jobs [#1518](https://github.com/filecoin-project/rust-fil-proofs/pull/1518)
- Use GPU Tree builder only for Poseidon hashes [#1515](https://github.com/filecoin-project/rust-fil-proofs/pull/1515)
- Run GPU Tree building tests on all CI tests [#1514](https://github.com/filecoin-project/rust-fil-proofs/pull/1514)

## [10.0.0] - 2021-09-30

- Integrate a variety of zk-SNARK proving related performance improvements. For details see [#220](https://github.com/filecoin-project/bellperson#220)
- Properly implement and document the CUDA feature [#1507](https://github.com/filecoin-project/rust-fil-proofs/pull/1507)
- Remove pairing dependency for circuit [#1509](https://github.com/filecoin-project/rust-fil-proofs/pull/1509)
- Warm up cache for window post verify bench [#1508](https://github.com/filecoin-project/rust-fil-proofs/pull/1508)
- Upgrade to dependencies supporting CUDA [#1504](https://github.com/filecoin-project/rust-fil-proofs/pull/1504)
- Use upstream group, ff and pairing dependencies [#1488](https://github.com/filecoin-project/rust-fil-proofs/pull/1488)

## [9.0.2] - 2021-09-07

- Use sync channels in PC2 [#1500](https://github.com/filecoin-project/rust-fil-proofs/pull/1500)
- Return error verifiying empty proof bytes [#1498](https://github.com/filecoin-project/rust-fil-proofs/pull/1498)
- Serialize parent's cache generation and access [#1496](https://github.com/filecoin-project/rust-fil-proofs/pull/1496)

## [9.0.1] - 2021-08-16

- Flush mutable mmap after data updates [#1493](https://github.com/filecoin-project/rust-fil-proofs/pull/1493)
- Revert usage of bitmask in multicore sdr [#1492](https://github.com/filecoin-project/rust-fil-proofs/pull/1492)

## [9.0.0] - 2021-08-12

- Correct usage of bitmask in multicore sdr (authored by @qy3u) [#1477](https://github.com/filecoin-project/rust-fil-proofs/pull/1477)
- Switch to yastl threadpool from rayon [#1483](https://github.com/filecoin-project/rust-fil-proofs/pull/1483)
- Swap out default bls-381 backend from pairing to blst [#1482](https://github.com/filecoin-project/rust-fil-proofs/pull/1482)
- Improve multicore sdr logging [#1485](https://github.com/filecoin-project/rust-fil-proofs/pull/1485)

## [8.0.3] - 2021-07-26

- Avoid duplicate generation of srs key caches [#1481](https://github.com/filecoin-project/rust-fil-proofs/pull/1481)
- Add an srs key loading bench and re-factor some tests [#1474](https://github.com/filecoin-project/rust-fil-proofs/pull/1474)

## [8.0.2] - 2021-06-17

- Use correct aggregate proof serialization format [#1475](https://github.com/filecoin-project/rust-fil-proofs/pull/1475)

## [8.0.1] - 2021-06-09

- Required SnarkPack Audit updates [#1470](https://github.com/filecoin-project/rust-fil-proofs/pull/1470)
- Allow hwloc to be optional, but enabled by default [#1468](https://github.com/filecoin-project/rust-fil-proofs/pull/1468)
- Improve Clippy on CI [#1465](https://github.com/filecoin-project/rust-fil-proofs/pull/1465)

## [8.0.0] - 2021-06-01

-  Add an API for Proof Aggregation [#1395](https://github.com/filecoin-project/rust-fil-proofs/pull/1395)
-  Enforce serde for PublicInputs [#1458](https://github.com/filecoin-project/rust-fil-proofs/pull/1458)

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

[Unreleased]: https://github.com/filecoin-project/rust-fil-proofs/compare/v18.1.0...HEAD
[18.1.0]: https://github.com/filecoin-project/rust-fil-proofs/tree/releases/v18.1.0
[18.0.0]: https://github.com/filecoin-project/rust-fil-proofs/tree/releases/v18.0.0
[17.0.0]: https://github.com/filecoin-project/rust-fil-proofs/tree/releases/v17.0.0
[16.1.0]: https://github.com/filecoin-project/rust-fil-proofs/tree/releases/v16.1.0
[16.0.0]: https://github.com/filecoin-project/rust-fil-proofs/tree/releases/v16.0.0
[15.0.0]: https://github.com/filecoin-project/rust-fil-proofs/tree/releases/v15.0.0
[14.0.0]: https://github.com/filecoin-project/rust-fil-proofs/tree/releases/v14.0.0
[13.0.0]: https://github.com/filecoin-project/rust-fil-proofs/tree/releases/v13.0.0
[12.0.0]: https://github.com/filecoin-project/rust-fil-proofs/tree/releases/v12.0.0
[11.1.1]: https://github.com/filecoin-project/rust-fil-proofs/tree/releases/v11.1.1
[11.1.0]: https://github.com/filecoin-project/rust-fil-proofs/tree/releases/v11.1.0
[11.0.2]: https://github.com/filecoin-project/rust-fil-proofs/tree/releases/v11.0.2
[11.0.1]: https://github.com/filecoin-project/rust-fil-proofs/tree/releases/v11.0.1
[11.0.0]: https://github.com/filecoin-project/rust-fil-proofs/tree/releases/v11.0.0
[10.1.0]: https://github.com/filecoin-project/rust-fil-proofs/tree/releases/v10.1.0
[10.0.0]: https://github.com/filecoin-project/rust-fil-proofs/tree/releases/v10.0.0
[9.0.2]: https://github.com/filecoin-project/rust-fil-proofs/tree/releases/v9.0.2
[9.0.1]: https://github.com/filecoin-project/rust-fil-proofs/tree/releases/v9.0.1
[9.0.0]: https://github.com/filecoin-project/rust-fil-proofs/tree/releases/v9.0.0
[8.0.3]: https://github.com/filecoin-project/rust-fil-proofs/tree/releases/v8.0.3
[8.0.2]: https://github.com/filecoin-project/rust-fil-proofs/tree/releases/v8.0.2
[8.0.1]: https://github.com/filecoin-project/rust-fil-proofs/tree/releases/v8.0.1
[8.0.0]: https://github.com/filecoin-project/rust-fil-proofs/tree/releases/v8.0.0
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
