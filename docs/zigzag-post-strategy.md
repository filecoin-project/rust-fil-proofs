# ZigZag PoSt strategy decision

WindowPoSt / WinningPoSt must repeatedly prove possession of the sealed replica. ZigZag's
replica trees are binary Poseidon (`ZigZagTree = DefaultBinaryTree`), while production Stacked
PoSt circuits and parameters target octree LC shapes (`SectorShape*`).

## Options

### A. Binary-tree FallbackPoSt (recommended for ZigZag-native deployment)

- Reuse `FallbackPoSt<ZigZagTree>` generically over the final-layer replica tree.
- Requires:
  - Persisting the final replica tree as an LCTree/DiskTree under the seal cache (phase 3).
  - Generating and publishing **new** Winning/Window PoSt Groth16 parameters for the binary
    Poseidon shape at each supported sector size.
- Pros: no change to the ZigZag seal circuit; clean separation from Stacked params.
- Cons: extra ceremony surface; miners must fetch ZigZag-specific PoSt params.

### B. Octree final layer only

- Build only the **last** layer's replica tree in the standard Stacked octree shape so existing
  PoSt circuits/params apply unchanged.
- Inner ZigZag layers stay binary Poseidon.
- Requires a circuit change: last-layer inclusion proofs use octree `PoRCircuit` arity.
- Pros: reuses mainnet PoSt params and miner PoSt pipelines.
- Cons: couples ZigZag seal to Stacked tree shapes; complicates disk layout and the seal circuit.

## Decision

**Adopt option A (binary-tree FallbackPoSt)** for the initial ZigZag deployment.

Rationale:

1. Phase 3 already persists binary trees via `StoreConfig`; extending that to LCTree for the
   final layer is straightforward.
2. Keeping seal and PoSt shapes aligned avoids a one-off octree exception in the seal circuit.
3. ZigZag already has a distinct param namespace (`zigzag-proof-of-replication-*`); PoSt params
   follow the same pattern (`zigzag-winning-post-*` / `zigzag-window-post-*`).

Revisit option B only if ceremony cost for binary PoSt params is prohibitive relative to a
seal-circuit change.

## Follow-ups

- Add `cache_zigzag_post_params` to `paramcache`.
- Wire `zigzag_generate_window_post` / `zigzag_generate_winning_post` in `filecoin-proofs`.
- Register ZigZag PoSt variants alongside the seal `porep_id` in the FIP.
