# ZigZag reference sources (2019)

These files are the last pre-removal ZigZag PoRep implementation, extracted verbatim
from commit `64ece875` (parent of `48d17d47 "feat: replace ZigZag with Stacked DRG"`).

They are **reference only** and are intentionally NOT part of the Cargo workspace or
any crate `src/` tree, so they are never compiled. They exist to guide the faithful
re-implementation of ZigZag against the current codebase.

Layout:
- `storage-proofs/` - vanilla scheme sources (zigzag graph, layered drgporep, drgporep, challenge derivation, vde, porep trait)
- `circuit/` - SNARK circuit sources (zigzag, drgporep, kdf, sloth, constraint, variables)
- `tooling/` - the old `filecoin-proofs/examples/zigzag.rs` and `benchy/zigzag.rs`

Original toolchain: `nightly-2019-08-09`, deps `paired`/`fil-sapling-crypto`/`ff 0.4`/`failure`.
Do not attempt to compile these directly against the current tree.
