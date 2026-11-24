# ZigZag security parameterization (placeholder analysis)

**Status:** provisional. Values currently borrowed from Stacked DRG (`LAYERS`,
`minimum_challenges`, `POREP_PARTITIONS`) carry **no ZigZag security argument**. A cryptographer
must derive ZigZag-specific parameters before any mainnet ceremony.

## What is borrowed today

| Parameter | Source | Current (test sizes / 32–64 GiB) |
|-----------|--------|----------------------------------|
| Layers | `LAYERS` map | 2 / 11 |
| Min challenges (interactive) | `minimum_challenges()` | 2 / 176 |
| Partitions | `POREP_PARTITIONS` | 1 / 10 |
| Challenges per partition cap | `ZIGZAG_MAX_CHALLENGES_PER_PARTITION` | 18 |
| Challenge schedule | `LayerChallenges::new_fixed` | fixed (tapered unused by API) |

## What must be derived for ZigZag

ZigZag differs from Stacked in ways that affect the security reduction:

1. **Graph reversal between layers** — depth-robustness arguments apply to each orientation;
   layer count and expansion degree interact with the Feistel expansion differently than Stacked's
   unidirectional labeling.
2. **Per-layer proofs** — every layer is challenged (Stacked proves columns across layers). Total
   challenge budget is `layers × challenges_per_layer × partitions`.
3. **`comm_r_star`** — vector commitment over all layer roots; soundness depends on the Poseidon
   `hash_md` fold (not Pedersen as in 2019).
4. **SHA256 KDF** — replaces the 2019 Blake2s KDF; treat as a random oracle in the analysis.
5. **Tapered challenges** — `LayerChallenges::Tapered` exists and is unit-tested. Tapering puts
   fewer challenges on early layers (including the expensive Sha256 `comm_d` openings on layer 0),
   which is both a security and a circuit-cost lever.

## Recommended analysis outputs

For each supported sector size, publish:

- `num_layers`
- `LayerChallenges` variant (fixed vs tapered, with taper parameters)
- `minimum_challenges` (interactive and, if supported, non-interactive)
- `partitions` / challenges per partition (must respect `ZIGZAG_MAX_CHALLENGES_PER_PARTITION`
  or a revised cap after constraint measurement)
- Soundness target (e.g. 2^{-128} or Filecoin's prevailing target)

Wire results into a ZigZag-specific map (e.g. `ZIGZAG_LAYERS`) rather than continuing to share
Stacked's `LAYERS`.

## Constraint-cost note (informs partition sizing)

Layer-0 data openings verify against a Sha256 binary tree (~50k constraints/level vs ~300 for
Poseidon). At depth 30 (32 GiB) that is ~1.5M constraints per layer-0 challenge. Tapered
schedules that minimize early-layer challenges reduce proving cost without changing the
replica-tree openings on later layers. Measure with:

```text
cargo test -p storage-proofs-porep zigzag_circuit_satisfied -- --nocapture
```

and scale by challenges × layers before freezing partition counts for the ceremony.
