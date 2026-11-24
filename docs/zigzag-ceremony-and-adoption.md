# ZigZag trusted setup, FIP, and ecosystem adoption

**Status:** checklist for deployability. None of this is implemented in-tree yet; it is the
external work required after Phases 1–3 land and security parameters are finalized.

## 1. Trusted setup (MPC ceremony)

ZigZag Groth16 circuits are **not** compatible with Stacked parameters (distinct
`cache_prefix`: `zigzag-proof-of-replication-{tree}-{piece_hasher}`).

Required:

1. Powers-of-Tau (or reuse Filecoin's existing phase-1 transcript if the circuit fits the
   supported degree).
2. Circuit-specific phase-2 MPC for each `(sector_size, partitions)` configuration, using the
   finalized challenge/layer counts from [zigzag-security-params.md](zigzag-security-params.md).
3. Publish `.params` / `.vk` files and digests in `parameters.json` for `paramfetch`.
4. Document that **dev params** from a well-known seed (if generated via a helper binary) have
   derivable toxic waste and must never be used on mainnet.

Local/dev generation remains available via `paramcache --only-zigzag` (uses `OsRng`; not
reproducible across machines, not ceremony-grade).

## 2. Protocol registration (FIP)

- Allocate an official `porep_id` / `RegisteredSealProof` variant range for ZigZag.
- Define on-chain commitment layout:
  - `comm_d`: standard Sha256 CommD (already compatible).
  - `comm_r` on chain: either `comm_r_star` alone, or `zigzag_comm_r_bound(comm_r, comm_r_star)`
    (`H(comm_r || comm_r_star)` — implemented in `filecoin_proofs::zigzag_comm_r_bound`).
- Specify interactive challenge seed (ticket) binding — API already accepts `seed: Option<Ticket>`.
- Register PoSt variants per [zigzag-post-strategy.md](zigzag-post-strategy.md) (binary FallbackPoSt).

## 3. Runtime wiring

| Component | Work |
|-----------|------|
| `filecoin-ffi` | Expose `zigzag_pre_commit_phase1/2`, `zigzag_prove`, `zigzag_verify_seal`, `zigzag_unseal_range`. |
| Builtin actors | Accept ZigZag `RegisteredSealProof`; verify with ZigZag VK. |
| Lotus / Venus | Miner seal pipeline selects ZigZag path; paramfetch pulls ZigZag params. |
| `paramfetch` / `parameters.json` | Digests for all ZigZag seal (and PoSt) param files. |

## 4. External audit

Scope at minimum:

- Ported vanilla scheme vs 2019 reference (`zigzag-reference/`).
- SHA256 KDF substitution (original Blake2s).
- Poseidon `comm_r_star` via `hash_md` (original Pedersen).
- Sha256 `comm_d` openings in circuit (layer 0 only).
- Challenge derivation with optional chain seed.
- Fast-extraction asymmetry (decode order-independence).

## Ordering

```text
security params → ceremony → parameters.json → FIP merge → FFI/actors/Lotus → mainnet
```

Do not run the ceremony until security parameters and the PoSt strategy are frozen.
