# Proofs for Filecoin in Rust

This code base implements the Filecoin proofs and circuits (currently only Proof-of-Replication).

## Overview of the code base

### `drgporep`
We refer to `drgporep` as the Proof-of-Replication following [Fisch2018](https://eprint.iacr.org/2018/678.pdf) construction based on Depth Robust Graphs

**Main code**
- `src/drgporep.rs`: implements `Setup`, `Replicate`, `Prove`, `Verify`
- `src/circuit/drgporep.rs`: implements the `Verify` algorithm as an arithmetic circuit. This implements both circuit generation and witness generation.


### `merklepor`
We refer to `merklepor` as the Proof-of-Retrievable-Commitment following [Fisch2018](https://eprint.iacr.org/2018/678.pdf) construction based on Merkle Trees. This implementation is an equivalent of multiple Merkle Tree inclusion proofs.

- `src/merklepor.rs`: implements `Setup`, `Replicate`, `Prove`, `Verify`
- `src/circuit/merklepor.rs`: implements the `Verify` algorithm as an arithmetic circuit. This implements both circuit generation and witness generation.

### Subcomponents

We list here all the relevant subcomponents in our code base:

- `src/porep.rs`: General interface for Proofs of Replication
- `src/vde.rs`: Verifiable Delay Encoding following [Fisch2018](https://eprint.iacr.org/2018/678.pdf) construction based on Depth Robust Graphs.
- `src/fr32.rs`: Utils for converting Fr elements in 32 bytes and viceversa
- `src/crypto/pedersen.rs`: Pedersen hashes over JubJub and BLS12-381
- `src/crypto/sloth.rs`: Slow Hash function used during key derivation


## Install and configure Rust

[Install Rust.](https://www.rust-lang.org/en-US/install.html)

Configure to use nightly:

```
> rustup default nightly
```

## Build

```
> cargo build --release --features u128-support
```

## Test

```
> cargo test
```


## Examples

Build

```
> cargo build --examples --release --features u128-support
```

Running them

```
> ./target/release/examples/merklepor
> ./target/release/examples/drgporep
```
