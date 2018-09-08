# Filecoin Proofs

This crate contains the Filecoin specific aspects, including a C based FFI, to generate
and verify proofs.


## Examples

Build

```
> cargo build --examples --release --features u128-support
```

Running them

```
> ./target/release/examples/merklepor
> ./target/release/examples/drgporep
> ./target/release/examples/drgporep-vanilla
```

## License

MIT or Apache 2.0
