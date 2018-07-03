# Proofs for Filecoin in Rust

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
