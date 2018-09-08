# Proofs for Filecoin in Rust

This is a collection of crates, that implement the various aspects of generating proofs,
for Filecoin.

There are currently four different crates.

- [Filecoin Proofs](./filecoin-proofs)
- [Storage Proofs](./storage-proofs)
- [Sector Base](./sector-base)
- [Storage Backend](./storage-backend)


## Install and configure Rust

[Install Rust.](https://www.rust-lang.org/en-US/install.html)

Configure to use nightly:

```
> rustup default nightly
```

## Build

```
> cargo build --release --all
```

## Test

```
> cargo test --all
```


## License

MIT or Apache 2.0
