# Filecoin Proving Subsystem (Only for FPGA test)

The **Filecoin Proving Subsystem** (or FPS) provides the storage proofs required by the Filecoin protocol. It is implemented entirely in Rust, as a series of partially inter-dependent crates – some of which export C bindings to the supported API.

There are currently several different crates:

- [**Storage Proofs (`storage-proofs`)**](./storage-proofs)
    A library for constructing storage proofs – including non-circuit proofs, corresponding SNARK circuits, and a method of combining them.

- [**Storage Proofs Core (`storage-proofs-core`)**](./storage-proofs/core)
    A set of common primitives used throughout the other storage-proofs sub-crates, including crypto, merkle tree, hashing and gadget interfaces.

- [**Storage Proofs PoRep (`storage-proofs-porep`)**](./storage-proofs/porep)
    `storage-proofs-porep` is intended to serve as a reference implementation for _**Proof-of-Replication**_ (**PoRep**), while also performing the heavy lifting for `filecoin-proofs`.

- [**Storage Proofs PoSt (`storage-proofs-post`)**](./storage-proofs/post)
    `storage-proofs-post` is intended to serve as a reference implementation for _**Proof-of-Space-time**_ (**PoSt**), for `filecoin-proofs`.

- [**Filecoin Proofs (`filecoin-proofs`)**](./filecoin-proofs)
  A wrapper around `storage-proofs`, providing an FFI-exported API callable from C (and in practice called by [lotus](https://github.com/filecoin-project/lotus) via cgo). Filecoin-specific values of setup parameters are included here.

## Install and configure Rust

**NOTE:** If you have installed `rust-fil-proofs` incidentally, as a submodule of `lotus`, then you may already have installed Rust.

The instructions below assume you have independently installed `rust-fil-proofs` in order to test, develop, or experiment with it.

[Install Rust using rustup.](https://www.rust-lang.org/en-US/install.html)


# Build

**NOTE:** `rust-fil-proofs` can only be built for and run on 64-bit platforms; building will panic if the target architecture is not 64-bits.

Before building you will need OpenCL to be installed, on Ubuntu this can be achieved with `apt install ocl-icd-opencl-dev`.  Other system dependencies such as 'gcc/clang', 'wall' and 'cmake' are also required.

```
> cargo build --release --all
```

## Test

```
> cargo test --all
```

## Benchmarks

some examples are below:
```
> cd rust-fil-proofs/sha2raw
> cargo bench compress256_benchmark
打印出测试信息如下：
compress256_benchmark/128                                                                           
                        time:   [288.39 ns 288.56 ns 288.91 ns]
                        thrpt:  [422.51 MiB/s 423.03 MiB/s 423.28 MiB/s]
                 change:
                        time:   [-0.2461% -0.1467% -0.0359%] (p = 0.02 < 0.05)
                        thrpt:  [+0.0359% +0.1469% +0.2467%]
                        Change within noise threshold.
compress256_benchmark/256                                                                           
                        time:   [293.42 ns 294.04 ns 294.67 ns]
                        thrpt:  [828.52 MiB/s 830.31 MiB/s 832.04 MiB/s]
                 change:
                        time:   [-6.1492% -2.1345% +0.2229%] (p = 0.37 > 0.05)
                        thrpt:  [-0.2224% +2.1811% +6.5521%]
                        No change in performance detected.
Found 1 outliers among 10 measurements (10.00%)
  1 (10.00%) high mild
compress256_benchmark/1024000                                                                           
                        time:   [292.62 ns 292.89 ns 293.51 ns]
                        thrpt:  [3249.2 GiB/s 3256.0 GiB/s 3259.1 GiB/s]
                 change:
                        time:   [-0.0685% +0.1092% +0.2875%] (p = 0.28 > 0.05)
                        thrpt:  [-0.2866% -0.1091% +0.0685%]
                        No change in performance detected.
Found 1 outliers among 10 measurements (10.00%)
  1 (10.00%) high mild
```
Note：安装完rust环境之后，初次编译的时候会下载很多依赖包，使用默认的国外源会比较慢，可以修改一下本地的源。
```
> vim ~/.cargo/config
输入：
[source.crates-io]
registry = "https://github.com/rust-lang/crates.io-index"
replace-with = 'ustc'
[source.ustc]
registry = "https://mirrors.ustc.edu.cn/crates.io-index"
```

## Logging

For better logging with backtraces on errors, developers should use `expects` rather than `expect` on `Result<T, E>` and `Option<T>`.

The crate use [`log`](https://crates.io/crates/log) for logging, which by default does not log at all. In order to log output crates like [`fil_logger`](https://crates.io/crates/fil_logger) can be used.

For example

```rust
fn main() {
    fil_logger::init();
}
```

and then when running the code setting

```sh
> RUST_LOG=filecoin_proofs=info
```

will enable all logging.

For advanced/verbose/debug logging, you can use the code setting

```sh
> RUST_LOG=trace
```

Note that if you modify this value and seal sectors using it, it CANNOT be modified without updating all previously sealed sectors (or alternatively, discarding all previously sealed sectors).  A tool is provided for this conversion, but it's considered an expensive operation and should be carefully planned and completed before restarting any nodes with the new setting.  The reason for this is because all 'tree_r_last' trees must be rebuilt from the sealed replica file(s) with the new target value of FIL_PROOFS_ROWS_TO_DISCARD in order to make sure that the system is consistent.

Adjusting this setting is NOT recommended unless you understand the implications of modification.

## Generate Documentation

Now, generate the documentation:

```
> cargo doc --all --no-deps
```

View the docs by pointing your browser at: `…/rust-fil-proofs/target/doc/proofs/index.html`.

---

## Building for Arm64

In order to build for arm64 the current requirements are

- nightly rust compiler

Example for building `filecoin-proofs`

```
$ rustup +nightly target add aarch64-unknown-linux-gnu
$ cargo +nightly build -p filecoin-proofs --release --target aarch64-unknown-linux-gnu
```

## License

The Filecoin Project is dual-licensed under Apache 2.0 and MIT terms:

- Apache License, Version 2.0, ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)
