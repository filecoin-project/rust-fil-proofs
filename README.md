# Filecoin Proving Subsystem

The **Filecoin Proving Subsystem** (or FPS) provides the storage proofs required by the Filecoin protocol. It is implemented entirely in Rust, as a series of partially inter-dependent crates – some of which export C bindings to the supported API.

There are currently several different crates:

- [**Storage Proofs (`storage-proofs`)**](./storage-proofs)
    A library for constructing storage proofs – including non-circuit proofs, corresponding SNARK circuits, and a method of combining them.

- [**Storage Proofs Core (`storage-proofs-core`)**](./storage-proofs/core)
    A set of common primitives used throughout the other storage-proofs sub-crates, including crypto, merkle tree, hashing and gadget interfaces.

- [**Storage Proofs PoRep (`storage-proofs-porep`)**](./storage-proofs/porep)
    `storage-proofs-porep` is intended to serve as a reference implementation for _**Proof-of-Replication**_ (**PoRep**), while also performing the heavy lifting for `filecoin-proofs`.

    Primary Components:
     -   **PoR** (**_Proof-of-Retrievability_**: Merkle inclusion proof)
     -   **DrgPoRep** (_Depth Robust Graph_ **_Proof-of-Replication_**)
     -   **StackedDrgPoRep**

- [**Storage Proofs PoSt (`storage-proofs-post`)**](./storage-proofs/post)
    `storage-proofs-post` is intended to serve as a reference implementation for _**Proof-of-Space-time**_ (**PoSt**), for `filecoin-proofs`.

    Primary Components:
     -   **PoSt** (Proof-of-Spacetime)


- [**Filecoin Proofs (`filecoin-proofs`)**](./filecoin-proofs)
  A wrapper around `storage-proofs`, providing an FFI-exported API callable from C (and in practice called by [lotus](https://github.com/filecoin-project/lotus) via cgo). Filecoin-specific values of setup parameters are included here.

## Security Audits

The `rust-fil-proofs` proofs code and the [Filecoin Spec](https://bafybeidxw5vxjdwsun2zc2illagf43v6w5r5w63vg455h7vjesbyqssg64.ipfs.dweb.link/algorithms/sdr/) has undergone a [proofs security audit](audits/Sigma-Prime-Protocol-Labs-Filecoin-Proofs-Security-Review-v2.1.pdf) performed by [Sigma Prime](https://sigmaprime.io/) and been deemed free of *critical* or *major* security issues.  In addition to the security review, the document provides the summary of findings, vulnerability classifications, and recommended resolutions.  All known issues have been resolved to date in both the code and the specification.

`rust-fil-proofs` has also undergone a [SNARK proofs security audit performed by Dr. Jean-Philippe Aumasson and Antony Vennard](audits/protocolai-audit-20200728.pdf) and been deemed free of *critical* or *major* security issues.  In addition to the security analysis, the document provides the audit goals, methodology, functionality descriptions and finally observations on what could be improved.  All known issues have been resolved to date.

## Design Notes

Earlier in the design process, we considered implementing what has become the **FPS** in Go – as a wrapper around potentially multiple SNARK circuit libraries. We eventually decided to use [bellman](https://github.com/zkcrypto/bellman) – a library developed by Zcash, which supports efficient pedersen hashing inside of SNARKs. Having made that decision, it was natural and efficient to implement the entire subsystem in Rust. We considered the benefits (self-contained codebase, ability to rely on static typing across layers) and costs (developer ramp-up, sometimes unwieldiness of borrow-checker) as part of that larger decision and determined that the overall project benefits (in particular ability to build on Zcash’s work) outweighed the costs.

We also considered whether the **FPS** should be implemented as a standalone binary accessed from Filecoin nodes either as a single-invocation CLI or as a long-running daemon process. Bundling the **FPS** as an FFI dependency was chosen for both the simplicity of having a Filecoin node deliverable as a single monolithic binary, and for the (perceived) relative development simplicity of the API implementation.

If at any point it were to become clear that the FFI approach is irredeemably problematic, the option of moving to a standalone **FPS** remains. However, the majority of technical problems associated with calling from Go into Rust are now solved, even while allowing for a high degree of runtime configurability. Therefore, continuing down the same path we have already invested in, and have begun to reap rewards from, seems likely.

## Install and configure Rust

**NOTE:** If you have installed `rust-fil-proofs` incidentally, as a submodule of `lotus`, then you may already have installed Rust.

The instructions below assume you have independently installed `rust-fil-proofs` in order to test, develop, or experiment with it.

[Install Rust using rustup.](https://www.rust-lang.org/en-US/install.html)

## Build

**NOTE:** `rust-fil-proofs` can only be built for and run on 64-bit platforms; building will panic if the target architecture is not 64-bits.

Before building you will need OpenCL to be installed. On Ubuntu, this can be achieved with `apt install ocl-icd-opencl-dev`.  Other system dependencies such as 'gcc/clang', 'wall' and 'cmake' are also required.

You will also need to install the hwloc library. On Ubuntu, this can be achieved with `apt install hwloc libhwloc-dev`. For other platforms, please see the [hwloc-rs Prerequisites section](https://github.com/daschl/hwloc-rs).


```
> cargo build --release --all
```

## Test

```
> cargo test --all
```

## Benchmarks

The main benchmarking tool is called `benchy`.  `benchy` has several subcommands, including `merkleproofs`, `prodbench`, `winning_post` and `window_post`.  You can run them with various configuration options, but some examples are below:

```
> cargo run --release --bin benchy -- merkleproofs --size 2
> cargo run --release --bin benchy -- winning-post --size 2
> cargo run --release --bin benchy -- window-post --size 2
> cargo run --release --bin benchy -- prodbench
```

There is also a bench called `gpu-cpu-test`:

```
> cargo run --release --bin gpu-cpu-test
```

Some results are displayed at the command line, or alternatively written as JSON files.  Logging can be enabled using the `RUST_LOG=trace` option (see more Logging options in the `Logging` section below).

Note: On macOS you need `gtime` (`brew install gnu-time`), as the built in `time` command is not enough.

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

## Settings

Further down in this README, various settings are described that can be adjusted by the end-user.  These settings are summarized in `rust-fil-proofs.config.toml.sample` and this configuration file can be used directly if copied to `./rust-fil-proofs.config.toml`.  Alternatively, each setting can be set by using environment variables of the form "FIL_PROOFS_<setting name here>", in all caps.  For example, to set `rows_to_discard` to the value 2, you would set `FIL_PROOFS_ROWS_TO_DISCARD=2` in your environment.

Any configuration setting that is not specified has a reasonable default already chosen.

To verify current environment settings, you can run:

```
cargo run --bin settings
```

## Parameter File Location

Filecoin proof parameter files are expected to be located in `/var/tmp/filecoin-proof-parameters`.  If they are located in an alternate location, you can point the system to that location using an environment variable

```
FIL_PROOFS_PARAMETER_CACHE=/path/to/parameters
```

If you are running a node that is expected to be using production parameters (i.e. the ones specified in the parameters.json file within this repo), you can optionally verify your on-disk parameters using an environment variable

```
FIL_PROOFS_VERIFY_PRODUCTION_PARAMS=1
```

By default, this verification is disabled.

## Optimizing for either speed or memory during replication

While replicating and generating the Merkle Trees (MT) for the proof at the same time there will always be a time-memory trade-off to consider, we present here strategies to optimize one at the cost of the other.

### Speed

One of the most computationally expensive operations during replication (besides the encoding itself) is the generation of the indexes of the (expansion) parents in the Stacked graph, implemented through a Feistel cipher (used as a pseudorandom permutation). To reduce that time we provide a caching mechanism to generate them only once and reuse them throughout replication (across the different layers).

```
FIL_PROOFS_SDR_PARENTS_CACHE_SIZE=2048
```

This value is defaulted to 2048 nodes, which is the equivalent of 112KiB of resident memory (where each cached node consists of DEGREE (base + exp = 6 + 8) x 4 byte elements = 56 bytes in length).  Given that the cache is now located on disk, it is memory mapped when accessed in window sizes related to this variable.  This default was chosen to minimize memory while still allowing efficient access to the cache.  If you would like to experiment with alternate sizes, you can modify the environment variable

Increasing this value will increase the amount of resident RAM used.

Lastly, the parent's cache data is located on disk by default in `/var/tmp/filecoin-parents`.  To modify this location, use the environment variable

```
FIL_PROOFS_PARENT_CACHE=/path/to/parent/cache
```

Using the above, the cache data would be located at `/path/to/parent/cache/filecoin-parents`.

Alternatively, use `FIL_PROOFS_CACHE_DIR=/path/to/parent/cache`, in which the parent cache will be located in `$FIL_PROOFS_CACHE_DIR/filecoin-parents`.  Note that if you're using `FIL_PROOFS_CACHE_DIR`, it must be set through the environment and cannot be set using the configuration file.  This setting has no effect if `FIL_PROOFS_PARENT_CACHE` is also specified.

If you are concerned about the integrity of your on-disk parent cache files, they can be verified at runtime when accessed for the first time using an environment variable

```
FIL_PROOFS_VERIFY_CACHE=1
```

If they are inconsistent (compared to the manifest in storage-proofs/porep/parent-cache.json), they will be automatically re-generated at runtime.  If that cache generation fails, it will be reported as an error.

```
FIL_PROOFS_USE_MULTICORE_SDR
```

When performing SDR replication (Precommit Phase 1) using only a single core, memory access to fetch a node's parents is
a bottlneck. Multicore SDR uses multiple cores (which should be restricted to a single core complex for shared cache) to
assemble each nodes parents and perform some prehashing. This setting is not enabled by default but can be activated by
setting `FIL_PROOFS_USE_MULTICORE_SDR=1`.

To take advantage of shared cache, the process should have been restricted to a single complex's cores. For example, on
an AMD Threadripper 3970x (where tested), this can be accomplished using `taskset -c 4,5,6,7` to ensure four 'adjacent'
cores are used (note that this avoids spanning a complex border).

Best performance will also be achieved when it is possible to lock pages which have been memory-mapped. This can be
accomplished either by running the process as root, or by increasing the system limit for max locked memory with `ulimit
-l`. Two sector size's worth of data (for current and previous layers) must be locked -- along with 56 *
`FIL_PROOFS_PARENT_CACHE_SIZE` bytes for the parent cache.

Default parameters have been tuned to provide good performance on the AMD Ryzen Threadripper 3970x. It may be useful to
experiment with these, especially on different hardware. We have made an effort to use sensible heuristics and to ensure
reasonable behavior for a range of configurations and hardware, but actual performance or behavior of mulitcore
replication is not yet well tested except on our target. The following settings may be useful, but do expect some
failure in the search for good parameters. This might take the form of failed replication (bad proofs), errors during
replication, or even potentially crashes if parameters prove pathological. For now, this is an experimental feature, and
only the default configuration on default hardware (3970x) is known to work well.

`FIL_PROOFS_MULTICORE_SDR_PRODUCERS`: This is the number of worker threads loading node parents in parallel. The default is `3` so the producers and main thread together use a full core complex (but no more).
`FIL_PROOFS_MULTICORE_SDR_PRODUCER_STRIDE`: This is the (max) number of nodes for which a producer thread will load parents in each iteration of its loop. The default is`128`.
`FIL_PROOFS_MULTICORE_SDR_LOOKAHEAD`: This is the size of the lookahead buffer into which node parents are pre-loaded by the producer threads. The default is 800.

### GPU Usage

We can now optionally build the column hashed tree 'tree_c' using the GPU with noticeable speed-up over the CPU.  To activate the GPU for this, use the environment variable

```
FIL_PROOFS_USE_GPU_COLUMN_BUILDER=1
```

We can optionally also build 'tree_r_last' using the GPU, which provides at least a 2x speed-up over the CPU.  To activate the GPU for this, use the environment variable

```
FIL_PROOFS_USE_GPU_TREE_BUILDER=1
```

Note that *both* of these GPU options can and should be enabled if a supported GPU is available.

### Advanced GPU Usage

If using the GPU to build tree_c (using `FIL_PROOFS_USE_GPU_COLUMN_BUILDER=1`), two experimental variables can be tested for local optimization of your hardware.  First, you can set

```
FIL_PROOFS_MAX_GPU_COLUMN_BATCH_SIZE=X
```

The default value for this is 400,000, which means that we compile 400,000 columns at once and pass them in batches to the GPU.  Each column is a "single node x the number of layers" (e.g. a 32GiB sector has 11 layers, so each column consists of 11 nodes).  This value is used as both a reasonable default, but it's also measured that it takes about as much time to compile this size batch as it does for the GPU to consume it (using the 2080ti for testing), which we do in parallel for maximized throughput.  Changing this value may exhaust GPU RAM if set too large, or may decrease performance if set too low.  This setting is made available for your experimentation during this step.

The second variable that may affect performance is the size of the parallel write buffers when storing the tree data returned from the GPU.  This value is set to a reasonable default of 262,144, but you may adjust it as needed if an individual performance benefit can be achieved.  To adjust this value, use the environment variable

```
FIL_PROOFS_COLUMN_WRITE_BATCH_SIZE=Y
```

A similar option for building 'tree_r_last' exists.  The default batch size is 700,000 tree nodes.  To adjust this, use the environment variable

```
FIL_PROOFS_MAX_GPU_TREE_BATCH_SIZE=Z
```

### Memory

At the moment the default configuration is set to reduce memory consumption as much as possible so there's not much to do from the user side. We are now storing Merkle trees on disk, which were the main source of memory consumption.  You should expect a maximum RSS between 1-2 sector sizes, if you experience peaks beyond that range please report an issue (you can check the max RSS with the `/usr/bin/time -v` command).

### Advanced Storage Tuning

With respect to the 'tree_r_last' cached Merkle Trees persisted on disk, a value is exposed for tuning the amount of storage space required.  Cached merkle trees are like normal merkle trees, except we discard some number of rows above the base level.  There is a trade-off in discarding too much data, which may result in rebuilding almost the entire tree when it's needed.  The other extreme is discarding too few rows, which results in higher utilization of disk space.  The default value is chosen to carefully balance this trade-off, but you may tune it as needed for your local hardware configuration.  To adjust this value, use the environment variable

```
FIL_PROOFS_ROWS_TO_DISCARD=N
```

Note that if you modify this value and seal sectors using it, it CANNOT be modified without updating all previously sealed sectors (or alternatively, discarding all previously sealed sectors).  A tool is provided for this conversion, but it's considered an expensive operation and should be carefully planned and completed before restarting any nodes with the new setting.  The reason for this is because all 'tree_r_last' trees must be rebuilt from the sealed replica file(s) with the new target value of FIL_PROOFS_ROWS_TO_DISCARD in order to make sure that the system is consistent.

Adjusting this setting is NOT recommended unless you understand the implications of modification.

## Generate Documentation

First, navigate to the `rust-fil-proofs` directory.

- If you cloned `rust-fil-proofs` manually, it will be wherever you cloned it:

```
> git clone https://github.com/filecoin-project/rust-fil-proofs.git
> cd rust-fil-proofs
```

For documentation corresponding to the latest source, you should clone `rust-fil-proofs` yourself.

Now, generate the documentation:

```
> cargo doc --all --no-deps
```

View the docs by pointing your browser at: `…/rust-fil-proofs/target/doc/proofs/index.html`.

---

## API Reference

The **FPS** is accessed from [**lotus**](https://github.com/filecoin-project/lotus) via FFI calls to its API, which is the union of the APIs of its constituents:

 The source of truth defining the **FPS** APIs is a separate repository of Rust source code. View the source directly:

- [**filecoin-proofs-api**](https://github.com/filecoin-project/rust-filecoin-proofs-api)

The above referenced repository contains the consumer facing API and it provides a versioned wrapper around the `rust-fil-proofs` repository's internal APIs.  End users should not be using the internal APIs of `rust-fil-proofs` directly, as they are subject to change outside of the formal API provided.

To generate the API documentation locally, follow the instructions to generate documentation above. Then navigate to:
- **Filecoin Proofs API:** `…/rust-filecoin-proofs-api/target/doc/filecoin_proofs_api/index.html`

- [Go implementation of filecoin-proofs sectorbuilder API](https://github.com/filecoin-project/go-sectorbuilder/blob/master/sectorbuilder.go) and [associated interface structures](https://github.com/filecoin-project/go-sectorbuilder/blob/master/interface.go).


## Building for Arm64

In order to build for arm64 the current requirements are

- nightly rust compiler

Example for building `filecoin-proofs`

```
$ rustup +nightly target add aarch64-unknown-linux-gnu
$ cargo +nightly build -p filecoin-proofs --release --target aarch64-unknown-linux-gnu
```

## Contributing

See [Contributing](CONTRIBUTING.md)

## License

The Filecoin Project is dual-licensed under Apache 2.0 and MIT terms:

- Apache License, Version 2.0, ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)
