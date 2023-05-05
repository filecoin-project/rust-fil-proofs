Storage Proofs Binaries
=======================

This crate contains a bundle of binaries to perform the proving in separate steps. The goal is a composable system you can drive with your own scripts.


Example scripts
---------------

The [`scripts`] directory contains some example scripts on how such a pipeline could look like.

**WARNING**: Those scripts only serve as examples and are not meant for production use. You should build your own pipeline in your preferred language.

Before running any of those scripts it's recommended to compile the binaries first. Run from within the root of this `fil-proofs-bin` directory:

```console
cargo build --release --bins
```

By default the scripts run with the default features. If you e.g. want to enable CUDA support, you can do so by overriding the `CARGO` env variable:

```console
CARGO='cargo run --release --features cuda'
```


### PC1/PC2

The [`pc1_pc2_cc.sh` script] illustrates how you could run the Precommit phase for a single CC sector. It returns the `CommR` of that sector. Example of running it for a 2KiB sector:

```console
> echo '{"output_dir": "/tmp/2kib", "porep_id": "0x0500000000000000000000000000000000000000000000000000000000000000", "replica_path": "/tmp/2kib/sc-02-data-layer-2.dat", "replica_id": "0xd93f7c0618c236179361de2164ce34ffaf26ecf3be7bf7e6b8f0cfcf886ad0d0", "sector_size": 2048}'|./scripts/pc1_pc2_cc.sh
…
{"comm_r":"0x9dabeaa4e2b53153152ac485c6b8ede4d750be12d0fae4fa265161dc0ff5502a"}
```


License
-------

[MIT] or [Apache 2.0].

[`scripts`]: ./scripts
[`pc1_pc2.sh` script]: ./scripts/pc1_pc2.sh
[MIT]: ./LICENSE-MIT
[Apache 2.0]: ./LICENSE-APACHE
