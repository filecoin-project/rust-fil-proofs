# Release notes

Steps to cut a release:

1) Update the CHANGELOG.md file
2) Copy Cargo.lock file to releases directory with appropriate version name
3) Run `cargo release` with the appropriate options

## Pre-release testing

Ensure that the following tests work as expected:

Basic tests:

```
# Regular tests
FIL_PROOFS_VERIFY_CACHE=1 \
FIL_PROOFS_VERIFY_PRODUCTION_PARAMS=0 \
FIL_PROOFS_USE_GPU_COLUMN_BUILDER=1 \
FIL_PROOFS_USE_GPU_TREE_BUILDER=1 \
FIL_PROOFS_USE_MULTICORE_SDR=1 \
RUST_BACKTRACE=full \
RUST_LOG=trace RUSTFLAGS="-C target-cpu=native" \
cargo test --release --all

# Ignored tests
FIL_PROOFS_VERIFY_CACHE=1 \
FIL_PROOFS_VERIFY_PRODUCTION_PARAMS=0 \
FIL_PROOFS_USE_GPU_COLUMN_BUILDER=1 \
FIL_PROOFS_USE_GPU_TREE_BUILDER=1 \
FIL_PROOFS_USE_MULTICORE_SDR=1 \
RUST_BACKTRACE=full \
RUST_LOG=trace RUSTFLAGS="-C target-cpu=native" \
cargo test --release --all -- --ignored
```

Extended tests:

Note: These tests require machines with large storage and RAM and are long running.

```
# 32GiB seal lifecycle test
FIL_PROOFS_VERIFY_CACHE=1 \
FIL_PROOFS_VERIFY_PRODUCTION_PARAMS=1 \
FIL_PROOFS_USE_GPU_COLUMN_BUILDER=1 \
FIL_PROOFS_USE_GPU_TREE_BUILDER=1 \
FIL_PROOFS_USE_MULTICORE_SDR=1 \
RUST_BACKTRACE=full \
RUST_LOG=info \
RUSTFLAGS="-C target-cpu=native" \
cargo test --features big-tests --release test_seal_lifecycle_32gib_porep_id_v1_1_top_8_8_0_api_v1_1 -- --nocapture

# 32GiB seal lifecycle test (synth-porep)
FIL_PROOFS_VERIFY_CACHE=1 \
FIL_PROOFS_VERIFY_PRODUCTION_PARAMS=1 \
FIL_PROOFS_USE_GPU_COLUMN_BUILDER=1 \
FIL_PROOFS_USE_GPU_TREE_BUILDER=1 \
FIL_PROOFS_USE_MULTICORE_SDR=1 \
RUST_BACKTRACE=full \
RUST_LOG=info \
RUSTFLAGS="-C target-cpu=native" \
cargo test --features big-tests --release test_seal_lifecycle_32gib_porep_id_v1_2_top_8_8_0_api_v1_2 -- --nocapture

# 32GiB seal lifecycle test (ni-porep)
FIL_PROOFS_VERIFY_CACHE=1 \
FIL_PROOFS_VERIFY_PRODUCTION_PARAMS=1 \
FIL_PROOFS_USE_GPU_COLUMN_BUILDER=1 \
FIL_PROOFS_USE_GPU_TREE_BUILDER=1 \
FIL_PROOFS_USE_MULTICORE_SDR=1 \
RUST_BACKTRACE=full \
RUST_LOG=info \
RUSTFLAGS="-C target-cpu=native" \
cargo test --features big-tests --release test_seal_lifecycle_32gib_porep_id_v1_2_ni_top_8_8_0_api_v1_2 -- --nocapture

# 32GiB max seal proof aggregation
FIL_PROOFS_VERIFY_CACHE=1 \
FIL_PROOFS_VERIFY_PRODUCTION_PARAMS=1 \
FIL_PROOFS_USE_GPU_COLUMN_BUILDER=1 \
FIL_PROOFS_USE_GPU_TREE_BUILDER=1 \
FIL_PROOFS_USE_MULTICORE_SDR=1 \
RUST_BACKTRACE=full \
RUST_LOG=info \
RUSTFLAGS="-C target-cpu=native" \
cargo test --features big-tests --release test_max_ni_seal_proof_aggregation_32gib -- --nocapture

# 32GiB seal lifecycle sector upgrade test
FIL_PROOFS_VERIFY_CACHE=1 \
FIL_PROOFS_VERIFY_PRODUCTION_PARAMS=1 \
FIL_PROOFS_USE_GPU_COLUMN_BUILDER=1 \
FIL_PROOFS_USE_GPU_TREE_BUILDER=1 \
FIL_PROOFS_USE_MULTICORE_SDR=1 \
RUST_BACKTRACE=full \
RUST_LOG=info \
RUSTFLAGS="-C target-cpu=native" \
cargo test --features big-tests --release test_seal_lifecycle_upgrade_32gib_top_8_8_0_v1_2 -- --nocapture

# 64GiB seal lifecycle test
FIL_PROOFS_VERIFY_CACHE=1 \
FIL_PROOFS_VERIFY_PRODUCTION_PARAMS=1 \
FIL_PROOFS_USE_GPU_COLUMN_BUILDER=1 \
FIL_PROOFS_USE_GPU_TREE_BUILDER=1 \
FIL_PROOFS_USE_MULTICORE_SDR=1 \
RUST_BACKTRACE=full \
RUST_LOG=info \
RUSTFLAGS="-C target-cpu=native" \
cargo test --features big-tests --release test_seal_lifecycle_64gib_porep_id_v1_1_top_8_8_2_api_v1_1 -- --nocapture

# 64GiB seal lifecycle test (synth-porep)
FIL_PROOFS_VERIFY_CACHE=1 \
FIL_PROOFS_VERIFY_PRODUCTION_PARAMS=1 \
FIL_PROOFS_USE_GPU_COLUMN_BUILDER=1 \
FIL_PROOFS_USE_GPU_TREE_BUILDER=1 \
FIL_PROOFS_USE_MULTICORE_SDR=1 \
RUST_BACKTRACE=full \
RUST_LOG=info \
RUSTFLAGS="-C target-cpu=native" \
cargo test --features big-tests --release test_seal_lifecycle_64gib_porep_id_v1_2_top_8_8_2_api_v1_2 -- --nocapture

# 64GiB seal lifecycle test (ni-porep)
FIL_PROOFS_VERIFY_CACHE=1 \
FIL_PROOFS_VERIFY_PRODUCTION_PARAMS=1 \
FIL_PROOFS_USE_GPU_COLUMN_BUILDER=1 \
FIL_PROOFS_USE_GPU_TREE_BUILDER=1 \
FIL_PROOFS_USE_MULTICORE_SDR=1 \
RUST_BACKTRACE=full \
RUST_LOG=info \
RUSTFLAGS="-C target-cpu=native" \
cargo test --features big-tests --release test_seal_lifecycle_64gib_porep_id_v1_2_ni_top_8_8_2_api_v1_2 -- --nocapture

# 64GiB seal proof aggregation
FIL_PROOFS_VERIFY_CACHE=1 \
FIL_PROOFS_VERIFY_PRODUCTION_PARAMS=1 \
FIL_PROOFS_USE_GPU_COLUMN_BUILDER=1 \
FIL_PROOFS_USE_GPU_TREE_BUILDER=1 \
FIL_PROOFS_USE_MULTICORE_SDR=1 \
RUST_BACKTRACE=full \
RUST_LOG=info \
RUSTFLAGS="-C target-cpu=native" \
cargo test --features big-tests --release test_sector_update_proof_aggregation_3_64gib -- --nocapture

# 64GiB seal lifecycle sector upgrade test
FIL_PROOFS_VERIFY_CACHE=1 \
FIL_PROOFS_VERIFY_PRODUCTION_PARAMS=1 \
FIL_PROOFS_USE_GPU_COLUMN_BUILDER=1 \
FIL_PROOFS_USE_GPU_TREE_BUILDER=1 \
FIL_PROOFS_USE_MULTICORE_SDR=1 \
RUST_BACKTRACE=full \
RUST_LOG=info \
RUSTFLAGS="-C target-cpu=native" \
cargo test --features big-tests --release test_seal_lifecycle_upgrade_64gib_top_8_8_2_v1_2 -- --nocapture
```
