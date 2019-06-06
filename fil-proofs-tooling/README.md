# fil-proofs-tooling

This crate contains the following binaries

- `bencher` - Can be used to run the examples and time them
- `micro` - Runs the micro benchmarks written with criterion, parses the output and pushes the information into prometheus.

## `micro`

All arguments passed to `micro` will be passed to `cargo bench --all <your arguments> -- --verbose --color never`.
Except for the following

- `--push-prometheus`: If set triggers the code to push to a prometheus gateway, expected to listen on `127.0.0.1:9091`.

### Example

```sh
> cargo run --bin micro -- --bench blake2s hash-blake2s
```
