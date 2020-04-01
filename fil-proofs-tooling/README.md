# fil-proofs-tooling

This crate contains the following binaries

- `benchy` - Can be used to capture Stacked performance metrics
- `micro` - Runs the micro benchmarks written with criterion, parses the output.

## `benchy`

The `benchy` program can (currently) be used to capture Stacked performance
metrics. Metrics are printed to stdout.

```
$ ./target/release/benchy stacked --size=1024 | jq '.'
{
  "inputs": {
    "dataSize": 1048576,
    "m": 5,
    "expansionDegree": 8,
    "slothIter": 0,
    "partitions": 1,
    "hasher": "pedersen",
    "samples": 5,
    "layers": 10
  },
  "outputs": {
    "avgGrothVerifyingCpuTimeMs": null,
    "avgGrothVerifyingWallTimeMs": null,
    "circuitNumConstraints": null,
    "circuitNumInputs": null,
    "extractingCpuTimeMs": null,
    "extractingWallTimeMs": null,
    "replicationWallTimeMs": 4318,
    "replicationCpuTimeMs": 32232,
    "replicationWallTimeNsPerByte": 4117,
    "replicationCpuTimeNsPerByte": 30739,
    "totalProvingCpuTimeMs": 0,
    "totalProvingWallTimeMs": 0,
    "vanillaProvingCpuTimeUs": 378,
    "vanillaProvingWallTimeUs": 377,
    "vanillaVerificationWallTimeUs": 98435,
    "vanillaVerificationCpuTimeUs": 98393,
    "verifyingWallTimeAvg": 97,
    "verifyingCpuTimeAvg": 97
  }
}
```

To include information about RAM utilization during Stacked benchmarking, run
`benchy` via its wrapper script:

```
$ ./scripts/benchy.sh stacked --size=1024 | jq '.'
{
  "inputs": {
    "dataSize": 1048576,
    "m": 5,
    "expansionDegree": 8,
    "slothIter": 0,
    "partitions": 1,
    "hasher": "pedersen",
    "samples": 5,
    "layers": 10
  },
  "outputs": {
    "avgGrothVerifyingCpuTimeMs": null,
    "avgGrothVerifyingWallTimeMs": null,
    "circuitNumConstraints": null,
    "circuitNumInputs": null,
    "extractingCpuTimeMs": null,
    "extractingWallTimeMs": null,
    "replicationWallTimeMs": 4318,
    "replicationCpuTimeMs": 32232,
    "replicationWallTimeNsPerByte": 4117,
    "replicationCpuTimeNsPerByte": 30739,
    "totalProvingCpuTimeMs": 0,
    "totalProvingWallTimeMs": 0,
    "vanillaProvingCpuTimeUs": 378,
    "vanillaProvingWallTimeUs": 377,
    "vanillaVerificationWallTimeUs": 98435,
    "vanillaVerificationCpuTimeUs": 98393,
    "verifyingWallTimeAvg": 97,
    "verifyingCpuTimeAvg": 97,
    "maxResidentSetSizeKb": 45644
  }
}
```

To run benchy on a remote server, provide SSH connection information to the
benchy-remote.sh script:

```shell
10:13 $ ./fil-proofs-tooling/scripts/benchy-remote.sh master foo@16.16.16.16 stacked --size=1 | jq '.'
{
  "inputs": {
    // ...
  },
  "outputs": {
    // ...
  }
}
```

Run benchy in "prodbench" mode with custom input and detailed metrics.

```shell
> echo '{
    "drg_parents": 6,
    "expander_parents": 8,
    "graph_parents": 8,
    "porep_challenges": 50,
    "porep_partitions": 10,
    "post_challenged_nodes": 1,
    "post_challenges": 20,
    "sector_size_bytes": 1024,
    "stacked_layers": 4,
    "window_size_bytes": 512,
    "wrapper_parents_all": 8
}' > config.json
> cat config.json|RUST_LOG=info ./target/release/benchy prodbench|jq '.'
…
{
  "git": {
    "hash": "d751257b4f7339f6ec3de7b3fda1b1b8979ccf21",
    "date": "2019-12-18T21:08:21Z"
  },
  "system": {
    "system": "Linux",
    "release": "5.2.0-3-amd64",
    "version": "#1 SMP Debian 5.2.17-1 (2019-09-26)",
    "architecture": "x86_64",
    "processor": "Intel(R) Core(TM) i7-8550U CPU @ 1.80GHz",
    "processor-base-frequency-hz": 2000,
    "processor-max-frequency-hz": 4000,
    "processor-features": "FeatureInfo { eax: 526058, ebx: 101713920, edx_ecx: SSE3 | PCLMULQDQ | DTES64 | MONITOR | DSCPL | VMX | EIST | TM2 | SSSE3 | FMA | CMPXCHG16B | PDCM | PCID | SSE41 | SSE42 | X2APIC | MOVBE | POPCNT | TSC_DEADLINE | AESNI | XSAVE | OSXSAVE | AVX | F16C | RDRAND | FPU | VME | DE | PSE | TSC | MSR | PAE | MCE | CX8 | APIC | SEP | MTRR | PGE | MCA | CMOV | PAT | PSE36 | CLFSH | DS | ACPI | MMX | FXSR | SSE | SSE2 | SS | HTT | TM | PBE | 0x4800 }",
    "processor-cores-logical": 8,
    "processor-cores-physical": 4,
    "memory-total-bytes": 32932844000
  },
  "benchmarks": {
    "inputs": {
      "window_size_bytes": 512,
      "sector_size_bytes": 1024,
      "drg_parents": 6,
      "expander_parents": 8,
      "porep_challenges": 50,
      "porep_partitions": 10,
      "post_challenges": 20,
      "post_challenged_nodes": 1,
      "stacked_layers": 4,
      "wrapper_parents_all": 8
    },
    "outputs": {
      "comm_d_cpu_time_ms": 0,
      "comm_d_wall_time_ms": 0,
      "encode_window_time_all_cpu_time_ms": 11,
      "encode_window_time_all_wall_time_ms": 4,
      "encoding_cpu_time_ms": 23,
      "encoding_wall_time_ms": 18,
      "epost_cpu_time_ms": 1,
      "epost_wall_time_ms": 1,
      "generate_tree_c_cpu_time_ms": 12,
      "generate_tree_c_wall_time_ms": 6,
      "porep_commit_time_cpu_time_ms": 83,
      "porep_commit_time_wall_time_ms": 27,
      "porep_proof_gen_cpu_time_ms": 6501654,
      "porep_proof_gen_wall_time_ms": 972945,
      "post_finalize_ticket_cpu_time_ms": 0,
      "post_finalize_ticket_time_ms": 0,
      "epost_inclusions_cpu_time_ms": 1,
      "epost_inclusions_wall_time_ms": 0,
      "post_partial_ticket_hash_cpu_time_ms": 1,
      "post_partial_ticket_hash_time_ms": 1,
      "post_proof_gen_cpu_time_ms": 61069,
      "post_proof_gen_wall_time_ms": 9702,
      "post_read_challenged_range_cpu_time_ms": 0,
      "post_read_challenged_range_time_ms": 0,
      "post_verify_cpu_time_ms": 37,
      "post_verify_wall_time_ms": 31,
      "tree_r_last_cpu_time_ms": 14,
      "tree_r_last_wall_time_ms": 6,
      "window_comm_leaves_time_cpu_time_ms": 20,
      "window_comm_leaves_time_wall_time_ms": 3,
      "porep_constraints": 67841707,
      "post_constraints": 335127,
      "kdf_constraints": 212428
    }
  }
}
```


## `micro`

All arguments passed to `micro` will be passed to `cargo bench --all <your arguments> -- --verbose --color never`.
Except for the following

### Example

```sh
> cargo run --bin micro -- --bench blake2s hash-blake2s
```
