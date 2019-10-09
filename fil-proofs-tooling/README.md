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

## `micro`

All arguments passed to `micro` will be passed to `cargo bench --all <your arguments> -- --verbose --color never`.
Except for the following

### Example

```sh
> cargo run --bin micro -- --bench blake2s hash-blake2s
```
