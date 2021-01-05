# Filecoin Parameters

> Parameter related utilities for Filecoin.


Available tools are

- `paramcache`
- `paramfetch`
- `parampublish`
- `fakeipfsadd`

# Running `parampublish` with Mocked `ipfs` Binary

```
$ cargo build --bin fakeipfsadd --bin parampublish
$ ./target/debug/parampublish --ipfs-bin=./target/debug/fakeipfsadd [-a]
```

## License

MIT or Apache 2.0
