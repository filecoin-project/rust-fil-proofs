# Contributing

Welcome, it is great that you found your way here. In order to make the best of all our time, we have gathered some notes 
below which we think can be helpful when contributing to this project.

## Getting Started

Please start by reviewing this file.

## Coding Standards

- No compiler warnings.
- No [clippy](https://github.com/rust-lang/rust-clippy) warnings.
- Minimize use of `unsafe` and justify usage in comments.
- Prefer `expect` with a good description to `unwrap`.
- Write unit tests in the same file.
- Format your code with `rustfmt`
- Code should compile on `stable` and `nightly`. If adding `nightly` only features they should be behind a flag.
- Write benchmarks for performance sensitive areas. We use [criterion.rs](https://github.com/japaric/criterion.rs).


## General Guidelines
- PRs require code owner approval to merge.
- Please scope PRs to areas in which you have expertise. This code is still close to research.
- Welcome contribution areas might include:
  - SNARKs
  - Proof-of-replication
  - Rust improvements
  - Optimizations
  - Documentation (expertise would require careful reading of the code)

## Resources for learning Rust

- Beginners 
  - [The Rust Book](https://doc.rust-lang.org/book/)
  - [Rust Playground](https://play.rust-lang.org/)
  - [Rust Docs](https://doc.rust-lang.org/)
  - [Clippy](https://github.com/rust-lang/rust-clippy)
  - [Rustfmt](https://github.com/rust-lang/rustfmt)
- Advanced
  - What does the Rust compiler do with my code? [Godbolt compiler explorer](https://rust.godbolt.org/)
  - How to safely write unsafe Rust: [The Rustonomicon](https://doc.rust-lang.org/nomicon/)
  - Did someone say macros? [The Little Book of Rust Macros](https://danielkeep.github.io/tlborm/book/index.html)

## Licensing

As mentioned in the [readme](README.md) all contributions are dual licensed under Apache 2 and MIT. 
