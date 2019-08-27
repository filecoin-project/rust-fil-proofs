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
- Please follow our commit guideline described below.
- Welcome contribution areas might include:
  - SNARKs
  - Proof-of-replication
  - Rust improvements
  - Optimizations
  - Documentation (expertise would require careful reading of the code)


## PR Merge Policy (Git topology)

### Allowed (white list)
 - Single fast-forward merge commit, with all internal commits squashed.
 - Non-fast-forward merge commit, with all internal commits squashed -- rebased to branch from the previous commit to master.
 - Non-fast-forward merge commit, with curated (as appropriate), linear, internal commits preserved -- rebased to branch from the previous commit to master.

### Disallowed (black list)
 - Non-rebased merge commits which branch from anywhere but the previous commit to master.
 - Merge commits whose internal history contains merge commits (except in rare circumstances).
 - Multiple fast-forward merge commits for a single PR.
 - Internal junk commits — (e.g. strings of WIP).

### In Practice
 - In general, please rebase PRs before merging.
 - To avoid having approvals dismissed by rebasing, authors may instead choose to:
   - First use GitHub's 'resolve conflicts' button;
   - Then merge with GitHub's 'squash and merge' button.

If automated conflict resolution is not possible, you will need to rebase and seek re-approval. In any event, please note the guidelines and prefer either a single commit or a usefully curated set of commits.

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


## Commit Message Guidelines

We have very precise rules over how our git commit messages can be formatted. This leads to **more
readable messages** that are easy to follow when looking through the **project history**. But also,
we use the git commit messages to **generate the change log programmatically**.

### Commit Message Format

Each commit message consists of a **header**, a **body** and a **footer**.  The header has a special
format that includes a **type**, a **scope** and a **subject**:

```
<type>(<scope>): <subject>
<BLANK LINE>
<body>
<BLANK LINE>
<footer>
```

The **header** is mandatory and the **scope** of the header is optional.

Any line of the commit message cannot be longer 100 characters! This allows the message to be easier
to read on GitHub as well as in various git tools.

The footer should contain a [closing reference to an issue](https://help.github.com/articles/closing-issues-via-commit-messages/) if any.

Samples: (even more [samples](https://github.com/filecoin-project/rust-fil-proofs/commits/master))

```
docs(changelog): update changelog to beta.5
```
```
fix(release): need to depend on latest rxjs and zone.js
The version in our package.json gets copied to the one we publish, and users need the latest of these.
```

### Revert
If the commit reverts a previous commit, it should begin with `revert: `, followed by the header of the reverted commit. In the body it should say: `This reverts commit <hash>.`, where the hash is the SHA of the commit being reverted.

### Type
Must be one of the following:

* **build**: Changes that affect the build system or external dependencies (example scopes: cargo, benchmarks)
* **ci**: Changes to our CI configuration files and scripts (example scopes: Circle)
* **docs**: Documentation only changes
* **feat**: A new feature
* **fix**: A bug fix
* **perf**: A code change that improves performance
* **refactor**: A code change that neither fixes a bug nor adds a feature
* **style**: Changes that do not affect the meaning of the code (white-space, formatting, missing semi-colons, etc)
* **test**: Adding missing tests or correcting existing tests
* **revert**: Used only for `git revert` commits.

### Scope
The scope should be the name of the crate affected (as perceived by the person reading the changelog generated from commit messages.

The following is the list of supported scopes:

* **fil-proofs-tooling**
* **filecoin-proofs**
* **storage-proofs**

There are currently a few exceptions to the "use package name" rule:

* **cargo**: used for changes that change the cargo workspace layout, e.g.
  public path changes, Cargo.toml changes done to all packages, etc.
* **changelog**: used for updating the release notes in CHANGELOG.md
* none/empty string: useful for `style`, `test` and `refactor` changes that are done across all
  packages (e.g. `style: add missing semicolons`) and for docs changes that are not related to a
  specific package (e.g. `docs: fix typo in tutorial`).

> If you find yourself wanting to use other scopes regularly, please open an issue so we can discuss and extend this list.

### Subject
The subject contains a succinct description of the change:

* use the imperative, present tense: "change" not "changed" nor "changes"
* don't capitalize the first letter
* no dot (.) at the end

### Body
Just as in the **subject**, use the imperative, present tense: "change" not "changed" nor "changes".
The body should include the motivation for the change and contrast this with previous behavior.

### Footer
The footer should contain any information about **Breaking Changes** and is also the place to
reference GitHub issues that this commit **Closes**.

**Breaking Changes** should start with the word `BREAKING CHANGE:` with a space or two newlines. The rest of the commit message is then used for this.

This guideline was adopted from the [Angular project](https://github.com/angular/angular/blob/master/CONTRIBUTING.md#commit).

## Licensing

As mentioned in the [readme](README.md) all contributions are dual licensed under Apache 2 and MIT.
