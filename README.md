# `pchmod`

[![Crates.io][shields.io]][crates.io]

`pchmod` is a utility to manage the permissions of files and directories on
Unix systems.

## Installation

```sh
cargo install pchmod
pchmod --help
```

### Building From Source

```sh
git clone https://github.com/Gregory-Meyer/pchmod.git
cd pchmod
cargo build --release
target/release/pchmod --help
```

You will then need to copy the binaries from `target/release` to somewhere in
your `PATH`, like `/usr/local/bin`.

## Usage

`pchmod` functions almost exactly like [`chmod` from GNU Coreutils][chmod], but
it runs in parallel with less functionality. All mode settings except `'X'` are
supported, including multiple symbolic modes (`u=rw,g=r,o=r`), but only the
`-R,--recursive` flag is supported. Mode changing is done in parallel using
[Rayon's][rayon] and logging is done via [`env_logger`][env_logger]; to see
permission changes occuring, set the environment variable `RUST_LOG=debug`. No
guarantees are made about the ordering of permission changes due to the nature
of Rayon's work-stealing scheduler.

[crates.io]: https://crates.io/crates/pchmod
[shields.io]: https://img.shields.io/crates/v/pchmod.svg
[chmod]: https://www.gnu.org/software/coreutils/manual/html_node/chmod-invocation.html#chmod-invocation
[rayon]: https://github.com/rayon-rs/rayon
[env_logger]: https://github.com/sebasmagri/env_logger
