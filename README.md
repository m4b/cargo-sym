# cargo-sym
Prints various binary symbols in your crate

# Usage

First install:

`cargo install cargo-sym`

Then:

1. `cargo sym` will print every debugging symbol it finds in the first valid binary target in `target/debug`
2. `cargo sym -d` will print every debugging symbol demangled
3. `cargo sym -e` will print every exported symbol importable by other binaries
4. `cargo sym -e -d` will do `-d` and `-e` together :]

# TODO:

When goblin gets a mach and PE backend (which should be soonish), will update here

PRs welcome of course :)