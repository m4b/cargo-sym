# cargo-sym [![Build Status](https://travis-ci.org/m4b/cargo-sym.svg?branch=master)](https://travis-ci.org/m4b/cargo-sym)
Prints various binary symbols in your crate. Also experimentally disassembles.

This uses capstone for disassembly, so it will compile faster if you have capstone installed as a system library.

# Usage

First install:

`cargo install cargo-sym`

or via git:

`cargo install --git https://github.com/m4b/cargo-sym -f`

Then:

1. `cargo sym` will print every debugging symbol it finds in the first valid binary target in `target/<target>/debug`. This can be, for example:

  a.`target/debug` (this is used if it doesn't find a special target, like the following)
  
  b. `target/x86_64-unknown-linux-musl/debug`

2. `cargo sym -C` will print every debugging symbol demangled
3. `cargo sym -e` will print every exported symbol importable by other binaries
4. `cargo sym -Ce` will do `-C` and `-e` together :]
5. `cargo sym -d` will disassemble your binary, objdump style. **experimental**
6. `cargo sym -d -C /bin/ls` will disassemble the binary `ls` at `/bin/` (actually most distros strip `/bin/ls` so it actually won't)
7. `cargo sym -Cd --target=aarch64-linux-android` will disassemble your crates binary at `target/aarch64-linux-android/debug/<crate_name>`
8. `cargo sym -C --release -x example` will print the symbols from the example binary you compiled in release mode (at `target/release/examples/example`)
9. `cargo sym -Cd --target=debug -x main` will disassemble the example binary `main` in the regular debug location `target/debug/examples/main`

Try `cargo sym --help` for more information!

# TODO:

1. Target selector is not. There are a few fixmes to make it nicer. (easy)
2. ARM 32-byte printer not completely correct when in thumb mode, should reverse second 8 byte block. (easy)
3. Need to properly print got, plt, and plt.got and iterate through sections in a more principled manner. (not to easy)
4. When goblin gets a mach and PE backend (which I keep saying will be soon), update the various backends (tedious, hard, requires knowledge of backend formats)

PRs welcome of course :)