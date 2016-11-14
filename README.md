# cargo-sym
Prints various binary symbols in your crate. Also experimentally disassembles.

# Usage

First install:

`cargo install cargo-sym`

Then:

1. `cargo sym` will print every debugging symbol it finds in the first valid binary target in `target/debug`
2. `cargo sym -C` will print every debugging symbol demangled
3. `cargo sym -e` will print every exported symbol importable by other binaries
4. `cargo sym -e -C` will do `-d` and `-e` together :]
5. `cargo sym -d` will disassemble your binary, objdump style. **experimental**
6. `cargo sym -d -C -f /bin/ls` will disassemble the binary `ls` at `/bin/` (actually most distros strip `/bin/ls` so it actually won't)

# TODO:

When goblin gets a mach and PE backend (which should be soonish), will update here

PRs welcome of course :)