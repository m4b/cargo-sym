//! Generic Symbols found in binaries.
//! Great stuff.

use std::fmt::{self, Display};

use rustc_demangle::Demangle;

/// A simple wrapper for a generic symbol. Contains the demangled symbol, and the offset it was found.
pub struct Symbol<'a> {
    demangle: Demangle<'a>,
    pub offset: u64,
}

impl<'a> Symbol<'a> {
    pub fn new(demangle: Demangle, offset: u64) -> Symbol {
        Symbol { demangle: demangle, offset: offset}
    }

    /// Return this symbols original name
    pub fn name(&self) -> &str {
        self.demangle.as_str()
    }
    /// Returns this symbols demangled name, if it has one
    pub fn demangle(&self) -> String {
        self.demangle.to_string()
    }
}

impl<'a> Display for Symbol<'a> {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        write!(fmt, "{:016x} {}", self.offset, self.demangle)
    }
}
