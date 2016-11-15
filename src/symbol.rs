//! Generic Symbols found in binaries.
//! Great stuff.

use std::fmt::{self, Display};
use rustc_demangle::{self, Demangle};

/// A simple wrapper for a generic symbol. Contains the demangled symbol, and the offset it was found.
#[derive(Debug)]
pub struct Symbol<'a> {
    demangle: Demangle<'a>,
    pub offset: u64,
    pub vaddr: u64,
    pub size: usize,
}

impl<'a> Symbol<'a> {
    pub fn new(name: &str, offset: u64, vaddr: u64, size: usize) -> Symbol {
        let demangle = rustc_demangle::demangle(name);
        Symbol { demangle: demangle, offset: offset, size: size, vaddr: vaddr }
    }

    /// Return this symbols original name
    pub fn name(&self) -> &str {
        self.demangle.as_str()
    }
    /// Returns this symbols demangled name, if it has one
    pub fn demangle(&self) -> String {
        self.demangle.to_string()
    }

    pub fn print(&self, demangle: bool) {
        let mut name: &str = &self.demangle();
        if !demangle {
            name = &self.name();
        }
        println!("{:016x} {}", self.vaddr, name)
    }
    pub fn maybe_demangle(&self, demangle: bool) -> String {
        let mut name: &str = &self.demangle();
        if !demangle {
            name = &self.name();
        }
        format!("{:016x} {}", self.vaddr, name)
    }

}

impl<'a> Display for Symbol<'a> {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        write!(fmt, "{:016x} {}", self.vaddr, self.demangle)
    }
}

