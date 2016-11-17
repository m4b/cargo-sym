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
    pub is_function: bool,
}

impl<'a> Symbol<'a> {
    pub fn new(name: &str, offset: u64, vaddr: u64, size: usize, is_function: bool) -> Symbol {
        let demangle = rustc_demangle::demangle(name);
        Symbol {
            demangle: demangle,
            offset: offset,
            size: size,
            vaddr: vaddr,
            is_function: is_function,
        }
    }

    /// Return this symbols original name
    pub fn name(&self) -> &str {
        self.demangle.as_str()
    }
    /// Returns this symbols demangled name, if it has one
    pub fn demangle(&self) -> String {
        self.demangle.to_string()
    }
    pub fn format(&self, demangle: bool, is_64: bool) -> String {
        let mut name: &str = &self.demangle();
        if !demangle {
            name = &self.name();
        }
        if is_64 {
            format!("{:016x} <{}>", self.vaddr, name)
        } else {
            format!("{:08x} <{}>", self.vaddr, name)
        }
    }
}

impl<'a> Display for Symbol<'a> {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        write!(fmt, "{:016x} {}", self.vaddr, self.demangle)
    }
}
