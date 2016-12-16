#![recursion_limit = "1024"]

extern crate clap;
extern crate goblin;
extern crate rustc_demangle;
extern crate toml;
extern crate capstone3 as capstone;
extern crate walkdir;
#[macro_use]
extern crate quick_error;
// #[macro_use]
// extern crate error_chain;

pub mod symbol;
pub mod marksman;
mod errors;
mod config;

use config::Config;
use symbol::Symbol;
use errors::*;
use marksman::Marksman;
use clap::{Arg, App, SubCommand, AppSettings};

use std::io::{self, Cursor, Read, Seek, ErrorKind};
use std::io::SeekFrom;
use std::fmt;

/// A symbol object.
/// - It knows how to return `Symbol`s _and_ disassemble itself, as well as other useful information about itself.
/// When a new binary backend becomes available, `impl` a new `SymObject`!
pub trait SymObject: fmt::Debug {
    fn get_arch(&self) -> Result<capstone::Arch>;
    fn little_endian(&self) -> bool;
    fn is_64(&self) -> bool;
    fn symbols(&self, config: &Config) -> Vec<Symbol>;
    fn disassemble(&self,
                   bytes: &mut Cursor<&Vec<u8>>,
                   disassembler: capstone::Capstone,
                   config: &Config)
                   -> Result<()>;

    fn new_disassembler(&self) -> Result<capstone::Capstone> {
        let arch = self.get_arch()?;
        let mut capstone = capstone::Capstone::new(arch)?;
        capstone.att();
        let mode = if self.little_endian() {
            capstone::Mode::LittleEndian
        } else {
            capstone::Mode::BigEndian
        };
        capstone.mode(&[mode])?;
        Ok(capstone)
    }
    fn print_vaddr(&self, vaddr: u64) {
        if self.is_64() {
            print!("{:16x}: ", vaddr);
        } else {
            print!("{:8x}: ", vaddr);
        }
    }
    fn print_non_function(&self, bytes: &[u8], vaddr: u64, _config: &Config) -> Result<()> {
        const NCOLUMNS: usize = 4;
        let column_width = if self.is_64() { 8 } else { 4 };
        let mut column = 1;
        let mut stack_buffer = [0u8; 8 * NCOLUMNS];
        let mut hex_buffer = &mut stack_buffer[..column_width * NCOLUMNS];
        let spaces = |columns| (column_width * columns * 2) + columns;
        let bytes_per_row = column_width * NCOLUMNS;
        let spaces_per_row = (column_width * NCOLUMNS * 2) + NCOLUMNS;
        let buffer_len = hex_buffer.len();
        self.print_vaddr(vaddr);
        let mut column_idx = 0;
        for (i, byte) in bytes.iter().rev().enumerate() {
            print!("{:02x}", byte);
            let idx = (i + 1) % column_width;
            hex_buffer[i % buffer_len] = *byte;
            if idx == 0 {
                print!(" ");
                if column % NCOLUMNS == 0 {
                    // hextable
                    for byte in &hex_buffer[..] {
                        let c = char::from(*byte);
                        let c = if c.is_control() { '.' } else { c };
                        print!("{}", c);
                    }
                    println!("");
                    self.print_vaddr(vaddr + 1 + i as u64);
                }
                column += 1;
            }
            column_idx = idx;
        }
        // yes this is so horrible i want to die too
        let remaining_columns = (column % NCOLUMNS) - 1;
        let spaces_written = spaces(remaining_columns) + (column_idx * 2);
        let bytes_written = bytes_per_row -
                            (((NCOLUMNS - remaining_columns) * column_width) - column_idx);
        // print!("\n{} {} written: {} bytes {}/{}", column_idx, remaining_columns, spaces_written, bytes_written, bytes_per_row);
        let whitespace = spaces_per_row - spaces_written;
        for _ in 0..whitespace {
            print!(" ");
        }
        for byte in &hex_buffer[..bytes_written] {
            let c = char::from(*byte);
            let c = if c.is_control() { '.' } else { c };
            print!("{}", c);
        }
        println!("");
        Ok(())
    }
    #[inline]
    fn print_function(&self,
                      instructions: &capstone::instruction::Instructions,
                      _mode: &capstone::Mode)
                      -> Result<()> {
        for instruction in instructions.iter() {
            self.print_vaddr(instruction.address());
            let mut width = 2;
            match self.get_arch()? {
                capstone::Arch::X86 => {
                    // print x86 (and any other variable length ISAs byte wise)
                    // TODO: add big-endian printer, though i think big endian x86 systems don't exist (in practice)?
                    for byte in instruction.bytes() {
                        print!(" {:02x}", byte);
                    }
                    // for the spaces
                    width += 1;
                }
                // these are fixed width instructions so we print them as a unified unit
                // fixme: this will need work for ISAs other than ARM, but maybe who cares about them? :D
                _ => {
                    print!(" ");
                    // FIXME: thumb 4 byte instructions are printed differently/slightly incorrectly, e.g.:
                    // f241 0018 	movw	r0, #4120
                    // 0018f241 	movw	r0, #4120
                    if self.little_endian() {
                        for (_i, byte) in instruction.bytes().iter().rev().enumerate() {
                            print!("{:02x}", byte);
                        }
                    } else {
                        for byte in instruction.bytes() {
                            print!("{:02x}", byte);
                        }
                    }
                }
            }
            let multiplier = if self.is_64() { 16 } else { 8 };
            let remainder = (multiplier * width) - (instruction.len()) * width;
            for _ in 0..remainder {
                print!(" ");
            }
            if let Some(mnemonic) = instruction.mnemonic() {
                print!(" {}", mnemonic);
                if let Some(op_str) = instruction.op_str() {
                    print!(" {}", op_str);
                }
            }
            print!("\n");
        }
        Ok(())
    }
    #[inline]
    fn print_instructions_at_symbol(&self,
                                    bytes: &[u8],
                                    config: &Config,
                                    capstone: &capstone::Capstone,
                                    mode: &capstone::Mode,
                                    symbol: Symbol)
                                    -> Result<()> {
        let offset = symbol.offset as usize;
        let bytes = &bytes[offset..offset + symbol.size];
        println!("{}:", symbol.format(config.demangle, self.is_64(), true));
        if symbol.is_function {
            let instructions = capstone.disassemble(bytes, symbol.vaddr)?;
            if !instructions.is_empty() {
                self.print_function(&instructions, mode)?;
            }
        } else {
            self.print_non_function(bytes, symbol.vaddr, config)?
        }
        println!("");
        Ok(())
    }
    fn print_symbols(&self, config: &Config) {
        for symbol in self.symbols(config) {
            println!("{}", symbol.format(config.demangle, self.is_64(), false))
        }
    }
    fn analyze(&self, bytes: &mut Cursor<&Vec<u8>>, config: &Config) -> Result<()> {
        if config.disassemble {
            let disassembler = self.new_disassembler()?;
            self.disassemble(bytes, disassembler, config)?;
        } else if config.dump {
            println!("{:#?}", self);
        } else {
            self.print_symbols(config);
        }
        Ok(())
    }
}

fn bias(sym: &goblin::elf::Sym, section: &goblin::elf::SectionHeader) -> u64 {
    (sym.st_value() - section.sh_addr()) + section.sh_offset()
}

fn valid_disassembly_target(name: &str) -> bool {
    match name {
        ".init" | ".plt" | ".got" | ".plt.got" | ".text" | ".fini" => true,
        _ => false,
    }
}

// this is all terribly inefficient right now, primarily due to goblin parsing and reading everything
// on earth. that should be fixed soon with some special magiks
impl SymObject for goblin::elf::Elf {
    fn is_64(&self) -> bool {
        self.is_64
    }
    fn little_endian(&self) -> bool {
        self.little_endian
    }
    fn symbols(&self, config: &Config) -> Vec<Symbol> {
        let mut syms = Vec::new();
        let (iter, strtab) = if config.exports {
            (&self.dynsyms, &self.dynstrtab)
        } else {
            (&self.syms, &self.strtab)
        };
        let mask = match self.header.e_machine() {
            goblin::elf::header::EM_ARM => !1,
            _ => !0,
        };
        for sym in iter {
            let name = &strtab[sym.st_name() as usize];
            // we skip boring empty symbol names and imports
            if !name.is_empty() && (!config.exports || !sym.is_import()) {
                let addr = {
                    let addr = sym.st_value();
                    if addr == 0 { 0 } else { addr & mask }
                };
                syms.push(Symbol::new(name, addr, addr, sym.st_size() as usize, sym.is_function()));
            }
        }
        syms.sort_by(|s1, s2| s1.offset.cmp(&s2.offset));
        syms
    }

    fn get_arch(&self) -> Result<capstone::Arch> {
        use goblin::elf::header::*;
        use capstone::Arch::*;
        match self.header.e_machine() {
            EM_AARCH64 => Ok(ARM64),
            EM_ARM => Ok(ARM),
            EM_X86_64 => Ok(X86),
            EM_386 => Ok(X86),
            _ => Err(Error::UnsupportedBinary),
        }
    }

    fn disassemble(&self,
                   bytes: &mut Cursor<&Vec<u8>>,
                   disassembler: capstone::Capstone,
                   config: &Config)
                   -> Result<()> {
        let mut mode = capstone::Mode::LittleEndian;
        let arch = self.get_arch()?;
        let mut capstone = disassembler;
        let strtab = &self.strtab;
        let shdr_strtab = &self.shdr_strtab;
        let bytes = bytes.get_ref();
        let section_headers = &self.section_headers;
        if section_headers.len() == 0 {
            return Err(Error::SectionlessBinary);
        }
        let sections: Vec<(_, &str)> = section_headers.into_iter()
            .map(|section| {
                let section_name = &shdr_strtab[section.sh_name()];
                (section, section_name)
            })
            .collect();
        let syms = &self.syms;
        if syms.len() == 0 {
            return Err(Error::StrippedBinary);
        }

        // filter the symbols to remove imports and empty symbol names
        let mut elf_syms = syms.into_iter()
            .filter(|sym| {
                (sym.is_function() || sym.st_type() == goblin::elf::sym::STT_OBJECT) &&
                !sym.is_import() && !&strtab[sym.st_name()].is_empty()
            })
            .collect::<Vec<_>>();
        elf_syms.sort_by(|s1, s2| {
            use std::cmp::Ordering::*;
            match s1.st_shndx().cmp(&s2.st_shndx()) {
                Equal => s1.st_value().cmp(&s2.st_value()),
                order => order,
            }
        });
        let mut current_section = 0;
        let nsyms = elf_syms.len();
        let mut i = 0;
        for sym in &elf_syms {
            // println!("name: {} st_shndx: {}", &strtab[sym.st_name()],  sym.st_shndx());
            // println!("{} {:?}", &strtab[sym.st_name()], sym);
            let is_last = i >= nsyms - 1;
            let section_index = sym.st_shndx();
            if section_index >= sections.len() {
                continue;
            }
            let (ref section, ref section_name) = sections[sym.st_shndx() as usize];
            if section.sh_type() != goblin::elf::section_header::SHT_PROGBITS ||
               !valid_disassembly_target(section_name) {
                continue;
            }
            // if name.is_empty() { name = format!("{}@{}", &dynstrtab[sym.st_name()], section_name)}
            if current_section != section_index {
                current_section = section_index;
                println!("Disassembly of section {}\n", section_name);
                match section_name {
                    // TODO: this is now a _broken_ hack for printing PLT entries (it doesn't print them,
                    // because there are no longer any symbols with the plt section to set off this logic)
                    &".plt" | &".plt.got" => {
                        let start = section.sh_offset();
                        let vaddr = section.sh_addr();
                        let ssize = section.sh_entsize() as usize;
                        let size = section.sh_entsize();
                        let strtab = &self.dynstrtab;
                        let symbol = Symbol::new(&"PLT", start, vaddr, ssize, true);
                        self.print_instructions_at_symbol(&bytes, config, &capstone, &mode, symbol)?;
                        let mut offset = size;
                        for rela in &self.pltrela {
                            let start = start + offset;
                            let vaddr = vaddr + offset;
                            let symindex = rela.r_sym();
                            let sym = self.dynsyms.get(symindex);
                            let name = &strtab[sym.st_name()];
                            // println!("name: {} offset {:x} size: {} shname: {} shoffset: {:x} shaddr: {:x}", name, rela.r_offset(), size, section_name, section.sh_offset(), section.sh_addr());
                            let symbol = Symbol::new(&name, start, vaddr, ssize, true);
                            self.print_instructions_at_symbol(&bytes,
                                                              config,
                                                              &capstone,
                                                              &mode,
                                                              symbol)?;
                            offset += size;
                        }
                    }
                    _ => (),
                }
            }
            // we're not doing plt stuff, so regular disassembly
            let name = &strtab[sym.st_name()];
            if name.is_empty() {
                continue;
            }
            let mut size = sym.st_size() as usize;
            let mut offset = bias(&sym, &section);
            // we compute the size of unsized symbols on the fly. it sucks. because elf sucks.
            if size == 0 && !is_last {
                let next_sym = &elf_syms[i + 1];
                // println!("i: {} current {}, name{} next: {:?}", i, current_section, name, next_sym);
                if current_section == next_sym.st_shndx() {
                    let next_offset = bias(&next_sym, &section);
                    size = (next_offset - offset) as usize;
                } else {
                    size = section.sh_size() as usize;
                }
            }
            // println!("offset {:x} size: {} section: {}, sh_type: {}", offset, size, section_name, section_header::sht_to_str(section.sh_type()));
            let vaddr = {
                let mut vaddr = sym.st_value();
                if arch == capstone::Arch::ARM {
                    if vaddr & 1 == 1 {
                        // we can speed up capstone mode switching here by using cached value, but who cares for now
                        mode = capstone::Mode::Thumb;
                        vaddr = vaddr - 1;
                        offset = offset - 1;
                    } else {
                        // untested with hybrid binaries...
                        mode = capstone::Mode::Arm32;
                    }
                }
                vaddr
            };
            capstone.mode(&[mode])?;
            let symbol = Symbol::new(name, offset, vaddr, size, sym.is_function());
            self.print_instructions_at_symbol(&bytes, config, &capstone, &mode, symbol)?;
            i += 1;
        }
        Ok(())
    }
}

fn run(config: &Config) -> Result<()> {
    let marksman = Marksman::new(&config)?;
    let mut fd = marksman.take_aim()?;
    // todo write a generic peek function in goblin you jerk
    let mut magic = [0u8; 16];
    let err = ErrorKind::InvalidInput;
    let metadata = fd.metadata()?;
    let mut buffer = Vec::new();
    fd.read_to_end(&mut buffer)?;
    let mut bytes = &mut Cursor::new(&buffer);
    bytes.read(&mut magic)?;
    bytes.seek(SeekFrom::Start(0))?;
    if &magic[0..goblin::archive::SIZEOF_MAGIC] == goblin::archive::MAGIC {
        let archive = goblin::archive::Archive::parse(bytes, metadata.len() as usize)?;
        let bytes = archive.extract(&format!("{}.0.o", &marksman.crate_name), bytes)
            .or(archive.extract(&format!("{}.o", &marksman.crate_name), bytes))?;
        let mut bytes = Cursor::new(&bytes);
        // ideally would pattern match (or just recurse) on the identifier here but we're only supporting elf
        let elf = goblin::elf::Elf::parse(&mut bytes)?;
        elf.analyze(&mut bytes, config)
    } else if &magic[0..4] == goblin::elf::header::ELFMAG {
        let elf = goblin::elf::Elf::parse(bytes)?;
        elf.analyze(bytes, config)
    } else {
        Err(Error::from(io::Error::new(err,
                                       format!("No binary backend available for target: {:?}",
                                               &fd))))
    }
}

fn main() {

    let matches = App::new("cargo-sym")
        .version("0.0.4")
        .bin_name("cargo")
        .settings(&[AppSettings::GlobalVersion, AppSettings::SubcommandRequired])
        .subcommand(SubCommand::with_name("sym")
            .author("m4b <m4b.github.io@gmail.com>")
            .about("Prints the debugging symbols in your binary. Or disassembles arbitrary ISAs \
                    for 32/64 bit binaries. No big deal")
            .args(&[Arg::with_name("binary")
                        .help("The binary file to read ")
                        .required(false)
                        .index(1),
                    Arg::with_name("disassemble")
                        .short("-d")
                        .long("disassemble")
                        .value_name("DISASSEMBLE")
                        .takes_value(false)
                        .help("Whether to disassemble or not "),
                    Arg::with_name("release")
                        .long("release")
                        .value_name("RELEASE")
                        .takes_value(false)
                        .help("Whether to search release target directories (default is debug)"),
                    Arg::with_name("target")
                        .short("t")
                        .long("target")
                        .value_name("target")
                        .takes_value(true)
                        .help("Use the given target even if other targets \
                               are present"),
                    Arg::with_name("example")
                        .short("x")
                        .long("example")
                        .value_name("EXAMPLE")
                        .takes_value(true)
                        .help("If present, a binary in the examples folder with the given \
                               name is used as the target"),
                    Arg::with_name("crate-name")
                        .short("-n")
                        .long("name")
                        .value_name("CRATE_NAME")
                        .takes_value(true)
                        .help("Force the given crate name to be used instead of searching the \
                               Cargo.toml file.This is useful when extracting specific binary \
                               objects to disassemble in static archives."),
                    Arg::with_name("demangle")
                        .short("-C")
                        .long("demangle")
                        .value_name("DEMANGLE")
                        .takes_value(false)
                        .help("Whether to demangle or not "),
                    Arg::with_name("dump")
                        .long("dump")
                        .value_name("DUMP")
                        .takes_value(false)
                        .help("Dump the debug representation of the binary"),
                    Arg::with_name("exports")
                        .short("-e")
                        .long("exports")
                        .value_name("EXPORTS")
                        .takes_value(false)
                        .help("Print the exported symbols that are importable by other \
                               binaries")]))
        .get_matches();

    let config = Config::from(&matches);
    match run(&config) {
        Ok (()) => (),
        Err(err) => {
            println!("Error: {:?}", err);
            ::std::process::exit(1)
        }
    }
}
