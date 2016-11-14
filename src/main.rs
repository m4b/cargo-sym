extern crate clap;
extern crate goblin;
extern crate rustc_demangle;
extern crate toml;
extern crate capstone;
#[macro_use] extern crate quick_error;

pub mod symbol;

use clap::{Arg, App, SubCommand, AppSettings};
use symbol::Symbol;

use std::fs::File;
use std::io::{self, Cursor, Read, Seek, ErrorKind};
use std::io::SeekFrom;
use std::path::{Path, PathBuf};
use std::result;

quick_error! {
    #[derive(Debug)]
    pub enum Error {
        Io(err: std::io::Error) { from () }
        CapstoneError(err: capstone::error::Err) { from ()}
        UnsupportedBinary { from() }
        SectionlessBinary { description("Cannot analyze and disassemble a sectionless (section stripped) binary") from() }
        StrippedBinary { description("Cannot analyze and disassemble a stripped binary") from() }
    }
}

type Result<T> = result::Result<T, Error>;

/// The command line state we're interested in
pub struct Config {
    pub exports: bool,
    pub demangle: bool,
    pub crate_name: String,
    pub disassemble: bool,
}

/// A fibulurous Trans-Ductinator which hammifies the Symglob
/// - It knows how to return `Symbol`s
/// When a new binary backend becomes available, `impl` a new TransDuctinator!
pub trait TransDuctinator {
    fn get_arch(&self) -> Option<capstone::Arch>;
    fn symbols(&self, config: &Config) -> Vec<Symbol>;
    fn print_symbols(&self, config: &Config) {
        for symbol in self.symbols(config) {
            symbol.print(config.demangle)
        }
    }
}

// this is all terribly inefficient right now, primarily due to goblin parsing and reading everything
// on earth. that should be fixed soon with some special magiks
impl TransDuctinator for goblin::elf::Elf {
    fn symbols(&self, config: &Config) -> Vec<Symbol> {
        let mut syms = Vec::new();
        let (iter, strtab) = if config.exports {
            (&self.dynsyms, &self.dynstrtab)
        } else {
            (&self.syms, &self.strtab)
        };
        for sym in iter {
            let name = &strtab[sym.st_name() as usize];
            // we skip boring empty symbol names and imports
            if !name.is_empty() && (!config.exports || !sym.is_import()) {
                syms.push(Symbol::new(name, sym.st_value(), sym.st_size() as usize));
            }
        }
        syms.sort_by(|s1, s2| s1.offset.cmp(&s2.offset));
        syms
    }

    fn get_arch(&self) -> Option<capstone::Arch> {
        use goblin::elf::header::*;
        use capstone::Arch::*;
        match self.header.e_machine() {
            EM_AARCH64 => Some(ARM64),
            EM_ARM => Some(ARM),
            EM_X86_64 => Some(X86),
            EM_386 => Some(X86),
            _ => None
        }
    }
}

fn get_crate_name() -> String {
    let mut toml_fd = File::open("Cargo.toml")
                          .expect("No Cargo.toml file found in root directory...");
    let mut toml = String::new();
    let _ = toml_fd.read_to_string(&mut toml);
    let value: toml::Value = toml.parse().expect("Malformed Cargo.toml file");
    let package_name = value.lookup("package.name")
                            .expect("No package.name in Cargo.toml")
                            .as_str()
                            .unwrap()
                            .to_owned()
        // we only replace this if it's a library..., so this breaks on ourself :/
                            .replace("-", "_");
    package_name
}

fn get_target(crate_name: &str) -> Option<PathBuf> {
    let targets = [Path::new("target").join("debug").join(&crate_name),
                   Path::new("target").join("debug").join(&format!("lib{}.so", &crate_name)),
                   Path::new("target").join("debug").join(&format!("lib{}.rlib", &crate_name)),
                   Path::new("target").join("debug").join(&format!("lib{}.a", &crate_name))];
    for target in &targets {
        match File::open(&target) {
            Ok(_) => return Some(target.clone()),
            _ => (),
        }
    }
    None
}

fn valid_disassembly_target(name: &str) -> bool {
    match name {
        ".init" | ".plt" | ".plt.got" | ".text" | ".fini" => true,
        _ => false,
    }
}

#[inline]
fn print_disass(bytes: &[u8], capstone: &capstone::Capstone, symbol: Symbol, demangle: bool) -> Result<()> {
    let offset = symbol.offset as usize;
    let bytes = &bytes[offset .. offset + symbol.size as usize];
    let instructions = capstone.disasm(bytes, symbol.offset)?;
    if !instructions.is_empty() {
        println!("{}:\n{}", symbol.maybe_demangle(demangle), instructions);
    }
    Ok(())
}

fn bias (sym: &goblin::elf::Sym, section: &goblin::elf::SectionHeader) -> u64 {
    (sym.st_value() - section.sh_addr()) + section.sh_offset()
}

fn disassemble_elf (bytes: &mut Cursor<&Vec<u8>>, elf: &goblin::elf::Elf, config: &Config) -> Result<()> {
    let arch = elf.get_arch().ok_or(Error::UnsupportedBinary)?;
    let mut capstone = capstone::Capstone::new(arch)?;
    capstone.att();
    let mode = if elf.little_endian { capstone::Mode::LittleEndian } else { capstone::Mode::BigEndian };
    capstone.mode(&[mode])?;
    let strtab = &elf.strtab;
    let shdr_strtab = &elf.shdr_strtab;
    let bytes = bytes.get_ref();
    let section_headers = &elf.section_headers;
    if section_headers.len() == 0 { return Err(Error::SectionlessBinary)}
    let sections: Vec<(_, &str)> = section_headers.into_iter().map (| section | {
        let section_name = &shdr_strtab[section.sh_name()];
        (section, section_name)
    }).collect();
    let syms = &elf.syms;
    if syms.len() == 0 { return Err(Error::StrippedBinary)}
    // filter the symbols to remove imports and empty symbol names
    let mut elf_syms = syms.into_iter().filter(|sym| !sym.is_import() && !&strtab[sym.st_name()].is_empty()).collect::<Vec<_>>();
    elf_syms.sort_by(|s1, s2| {
        use std::cmp::Ordering::*;
        match s1.st_shndx().cmp(&s2.st_shndx()) {
            Equal => {
                s1.st_value().cmp(&s2.st_value())
            },
            order => order
        }
    });
    let mut current_section = 0;
    let nsyms = elf_syms.len();
    let mut i = 0;
    for sym in &elf_syms {
        //println!("name: {} st_shndx: {}", &strtab[sym.st_name()],  sym.st_shndx());
        //println!("{} {:?}", &strtab[sym.st_name()], sym);
        let is_last = i >= nsyms - 1;
        let section_index = sym.st_shndx();
        if section_index >= sections.len() { continue }
        let (ref section, ref section_name) = sections[sym.st_shndx() as usize];
        if section.sh_type() != goblin::elf::section_header::SHT_PROGBITS || !valid_disassembly_target(section_name) { continue }
        //if name.is_empty() { name = format!("{}@{}", &dynstrtab[sym.st_name()], section_name)}
        if current_section != section_index {
            current_section = section_index;
            println!("Disassembly of section {}\n", section_name);
            match section_name {
                // maybe do some specific plt disassembly stuff
                // this is a hack for printing PLT entries (plt.got is untested and doesn't work)
                &".plt" | &".plt.got" => {
                    let mut start = section.sh_offset() as usize;
                    let size = section.sh_entsize() as usize;
                    let strtab = &elf.dynstrtab;
                    let symbol = Symbol::new(&"PLT", start as u64, size);
                    print_disass(&bytes, &capstone, symbol, config.demangle)?;
                    start += size;
                    for rela in &elf.pltrela {
                        let symindex = rela.r_sym();
                        let sym = elf.dynsyms.get(symindex);
                        let name = &strtab[sym.st_name()];
                        //println!("name: {} offset {:x} size: {} shname: {} shoffset: {:x} shaddr: {:x}", name, rela.r_offset(), size, section_name, section.sh_offset(), section.sh_addr());
                        let symbol = Symbol::new(&name, start as u64, size);
                        print_disass(&bytes, &capstone, symbol, config.demangle)?;
                        start += size;
                    }
                },
                _ => ()
            }
        }
        // we're not doing plt stuff, so regular disassembly
        let name = &strtab[sym.st_name()];
        if name.is_empty() { continue }
        let mut size = sym.st_size() as usize;
        let offset = bias(&sym, &section);
        // we compute the size of unsized symbols on the fly. it sucks. because elf sucks.
        if size == 0 && !is_last {
            let next_sym = &elf_syms[i + 1];
            //println!("i: {} current {}, name{} next: {:?}", i, current_section, name, next_sym);
            if current_section == next_sym.st_shndx() {
                let next_offset = bias(&next_sym, &section);
                size = (next_offset - offset) as usize;
            } else {
                size = section.sh_size() as usize;
            }
        }
        //println!("offset {:x} size: {} section: {}, sh_type: {}", offset, size, section_name, section_header::sht_to_str(section.sh_type()));
        let symbol = Symbol::new(name, offset, size);
        print_disass(&bytes, &capstone, symbol, config.demangle)?;
        i += 1;
    }
    Ok(())
}

fn do_elf (bytes: &mut Cursor<&Vec<u8>>, config: &Config) -> Result<()> {
    let elf = goblin::elf::Elf::parse(bytes)?;
    if config.disassemble {
        disassemble_elf(bytes, &elf, config)?;
    } else {
        elf.print_symbols(config);
    }
    Ok(())
}

fn run(fd: &mut File, config: &Config) -> Result<()> {
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
        let bytes = archive.extract(&format!("{}.0.o", &config.crate_name), bytes)?;
        let mut bytes = Cursor::new(&bytes);
        do_elf(&mut bytes, config)
    } else if &magic[0..4] == goblin::elf::header::ELFMAG {
        do_elf(bytes, config)
    } else {
        Err(Error::from(io::Error::new(err,
                           format!("No binary backend available for target: {:?}", &fd))))
    }
}

fn main() {

    let matches = App::new("cargo-sym")
                      .version("0.0.2")
                      .bin_name("cargo")
                      .settings(&[AppSettings::GlobalVersion, AppSettings::SubcommandRequired])
                      .subcommand(SubCommand::with_name("sym")
                                      .author("m4b <m4b.github.io@gmail.com>")
                                      .about("Prints the debugging symbols in your binary; more \
                                              fancy stuff to come later")
                                      .args(&[Arg::with_name("binary")
                                                  .short("-f")
                                                  .long("file")
                                                  .value_name("BINARY")
                                                  .help("The binary file to read ")
                                                  .takes_value(true),
                                          Arg::with_name("disassemble")
                                              .short("-D")
                                              .long("disassemble")
                                              .value_name("DISASSEMBLE")
                                              .takes_value(false)
                                              .help("Whether to disassaemble or not "),
                                          Arg::with_name("demangle")
                                                  .short("-d")
                                                  .long("demangle")
                                                  .value_name("DEMANGLE")
                                                  .takes_value(false)
                                                  .help("Whether to demangle or not "),
                                              Arg::with_name("exports")
                                                  .short("-e")
                                                  .long("exports")
                                                  .value_name("EXPORTS")
                                                  .takes_value(false)
                                                  .help("Print the exported symbols that are \
                                                         importable by other binaries")]))
                      .get_matches();

    let crate_name = get_crate_name();
    let matches = matches.subcommand_matches("sym").unwrap();
    let demangle = matches.is_present("demangle");
    let exports = matches.is_present("exports");
    let disassemble = matches.is_present("disassemble");
    let config = Config {
        demangle: demangle,
        exports: exports,
        crate_name: crate_name.to_string(),
        disassemble: disassemble,
    };
    let mut fd = match matches.value_of("binary") {
                     Some(binary) => File::open(Path::new(binary)),
                     _ => File::open(get_target(&crate_name).expect("No valid binary found")),
                 }
                 .expect("Cannot open file");

    run(&mut fd, &config)
        .expect(&format!("Cannot read symbols from: {}", &config.crate_name));

}
