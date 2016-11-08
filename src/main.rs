extern crate clap;
extern crate goblin;
extern crate rustc_demangle;
extern crate toml;

pub mod symbol;

use clap::{Arg, App};
use symbol::Symbol;

use std::fs::File;
use std::io::{self, Cursor, Read, Seek, ErrorKind};
use std::io::SeekFrom;
use std::path::{Path, PathBuf};

/// The command line state we're interested in
/// For now mostly whether we should print exports or demangle
pub struct Config {
    pub exports: bool,
    pub demangle: bool,
    pub crate_name: String,
}

/// A fibulurous Trans-Ductinator which hammifies the Symglob
/// - It knows how to return `Symbol`s
/// When a new binary backend becomes available, `impl` a new TransDuctinator!
pub trait TransDuctinator {
    fn symbols(&self, config: &Config) -> Vec<Symbol>;
}

// this is all terribly inefficient right now, primarily due to goblin parsing and reading everything
// on earth. that should be fixed soon with some special magiks
impl TransDuctinator for goblin::elf::Elf {
    fn symbols(&self, config: &Config) -> Vec<Symbol> {
        let mut syms = Vec::new();
        let (iters, strtab) = if config.exports {
            (&self.dynsyms, &self.dynstrtab)
        } else {
            (&self.syms, &self.strtab)
        };
        for sym in iters {
            let name = &strtab[sym.st_name() as usize];
            let demangle = rustc_demangle::demangle(name);
            syms.push(Symbol::new(demangle, sym.st_value()));
        }
        syms.sort_by(|s1, s2| s1.offset.cmp(&s2.offset));
        syms
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
                            .to_owned();
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

fn get_symbols(fd: &mut File, config: &Config) -> io::Result<()> {
    // todo write a generic peek function in goblin you jerk
    let mut magic = [0u8; 16];
    let err = ErrorKind::InvalidInput;
    let metadata = try!(fd.metadata());
    try!(fd.read(&mut magic));
    try!(fd.seek(SeekFrom::Start(0)));
    if &magic[0..goblin::archive::SIZEOF_MAGIC] == goblin::archive::MAGIC {
        let archive = try!(goblin::archive::Archive::parse(fd, metadata.len() as usize));
        let bytes = try!(archive.extract(&format!("{}.0.o", &config.crate_name), fd));
        // in the future we'll either wrap this case in a single function call to a handler against
        // TransDuctinaros/whatever later, OR we'll specialize the printing for archive like objdump
        // but for now since we only support ELF, we'll just repeat ourselves!
        let elf = try!(goblin::elf::Elf::parse(&mut Cursor::new(&bytes)));
        for symbol in elf.symbols(config) {
            let mut name: &str = &symbol.demangle();
            if !config.demangle {
                name = symbol.name()
            };
            println!("{:016x} {}", symbol.offset, name);
        }
        Ok(())
    } else if &magic[0..4] == goblin::elf::header::ELFMAG {
        let binary = try!(goblin::elf::Elf::parse(fd));
        for symbol in binary.symbols(config) {
            let mut name: &str = &symbol.demangle();
            if !config.demangle {
                name = symbol.name()
            };
            println!("{:016x} {}", symbol.offset, name);
        }
        Ok(())
    } else {
        Err(io::Error::new(err, format ! ("No binary backend available for target: {:?}", & fd)))
    }
}

fn main() {

    let matches = App::new("cargo-sym")
                      .version("0.0.1")
                      .author("m4b <m4b.github.io@gmail.com>")
                      .about("Prints the debugging symbols in your binary; more fancy stuff to \
                              come later")
                      .arg(Arg::with_name("binary")
                               .short("-f")
                               .long("file")
                               .value_name("BINARY")
                               .help("The binary file to read ")
                               .takes_value(true))
                      .arg(Arg::with_name("demangle")
                               .short("-d")
                               .long("demangle")
                               .value_name("DEMANGLE")
                               .takes_value(false)
                               .help("Whether to demangle or not "))
                      .arg(Arg::with_name("exports")
                               .short("-e")
                               .long("exports")
                               .value_name("EXPORTS")
                               .takes_value(false)
                               .help("Print the exported symbols that are importable by other \
                                      binaries"))
                      .get_matches();


    let crate_name = get_crate_name();
    let demangle = matches.is_present("demangle");
    let exports = matches.is_present("exports");
    let config = Config {
        demangle: demangle,
        exports: exports,
        crate_name: crate_name.to_string(),
    };
    let mut fd = match matches.value_of("binary") {
                     Some(binary) => File::open(Path::new(binary)),
                     _ => File::open(get_target(&crate_name).expect("No valid binary found")),
                 }
                 .expect("Cannot open file");

    get_symbols(&mut fd, &config).expect(&format!("Cannot read symbols from: {}", &config.crate_name));
}
