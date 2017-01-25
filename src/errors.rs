use std::io;
use capstone;
use scroll;
use goblin;
use std::result;
use toml;
use walkdir;

quick_error! {
    #[derive(Debug)]
    pub enum Error {
        Io(err: io::Error) { from () }
        Walkdir(err: walkdir::Error) { from () }
        CapstoneError(err: capstone::error::Error) { from ()}
        ScrollError(err: scroll::Error) { from ()}
        GoblinError(err: goblin::error::Error) { from ()}
        UnsupportedBinary { from() }
        SectionlessBinary { description("Cannot analyze and disassemble a sectionless (section stripped) binary") from() }
        StrippedBinary { description("Cannot analyze and disassemble a stripped binary") from() }
        NoTargetFoundFor(list: Vec<String>) { description("No valid target found for") from() }
        BadToml(error: toml::ParserError) { from() }
        MissingPackageName { description("Your Cargo.toml doesn't specify a package name. Fix it please") }
    }
}

pub type Result<T> = result::Result<T, Error>;
