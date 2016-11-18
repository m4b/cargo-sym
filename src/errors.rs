use std::io;
use capstone;
use std::result;

quick_error! {
    #[derive(Debug)]
    pub enum Error {
        Io(err: io::Error) { from () }
        CapstoneError(err: capstone::error::Error) { from ()}
        UnsupportedBinary { from() }
        SectionlessBinary { description("Cannot analyze and disassemble a sectionless (section stripped) binary") from() }
        StrippedBinary { description("Cannot analyze and disassemble a stripped binary") from() }
    }
}

pub type Result<T> = result::Result<T, Error>;
