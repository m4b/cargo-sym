use clap;

/// The command line state we're interested in
#[derive(Debug)]
pub struct Config<'a> {
    pub exports: bool,
    pub demangle: bool,
    pub disassemble: bool,
    pub dump: bool,
    pub release: bool,
    pub example: Option<&'a str>,
    pub file: Option<&'a str>,
    pub base_target: &'static str,
}

impl<'a> From<&'a clap::ArgMatches<'a>> for Config<'a> {
    fn from(matches: &'a clap::ArgMatches) -> Self {
        let matches = matches.subcommand_matches("sym").unwrap();
        let demangle = matches.is_present("demangle");
        let exports = matches.is_present("exports");
        let disassemble = matches.is_present("disassemble");
        let dump = matches.is_present("dump");
        let release = matches.is_present("release");
        let file_name = matches.value_of("binary");
        let example = matches.value_of("example");
        let debug_or_release = if release { "release" } else { "debug" };
        Config {
            demangle: demangle,
            exports: exports,
            disassemble: disassemble,
            dump: dump,
            release: release,
            example: example,
            file: file_name,
            base_target: debug_or_release,
        }
    }
}
