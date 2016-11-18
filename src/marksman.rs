use walkdir::WalkDir;
use toml;
use errors::*;
use std::process::Command;
use std::env;
use std::path::{Path, PathBuf};
use std::fs::File;
use std::io::Read;

fn rustc() -> Command {
    Command::new(env::var("RUSTC").as_ref().map(|s| &s[..]).unwrap_or("rustc"))
}

// stole this from japaric
pub fn target_list() -> Result<Vec<String>> {
    let stdout = rustc().args(&["--print", "target-list"]).output()?.stdout;
    let stdout = String::from_utf8_lossy(&stdout);

    Ok(stdout.split('\n')
        .filter_map(|s| if s.is_empty() {
            None
        } else {
            Some(s.to_owned())
        })
        .collect())
}

#[inline]
fn get_crate_name() -> Result<String> {
    let mut toml_fd = File::open("Cargo.toml")?;
    let mut toml = String::new();
    let _ = toml_fd.read_to_string(&mut toml);
    // FIXME: don't unwrap here
    let value: toml::Value = toml.parse().unwrap();
    let package_name = match value.lookup("package.name") {
        Some(package_name) => {
            package_name
            .as_str()
            .unwrap()
            .to_owned()
            // FIXME: we only replace this if it's a library..., so this breaks on ourself :/
            //.replace("-", "_")
        },
        None => Err(Error::MissingPackageName)?
    };
    Ok(package_name)
}

fn find_target(crate_name: &str) -> Result<PathBuf> {
    let target_list = target_list()?;
    let mut target = Path::new("target").to_path_buf();
    for entry in WalkDir::new("target").max_depth(1) {
        let entry = entry?;
        println!("filename: {:?}", entry.file_name());
        let filename: String = entry.file_name().to_str().unwrap().to_string();
        if target_list.contains(&filename) {
            target = entry.path().to_path_buf();
            break;
        }
    }
    let targets = [
        target.join("debug").join(&crate_name),
        target.join("debug").join(&format!("lib{}.so", &crate_name)),
        target.join("debug").join(&format!("lib{}.rlib", &crate_name)),
        target.join("debug").join(&format!("lib{}.a", &crate_name))
    ];
    for target in &targets {
        println!("target {:?}", target);
        if target.exists() {
            return Ok(target.clone())
        }
    }
    Err(Error::NoTargetFoundFor(target_list))
}

pub struct Marksman {
    pub crate_name: String,
    target: PathBuf,
}

impl Marksman {
    pub fn crate_name (&self) -> &str {
        &self.crate_name
    }
    pub fn new(file: Option<&str>) -> Result<Self> {
        let crate_name = get_crate_name()?;
        let target = match file {
            Some(binary) => {
                Path::new(binary).to_path_buf()
            },
            None => {
                find_target(&crate_name)?
            }
        };
        println!("target : {:?}", target);
        Ok( Marksman {
            crate_name: crate_name,
            target: target
        })
    }
    pub fn take_aim(&self) -> Result<File> {
        Ok(File::open(&self.target)?)
    }
}