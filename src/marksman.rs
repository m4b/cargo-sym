use config::Config;

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
            package_name.as_str()
                .unwrap()
                .to_owned()
            // FIXME: we only replace this if it's a library..., so this breaks on ourself :/
            // .replace("-", "_")
        }
        None => Err(Error::MissingPackageName)?,
    };
    Ok(package_name)
}

fn find_target(crate_name: &str, config: &Config) -> Result<PathBuf> {
    let target_list = target_list()?;
    let mut target = Path::new("target").to_path_buf();
    match config.target {
        Some(t) => {
            target = target.join(t);
            // if we're not the same as the base target (debug/release), then we add it
            if t != config.base_target {
                target = target.join(&config.base_target);
            }
            // add examples if we asked for it
            if config.example.is_some() {
                target = target.join("examples");
            }
        }
        None => {
            // fixme: we really should actually _try_ each of these file targets and use it if it's there
            // that way we iterate through known targets for free; but maybe this is very unlikely and
            // the user should just delete half-built/unused stale/old targets
            for entry in WalkDir::new("target").max_depth(1) {
                let entry = entry?;
                //println!("filename: {:?}", entry.file_name());
                let filename: String = entry.file_name().to_str().unwrap().to_string();
                // we choose the first available target in the list; if none are found, we default to target/debug
                if target_list.contains(&filename) {
                    target = entry.path().to_path_buf();
                    //println!("using target: {:?}", target);
                    break;
                }
            }
            let base_target = if config.example.is_some() {
                Path::new(&config.base_target).join(&"examples")
            } else {
                Path::new(&config.base_target).to_path_buf()
            };
            target = target.join(base_target);

        }
    }
    let names = [crate_name.to_string(),
                 format!("lib{}.so", &crate_name),
                 format!("lib{}.rlib", &crate_name),
                 format!("lib{}.a", &crate_name)];

    let targets: Vec<PathBuf> = names.iter()
        .map(|name| target.join(&name))
        .collect();

    for target in &targets {
        //println!("target {:?}", target);
        if target.exists() {
            return Ok(target.clone());
        }
    }
    Err(Error::NoTargetFoundFor(target_list))
}

pub struct Marksman {
    pub crate_name: String,
    target: PathBuf,
}

impl Marksman {
    pub fn crate_name(&self) -> &str {
        &self.crate_name
    }
    pub fn new(config: &Config) -> Result<Self> {
        let crate_name = get_crate_name()?;
        let target = match config.file {
            Some(binary) => Path::new(binary).to_path_buf(),
            None => {
                let target_name = match config.example {
                    Some(example) => example,
                    None => &crate_name,
                };
                find_target(&target_name, &config)?
            }
        };
        println!("target : {:?}", target);
        Ok(Marksman {
            crate_name: crate_name,
            target: target,
        })
    }
    pub fn take_aim(&self) -> Result<File> {
        Ok(File::open(&self.target)?)
    }
}
