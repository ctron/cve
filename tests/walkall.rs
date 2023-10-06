use cve::Cve;
use std::ffi::OsStr;
use std::fs::File;
use std::io::BufReader;
use std::path::Path;
use walkdir::WalkDir;

#[test]
fn walkall() -> anyhow::Result<()> {
    env_logger::init();

    let source = std::env::var("CVE_BASE_DIR").expect("Pass in path to the CVE repository data");

    let walker = WalkDir::new(source).follow_links(true).contents_first(true);

    for entry in walker {
        let entry = entry?;

        if !entry.file_type().is_file() {
            continue;
        }

        if entry.path().extension().and_then(OsStr::to_str) != Some("json") {
            continue;
        }

        let name = match entry.file_name().to_str() {
            None => continue,
            Some(name) => name,
        };

        if !name.starts_with("CVE-") {
            continue;
        }

        process(entry.path())?;
    }

    Ok(())
}

fn process(path: &Path) -> anyhow::Result<()> {
    let cve = match path.file_name().and_then(OsStr::to_str) {
        Some(name) => name,
        None => return Ok(()),
    };

    log::info!("{}: {}", cve, path.display());

    let _cve: Cve = serde_json::from_reader(BufReader::new(File::open(&path)?))?;

    Ok(())
}
