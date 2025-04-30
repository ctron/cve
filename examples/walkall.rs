use anyhow::bail;
use cve::{Cve, Published, Rejected};
use indicatif::{MultiProgress, ParallelProgressIterator, ProgressBar, ProgressStyle};
use indicatif_log_bridge::LogWrapper;
use rayon::prelude::*;
use std::ffi::OsStr;
use std::path::Path;
use std::process::ExitCode;
use std::sync::atomic::{AtomicUsize, Ordering};
use walkdir::WalkDir;

fn main() -> anyhow::Result<ExitCode> {
    let logger =
        env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).build();
    let multi = MultiProgress::new();

    LogWrapper::new(multi.clone(), logger).try_init().unwrap();

    let source = std::env::var("CVE_BASE_DIR").expect("Pass in path to the CVE repository data");

    let walker = WalkDir::new(source).follow_links(true).contents_first(true);

    let mut files = Vec::new();

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

        files.push(entry.into_path());
    }

    let pb = multi.add(ProgressBar::new(files.len() as u64));
    pb.set_style(
        ProgressStyle::default_bar()
            .template("{msg} {wide_bar} {pos}/{len} ({eta})")
            .unwrap(),
    );

    let num = files.len();

    let counter = AtomicUsize::default();

    files.into_par_iter().progress_with(pb).for_each(|file| {
        if process(&file).is_err() {
            counter.fetch_add(1, Ordering::SeqCst);
        };
    });

    log::info!("Successfully parsed {num} documents");
    let failed = counter.load(Ordering::SeqCst);

    Ok(if failed > 0 {
        log::error!("{failed} documents failed to parse");
        ExitCode::FAILURE
    } else {
        ExitCode::SUCCESS
    })
}

fn process(path: &Path) -> anyhow::Result<()> {
    let _cve = match path.file_name().and_then(OsStr::to_str) {
        Some(name) => name,
        None => return Ok(()),
    };

    let content = std::fs::read(path)?;

    let cve: Cve = match serde_json::from_slice(&content) {
        Ok(cve) => cve,
        Err(_err) => {
            let published = serde_json::from_slice::<Published>(&content).unwrap_err();
            let rejected = serde_json::from_slice::<Rejected>(&content).unwrap_err();
            log::warn!("Published: {published} @ {}", path.display());
            log::warn!("Rejected: {rejected} @ {}", path.display());
            bail!(
                "Failed to parse {} as either published or rejected",
                path.display()
            );
        }
    };

    static COUNTER: AtomicUsize = AtomicUsize::new(0);

    if COUNTER.fetch_add(1, Ordering::SeqCst) % 100 == 0 {
        log::info!("{cve:?}");
    }

    Ok(())
}
