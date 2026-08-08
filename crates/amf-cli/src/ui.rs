//! Terminal output.
//!
//! Warnings that matter to trust are printed loudly and separately from the
//! progress bar. A hash disagreement between two hosts scrolling past inside a
//! progress display would be the worst possible place to put it.

use indicatif::{ProgressBar, ProgressStyle};

pub fn error(msg: &str) {
    eprintln!("error: {msg}");
}

pub fn warn(msg: &str) {
    eprintln!("warning: {msg}");
}

/// A warning serious enough that it must not be missed.
pub fn alarm(title: &str, body: &str) {
    eprintln!();
    eprintln!("!! {title}");
    for line in body.lines() {
        eprintln!("!! {line}");
    }
    eprintln!();
}

pub fn info(msg: &str) {
    println!("{msg}");
}

pub fn step(msg: &str) {
    println!("==> {msg}");
}

pub fn progress_bar(total: u64, label: &str) -> ProgressBar {
    let bar = ProgressBar::new(total);
    bar.set_style(
        ProgressStyle::with_template(
            "  {msg}\n  [{bar:40}] {bytes}/{total_bytes} ({bytes_per_sec}, {eta})",
        )
        .unwrap_or_else(|_| ProgressStyle::default_bar())
        .progress_chars("=> "),
    );
    bar.set_message(label.to_string());
    bar
}

pub fn human_bytes(n: u64) -> String {
    amf_fs::human_bytes(n)
}
