// Copyright (C) 2024-2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: AGPL-3.0-or-later
//! Ceremony helpers: file I/O primitives for attestation tools.
//!
//! Minimal stub — full implementation planned.

use std::path::{Path, PathBuf};

/// Resolve `path` to an absolute canonical-ish path, attaching `label` to error messages.
pub fn absolute_path(
    path: impl AsRef<std::ffi::OsStr>,
    label: &str,
) -> Result<PathBuf, Box<dyn std::error::Error>> {
    let p = PathBuf::from(path.as_ref());
    if p.as_os_str().is_empty() {
        return Err(format!("{label}: path must not be empty").into());
    }
    Ok(if p.is_absolute() {
        p
    } else {
        std::env::current_dir()?.join(p)
    })
}

/// Read a file, rejecting it if it exceeds `max_bytes`.
/// `expected_mode` is reserved for future Unix permission checks.
pub fn read_private_file(
    path: &Path,
    max_bytes: u64,
    _expected_mode: Option<u32>,
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let meta =
        std::fs::metadata(path).map_err(|e| format!("cannot stat {}: {e}", path.display()))?;
    if meta.len() > max_bytes {
        return Err(format!(
            "{}: file exceeds limit of {max_bytes} bytes (got {})",
            path.display(),
            meta.len()
        )
        .into());
    }
    std::fs::read(path).map_err(|e| format!("cannot read {}: {e}", path.display()).into())
}

/// Write `data` to `path` atomically (write to a sibling `.tmp` then rename).
pub fn atomic_write_private(path: &Path, data: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
    let tmp = path.with_extension("tmp");
    std::fs::write(&tmp, data).map_err(|e| format!("cannot write {}: {e}", tmp.display()))?;
    std::fs::rename(&tmp, path)
        .map_err(|e| format!("cannot rename {} -> {}: {e}", tmp.display(), path.display()).into())
}

/// Assert that no two paths in `paths` are identical.
pub fn require_distinct_paths(paths: &[&Path]) -> Result<(), Box<dyn std::error::Error>> {
    for i in 0..paths.len() {
        for j in (i + 1)..paths.len() {
            if paths[i] == paths[j] {
                return Err(format!(
                    "paths must be distinct: {} appears more than once",
                    paths[i].display()
                )
                .into());
            }
        }
    }
    Ok(())
}
