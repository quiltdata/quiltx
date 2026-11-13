//! Rust core of quiltx, built into the Python package as `quiltx._core`.
//!
//! The catalog-identity and credential-location logic that used to be Python
//! (`quiltx.identity.normalize_dns`, and the credential-file paths and keyring
//! key in `quiltx.auth.store`) lives here, so the compiled extension is on
//! every CLI command's path. The Python callers are thin wrappers and
//! `quiltx/auth/_native.py` is the only importer.
//!
//! * [`dns`]: `normalize_dns`, a port of the Python original with its error
//!   messages.
//! * [`paths`]: the credential store's directory (`platformdirs`-equivalent),
//!   file paths and keyring entry.

use std::path::PathBuf;

use pyo3::exceptions::{PyRuntimeError, PyValueError};
use pyo3::prelude::*;

pub mod dns;
pub mod paths;

/// Version of this Rust crate, from `Cargo.toml` (not the Python package version).
#[pyfunction]
fn core_version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

/// Return `pong:<message>`: a string crossing the FFI boundary both ways.
#[pyfunction]
fn ping(message: &str) -> String {
    format!("pong:{message}")
}

/// Normalize a catalog identifier to a bare lowercase DNS name; raises
/// `ValueError` with the same message the Python implementation had.
#[pyfunction]
#[pyo3(signature = (value, insecure=false))]
fn normalize_dns(value: &str, insecure: bool) -> PyResult<String> {
    dns::normalize_dns(value, insecure).map_err(|e| PyValueError::new_err(e.0))
}

/// Path of the file-based credential fallback, `credentials.json`.
#[pyfunction]
fn credentials_file() -> PyResult<PathBuf> {
    paths::credentials_file(paths::Platform::current(), &paths::Inputs::from_env())
        .map_err(|e| PyRuntimeError::new_err(e.0))
}

/// Path of the keyring index, `credentials_index.json`.
#[pyfunction]
fn credentials_index_file() -> PyResult<PathBuf> {
    paths::index_file(paths::Platform::current(), &paths::Inputs::from_env())
        .map_err(|e| PyRuntimeError::new_err(e.0))
}

/// `(service, username)` of the OS-keyring entry for a catalog DNS.
#[pyfunction]
fn keyring_entry(dns: &str) -> (&'static str, String) {
    paths::keyring_entry(dns)
}

#[pymodule]
fn _core(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(core_version, m)?)?;
    m.add_function(wrap_pyfunction!(ping, m)?)?;
    m.add_function(wrap_pyfunction!(normalize_dns, m)?)?;
    m.add_function(wrap_pyfunction!(credentials_file, m)?)?;
    m.add_function(wrap_pyfunction!(credentials_index_file, m)?)?;
    m.add_function(wrap_pyfunction!(keyring_entry, m)?)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ping_echoes_the_message() {
        assert_eq!(ping("x"), "pong:x");
        assert_eq!(ping(""), "pong:");
    }

    #[test]
    fn core_version_is_semver_shaped() {
        let parts: Vec<&str> = core_version().split('.').collect();
        assert_eq!(parts.len(), 3);
        assert!(parts.iter().all(|p| p.parse::<u32>().is_ok()));
    }
}
