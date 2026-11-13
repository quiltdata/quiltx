//! Rust core of quiltx, built into the Python package as `quiltx._core`.
//!
//! This is a walking skeleton: two functions that prove the Rust/Python
//! boundary and the cross-platform build, with no quiltx behaviour behind them
//! yet. Real logic arrives in later changes.

use pyo3::prelude::*;

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

#[pymodule]
fn _core(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(core_version, m)?)?;
    m.add_function(wrap_pyfunction!(ping, m)?)?;
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
