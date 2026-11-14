//! Rust core of quiltx, built into the Python package as `quiltx._core`.
//!
//! The catalog-identity, credential-location, and file-backed credential-store
//! logic that used to be Python lives here, so the compiled extension is on
//! every CLI command's path. The Python callers are thin wrappers and
//! `quiltx/auth/_native.py` is the only importer.
//!
//! * [`dns`]: `normalize_dns`, a port of the Python original with its error
//!   messages.
//! * [`paths`]: the credential store's directory (`platformdirs`-equivalent),
//!   file paths and keyring entry.
//! * `store`: the 0600 `credentials.json` fallback, the index file, and the
//!   public get/store/delete/list including the OS-keyring path.
//! * `registry`: resolve the catalog's registry URL, log in, mint a `qk_`
//!   API key, and validate one. HTTP is an injectable client; production
//!   uses the Python `urllib` helpers so SSL env vars and test patches work.
//!
//! # Using the crate from Rust without Python
//!
//! `dns` and `paths` do not touch Python. Depend on the crate with
//! `default-features = false` to get only them, with no PyO3 in the build:
//!
//! ```toml
//! quiltx-core = { git = "https://github.com/quiltdata/quiltx", rev = "...", default-features = false }
//! ```
//!
//! The `python` feature (on by default, and what the wheel build uses) adds the
//! modules that still call into Python (`registry`, `resolve`, `session`,
//! `store`) and the `quiltx._core` extension module itself.

pub mod dns;
pub mod paths;
#[cfg(feature = "python")]
pub mod registry;
#[cfg(feature = "python")]
pub mod resolve;
#[cfg(feature = "python")]
pub mod session;
#[cfg(feature = "python")]
pub mod store;

#[cfg(feature = "python")]
mod python;
