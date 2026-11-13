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
//! * [`store`]: the 0600 `credentials.json` fallback and the index file.

use std::path::PathBuf;

use pyo3::exceptions::{
    PyAttributeError, PyRuntimeError, PyTypeError, PyUnicodeDecodeError, PyValueError,
};
use pyo3::prelude::*;
use pyo3::types::{PyAny, PyBool, PyDict, PyInt, PyList, PyTuple};
use serde_json::{Map, Number, Value};

pub mod dns;
pub mod paths;
pub mod store;

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

fn io_err(e: std::io::Error) -> PyErr {
    PyErr::from(e)
}

fn store_op_err(e: store::StoreOpError) -> PyErr {
    match e {
        store::StoreOpError::Validation(store::StoreError(msg)) => PyValueError::new_err(msg),
        store::StoreOpError::Io(e) => io_err(e),
        store::StoreOpError::Attribute { typ, attr } => {
            PyAttributeError::new_err(format!("'{typ}' object has no attribute '{attr}'"))
        }
        store::StoreOpError::Type(msg) => PyTypeError::new_err(msg),
        store::StoreOpError::Utf8(e) => Python::attach(|py| {
            PyUnicodeDecodeError::new_err_from_utf8(py, e.as_bytes(), e.utf8_error())
        }),
        store::StoreOpError::Value(msg) => PyValueError::new_err(msg),
    }
}

fn map_to_py<'py>(py: Python<'py>, map: &Map<String, Value>) -> PyResult<Bound<'py, PyDict>> {
    let dict = PyDict::new(py);
    for (key, value) in map {
        dict.set_item(key, json_to_py(py, value)?)?;
    }
    Ok(dict)
}

fn json_to_py(py: Python<'_>, value: &Value) -> PyResult<Py<PyAny>> {
    match value {
        Value::Null => Ok(py.None()),
        Value::Bool(b) => Ok(PyBool::new(py, *b).to_owned().into_any().unbind()),
        Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                Ok(i.into_pyobject(py)?.into_any().unbind())
            } else if let Some(u) = n.as_u64() {
                Ok(u.into_pyobject(py)?.into_any().unbind())
            } else if store::number_is_integer(n) {
                Ok(py
                    .import("builtins")?
                    .getattr("int")?
                    .call1((n.to_string(),))?
                    .unbind())
            } else if let Some(f) = store::number_as_python_float(n) {
                Ok(f.into_pyobject(py)?.into_any().unbind())
            } else {
                Ok(n.to_string().into_pyobject(py)?.into_any().unbind())
            }
        }
        Value::String(s) => Ok(s.as_str().into_pyobject(py)?.into_any().unbind()),
        Value::Array(items) => {
            let list = PyList::empty(py);
            for item in items {
                list.append(json_to_py(py, item)?)?;
            }
            Ok(list.into_any().unbind())
        }
        Value::Object(map) => Ok(map_to_py(py, map)?.into_any().unbind()),
    }
}

fn pydict_to_map(dict: &Bound<'_, PyDict>) -> PyResult<Map<String, Value>> {
    let mut map = Map::new();
    for (key, value) in dict.iter() {
        let key: String = match key.extract() {
            Ok(s) => s,
            Err(_) => key.str()?.to_string(),
        };
        map.insert(key, py_to_json(&value)?);
    }
    Ok(map)
}

fn py_to_json(obj: &Bound<'_, PyAny>) -> PyResult<Value> {
    if obj.is_none() {
        return Ok(Value::Null);
    }
    // bool is a subclass of int in Python; try it first.
    if let Ok(b) = obj.extract::<bool>() {
        return Ok(Value::Bool(b));
    }
    if let Ok(i) = obj.extract::<i64>() {
        return Ok(Value::Number(i.into()));
    }
    if let Ok(u) = obj.extract::<u64>() {
        return Ok(Value::Number(u.into()));
    }
    // A Python int too large for i64/u64 must not be taken as a float.
    if let Ok(int_obj) = obj.cast::<PyInt>() {
        let token = int_obj.str()?.to_string();
        if let Ok(n) = token.parse::<Number>() {
            return Ok(Value::Number(n));
        }
    }
    if let Ok(f) = obj.extract::<f64>() {
        return Ok(Number::from_f64(f)
            .map(Value::Number)
            .unwrap_or(Value::Null));
    }
    if let Ok(s) = obj.extract::<String>() {
        return Ok(Value::String(s));
    }
    if let Ok(list) = obj.cast::<PyList>() {
        let mut items = Vec::with_capacity(list.len());
        for item in list.iter() {
            items.push(py_to_json(&item)?);
        }
        return Ok(Value::Array(items));
    }
    if let Ok(tup) = obj.cast::<PyTuple>() {
        let mut items = Vec::with_capacity(tup.len());
        for item in tup.iter() {
            items.push(py_to_json(&item)?);
        }
        return Ok(Value::Array(items));
    }
    if let Ok(dict) = obj.cast::<PyDict>() {
        return Ok(Value::Object(pydict_to_map(dict)?));
    }
    Err(PyValueError::new_err(format!(
        "cannot store a {}",
        obj.get_type().name()?
    )))
}

/// Read `credentials.json`; a missing file is `{}`. Invalid UTF-8 raises
/// `UnicodeDecodeError`. JSON that Python would parse but this parser cannot
/// raises `ValueError`. Other invalid JSON is `{}`.
#[pyfunction]
fn read_fallback(py: Python<'_>, path: PathBuf) -> PyResult<Py<PyAny>> {
    json_to_py(
        py,
        &store::read_fallback_value(&path).map_err(store_op_err)?,
    )
}

/// Write `credentials.json` with mode 0600 and Python's `indent=2` JSON.
#[pyfunction]
fn write_fallback(path: PathBuf, data: Bound<'_, PyDict>) -> PyResult<()> {
    store::write_fallback(&path, &pydict_to_map(&data)?).map_err(io_err)
}

/// Read `credentials_index.json`; a missing or non-list file is `[]`.
#[pyfunction]
fn read_index(path: PathBuf) -> PyResult<Vec<String>> {
    store::read_index(&path).map_err(store_op_err)
}

/// Write `credentials_index.json` (compact JSON, process umask).
#[pyfunction]
fn write_index(path: PathBuf, entries: Vec<String>) -> PyResult<()> {
    store::write_index(&path, &entries).map_err(io_err)
}

/// Append *dns* to the index if it is not already listed.
#[pyfunction]
fn add_to_index(path: PathBuf, dns: &str) -> PyResult<()> {
    store::add_to_index(&path, dns).map_err(store_op_err)
}

/// Remove *dns* from the index if it is listed (idempotent).
#[pyfunction]
fn remove_from_index(path: PathBuf, dns: &str) -> PyResult<()> {
    store::remove_from_index(&path, dns).map_err(store_op_err)
}

/// The file-backend `get`: the entry for *dns*, or `None`.
#[pyfunction]
fn get_fallback(py: Python<'_>, path: PathBuf, dns: &str) -> PyResult<Option<Py<PyDict>>> {
    match store::get_fallback(&path, dns).map_err(store_op_err)? {
        Some(map) => Ok(Some(map_to_py(py, &map)?.unbind())),
        None => Ok(None),
    }
}

/// The file-backend `store`: validate the key and write the entry.
#[pyfunction]
#[pyo3(signature = (path, dns, api_key, name=None, expires_at=None))]
fn store_fallback(
    path: PathBuf,
    dns: &str,
    api_key: &str,
    name: Option<&str>,
    expires_at: Option<i64>,
) -> PyResult<()> {
    store::store_fallback(&path, dns, api_key, name, expires_at).map_err(store_op_err)
}

/// The file-backend `delete` (idempotent).
#[pyfunction]
fn delete_fallback(path: PathBuf, dns: &str) -> PyResult<()> {
    store::delete_fallback(&path, dns).map_err(store_op_err)
}

/// The file-backend `catalog_list`: `(dns, entry)` in file order.
#[pyfunction]
fn list_fallback(py: Python<'_>, path: PathBuf) -> PyResult<Vec<(String, Py<PyDict>)>> {
    let mut out = Vec::new();
    for (dns, entry) in store::list_fallback(&path).map_err(store_op_err)? {
        out.push((dns, map_to_py(py, &entry)?.unbind()));
    }
    Ok(out)
}

#[pymodule]
fn _core(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(core_version, m)?)?;
    m.add_function(wrap_pyfunction!(ping, m)?)?;
    m.add_function(wrap_pyfunction!(normalize_dns, m)?)?;
    m.add_function(wrap_pyfunction!(credentials_file, m)?)?;
    m.add_function(wrap_pyfunction!(credentials_index_file, m)?)?;
    m.add_function(wrap_pyfunction!(keyring_entry, m)?)?;
    m.add_function(wrap_pyfunction!(read_fallback, m)?)?;
    m.add_function(wrap_pyfunction!(write_fallback, m)?)?;
    m.add_function(wrap_pyfunction!(read_index, m)?)?;
    m.add_function(wrap_pyfunction!(write_index, m)?)?;
    m.add_function(wrap_pyfunction!(add_to_index, m)?)?;
    m.add_function(wrap_pyfunction!(remove_from_index, m)?)?;
    m.add_function(wrap_pyfunction!(get_fallback, m)?)?;
    m.add_function(wrap_pyfunction!(store_fallback, m)?)?;
    m.add_function(wrap_pyfunction!(delete_fallback, m)?)?;
    m.add_function(wrap_pyfunction!(list_fallback, m)?)?;
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
