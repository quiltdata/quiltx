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
//! * [`store`]: the 0600 `credentials.json` fallback, the index file, and the
//!   public get/store/delete/list including the OS-keyring path.
//! * [`registry`]: resolve the catalog's registry URL, log in, mint a `qk_`
//!   API key, and validate one. HTTP is an injectable client; production
//!   uses the Python `urllib` helpers so SSL env vars and test patches work.

use std::path::PathBuf;

use pyo3::exceptions::{
    PyAttributeError, PyRuntimeError, PyTypeError, PyUnicodeDecodeError, PyValueError,
};
use pyo3::prelude::*;
use pyo3::types::{PyAny, PyBool, PyDict, PyInt, PyList, PyTuple};
use serde_json::{Map, Number, Value};

pub mod dns;
pub mod paths;
pub mod registry;
pub mod resolve;
pub mod session;
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
        store::StoreOpError::Py(e) => e,
    }
}

fn registry_err(e: registry::RegistryError) -> PyErr {
    match e {
        registry::RegistryError::Auth(msg) => {
            Python::attach(|py| match catalog_auth_error(py, &msg) {
                Ok(err) => err,
                Err(err) => err,
            })
        }
        registry::RegistryError::Py(e) => e,
    }
}

fn catalog_auth_error(py: Python<'_>, msg: &str) -> PyResult<PyErr> {
    let inst = py
        .import("quiltx.auth.registry")?
        .getattr("CatalogAuthError")?
        .call1((msg,))?;
    Ok(PyErr::from_value(inst))
}

fn session_err(e: session::SessionError) -> PyErr {
    match e {
        session::SessionError::Credentials(msg) => {
            Python::attach(|py| match catalog_credentials_error(py, &msg) {
                Ok(err) => err,
                Err(err) => err,
            })
        }
        session::SessionError::Py(e) => e,
    }
}

fn catalog_credentials_error(py: Python<'_>, msg: &str) -> PyResult<PyErr> {
    let inst = py
        .import("quiltx.auth.session")?
        .getattr("CatalogCredentialsError")?
        .call1((msg,))?;
    Ok(PyErr::from_value(inst))
}

fn credential_error(py: Python<'_>, msg: &str) -> PyResult<PyErr> {
    let inst = py
        .import("quiltx.auth.resolve")?
        .getattr("CredentialError")?
        .call1((msg,))?;
    Ok(PyErr::from_value(inst))
}

struct PythonHttp;

impl registry::HttpClient for PythonHttp {
    fn get_json(&self, url: &str) -> Result<serde_json::Value, registry::RegistryError> {
        Python::initialize();
        Python::attach(|py| -> PyResult<serde_json::Value> {
            let obj = py
                .import("quiltx.auth.registry")?
                .getattr("_get_json")?
                .call1((url,))?;
            json_from_response(url, &obj).map_err(registry_err)
        })
        .map_err(registry::RegistryError::Py)
    }

    fn post_json(
        &self,
        url: &str,
        payload: &serde_json::Value,
        bearer: Option<&str>,
    ) -> Result<serde_json::Value, registry::RegistryError> {
        Python::initialize();
        Python::attach(|py| -> PyResult<serde_json::Value> {
            let func = py.import("quiltx.auth.registry")?.getattr("_post_json")?;
            let kwargs = PyDict::new(py);
            if let Some(token) = bearer {
                kwargs.set_item("bearer", token)?;
            }
            let obj = func.call((url, json_to_py(py, payload)?), Some(&kwargs))?;
            json_from_response(url, &obj).map_err(registry_err)
        })
        .map_err(registry::RegistryError::Py)
    }

    fn post_form(
        &self,
        url: &str,
        payload: &serde_json::Map<String, serde_json::Value>,
    ) -> Result<serde_json::Value, registry::RegistryError> {
        Python::initialize();
        Python::attach(|py| -> PyResult<serde_json::Value> {
            let obj = py
                .import("quiltx.auth.registry")?
                .getattr("_post_form")?
                .call1((url, map_to_py(py, payload)?))?;
            json_from_response(url, &obj).map_err(registry_err)
        })
        .map_err(registry::RegistryError::Py)
    }
}

struct SessionHttp;

impl session::HttpClient for SessionHttp {
    fn get_json(&self, url: &str) -> Result<serde_json::Value, session::SessionError> {
        Python::initialize();
        Python::attach(|py| {
            let obj = py
                .import("quiltx.auth.session")
                .and_then(|m| m.getattr("_get_json"))
                .and_then(|f| f.call1((url,)))
                .map_err(session::SessionError::Py)?;
            session_json_from_response(url, &obj)
        })
    }
}

/// Resolve the registry API base URL from ``<catalog_url>/config.json``.
#[pyfunction]
fn resolve_registry_url(catalog_url: &str) -> PyResult<String> {
    registry::resolve_registry_url(catalog_url, &PythonHttp).map_err(registry_err)
}

/// POST username/password to ``<registry_url>/api/login``.
#[pyfunction]
fn acquire_refresh_token(registry_url: &str, username: &str, password: &str) -> PyResult<String> {
    registry::acquire_refresh_token(registry_url, username, password, &PythonHttp)
        .map_err(registry_err)
}

/// Trade a refresh_token for an access_token (form-encoded ``/api/token``).
#[pyfunction]
fn exchange_refresh_token_for_access_token(
    registry_url: &str,
    refresh_token: &str,
) -> PyResult<String> {
    registry::exchange_refresh_token_for_access_token(registry_url, refresh_token, &PythonHttp)
        .map_err(registry_err)
}

/// Mint a ``qk_`` API key via GraphQL ``apiKeyCreate``.
#[pyfunction]
fn create_api_key(
    py: Python<'_>,
    registry_url: &str,
    access_token: &str,
    name: &str,
    expires_in_days: i64,
) -> PyResult<Py<PyDict>> {
    let map = registry::create_api_key(
        registry_url,
        access_token,
        name,
        expires_in_days,
        &PythonHttp,
    )
    .map_err(registry_err)?;
    Ok(map_to_py(py, &map)?.unbind())
}

/// Confirm *api_key* is accepted by the registry (already-resolved URL).
#[pyfunction]
fn validate_api_key(registry_url: &str, api_key: &str) -> PyResult<()> {
    registry::validate_api_key(registry_url, api_key, &PythonHttp).map_err(registry_err)
}

/// Fetch temporary STS credentials from ``<registry_url>/api/auth/get_credentials``.
#[pyfunction]
fn mint_registry_credentials(py: Python<'_>, registry_url: &str) -> PyResult<Py<PyDict>> {
    let map =
        session::mint_registry_credentials(registry_url, &SessionHttp).map_err(session_err)?;
    Ok(map_to_py(py, &map)?.unbind())
}

/// Resolve an API key from already-read flag, env, and store inputs.
#[pyfunction]
#[allow(clippy::too_many_arguments)]
fn resolve_credentials(
    py: Python<'_>,
    dns: &str,
    provided: Option<&str>,
    env_key: Option<&str>,
    stored_key: Option<&str>,
    skip_keyring: bool,
    allow_interactive: bool,
    mode: &str,
) -> PyResult<Py<PyDict>> {
    match resolve::resolve_credentials(
        dns,
        provided,
        env_key,
        stored_key,
        skip_keyring,
        allow_interactive,
        mode,
    ) {
        resolve::ResolveResult::Found { api_key, source } => {
            let dict = PyDict::new(py);
            dict.set_item("status", "found")?;
            dict.set_item("api_key", api_key)?;
            dict.set_item("source", source)?;
            Ok(dict.unbind())
        }
        resolve::ResolveResult::NeedInteractive { rejected } => {
            let dict = PyDict::new(py);
            dict.set_item("status", "need_interactive")?;
            dict.set_item("rejected", rejected)?;
            Ok(dict.unbind())
        }
        resolve::ResolveResult::Error(msg) => {
            Err(Python::attach(|py| match credential_error(py, &msg) {
                Ok(err) => err,
                Err(err) => err,
            }))
        }
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

/// Convert a Python HTTP helper's return value to JSON. A `ValueError`
/// (including a lone surrogate that cannot be represented in Rust) is a
/// bad response, not a bug in the caller: raise `CatalogAuthError`.
fn json_from_response(
    url: &str,
    obj: &Bound<'_, PyAny>,
) -> Result<serde_json::Value, registry::RegistryError> {
    match py_to_json(obj) {
        Ok(value) => Ok(value),
        Err(err) => Python::attach(|py| {
            if err.is_instance_of::<PyValueError>(py) {
                Err(registry::RegistryError::Auth(format!(
                    "Unexpected response from {url}: {err}"
                )))
            } else {
                Err(registry::RegistryError::Py(err))
            }
        }),
    }
}

fn session_json_from_response(
    url: &str,
    obj: &Bound<'_, PyAny>,
) -> Result<serde_json::Value, session::SessionError> {
    match py_to_json(obj) {
        Ok(value) => Ok(value),
        Err(err) => Python::attach(|py| {
            if err.is_instance_of::<PyValueError>(py) {
                Err(session::SessionError::Credentials(format!(
                    "Unexpected response from {url}: {err}"
                )))
            } else {
                Err(session::SessionError::Py(err))
            }
        }),
    }
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

/// The production keyring backend: the Python `keyring` package.
struct PythonKeyring;

impl store::KeyringBackend for PythonKeyring {
    fn get_password(
        &self,
        service: &str,
        username: &str,
    ) -> Result<Option<String>, store::StoreOpError> {
        Python::initialize();
        Python::attach(|py| -> PyResult<Option<String>> {
            let keyring = py.import("keyring")?;
            let value = keyring.call_method1("get_password", (service, username))?;
            if value.is_none() {
                Ok(None)
            } else if let Ok(text) = value.extract::<String>() {
                Ok(Some(text))
            } else {
                let raw: Vec<u8> = value.extract()?;
                match String::from_utf8(raw) {
                    Ok(text) => Ok(Some(text)),
                    Err(err) => {
                        let raw = err.into_bytes();
                        let end = raw.len();
                        Err(PyUnicodeDecodeError::new_err((
                            "utf-8",
                            raw,
                            0,
                            end,
                            "invalid utf-8 in keyring entry",
                        )))
                    }
                }
            }
        })
        .map_err(store::StoreOpError::Py)
    }

    fn set_password(
        &self,
        service: &str,
        username: &str,
        password: &str,
    ) -> Result<(), store::StoreOpError> {
        Python::initialize();
        Python::attach(|py| -> PyResult<()> {
            py.import("keyring")?
                .call_method1("set_password", (service, username, password))?;
            Ok(())
        })
        .map_err(store::StoreOpError::Py)
    }

    fn delete_password(&self, service: &str, username: &str) -> Result<(), store::StoreOpError> {
        Python::initialize();
        Python::attach(|py| -> PyResult<()> {
            let keyring = py.import("keyring")?;
            match keyring.call_method1("delete_password", (service, username)) {
                Ok(_) => Ok(()),
                Err(err) => {
                    let typ = py
                        .import("keyring.errors")?
                        .getattr("PasswordDeleteError")?;
                    if err.is_instance(py, &typ) {
                        Ok(())
                    } else {
                        Err(err)
                    }
                }
            }
        })
        .map_err(store::StoreOpError::Py)
    }
}

/// Public `get`: OS keyring or the file fallback, chosen by *use_keyring*.
#[pyfunction]
fn get_credential(
    py: Python<'_>,
    dns: &str,
    use_keyring: bool,
    fallback_path: PathBuf,
) -> PyResult<Option<Py<PyDict>>> {
    match store::get_credential(dns, use_keyring, &fallback_path, &PythonKeyring)
        .map_err(store_op_err)?
    {
        Some(map) => Ok(Some(map_to_py(py, &map)?.unbind())),
        None => Ok(None),
    }
}

/// Public `store`.
#[pyfunction]
#[pyo3(signature = (dns, api_key, name, expires_at, use_keyring, fallback_path, index_path))]
fn store_credential(
    dns: &str,
    api_key: &str,
    name: Option<&str>,
    expires_at: Option<i64>,
    use_keyring: bool,
    fallback_path: PathBuf,
    index_path: PathBuf,
) -> PyResult<()> {
    store::store_credential(
        dns,
        api_key,
        name,
        expires_at,
        use_keyring,
        &fallback_path,
        &index_path,
        &PythonKeyring,
    )
    .map_err(store_op_err)
}

/// Public `delete` (idempotent).
#[pyfunction]
fn delete_credential(
    dns: &str,
    use_keyring: bool,
    fallback_path: PathBuf,
    index_path: PathBuf,
) -> PyResult<()> {
    store::delete_credential(
        dns,
        use_keyring,
        &fallback_path,
        &index_path,
        &PythonKeyring,
    )
    .map_err(store_op_err)
}

/// Public `catalog_list`.
#[pyfunction]
fn list_credentials(
    py: Python<'_>,
    use_keyring: bool,
    fallback_path: PathBuf,
    index_path: PathBuf,
) -> PyResult<Vec<(String, Py<PyDict>)>> {
    let mut out = Vec::new();
    for (dns, entry) in
        store::list_credentials(use_keyring, &fallback_path, &index_path, &PythonKeyring)
            .map_err(store_op_err)?
    {
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
    m.add_function(wrap_pyfunction!(get_credential, m)?)?;
    m.add_function(wrap_pyfunction!(store_credential, m)?)?;
    m.add_function(wrap_pyfunction!(delete_credential, m)?)?;
    m.add_function(wrap_pyfunction!(list_credentials, m)?)?;
    m.add_function(wrap_pyfunction!(resolve_registry_url, m)?)?;
    m.add_function(wrap_pyfunction!(acquire_refresh_token, m)?)?;
    m.add_function(wrap_pyfunction!(
        exchange_refresh_token_for_access_token,
        m
    )?)?;
    m.add_function(wrap_pyfunction!(create_api_key, m)?)?;
    m.add_function(wrap_pyfunction!(validate_api_key, m)?)?;
    m.add_function(wrap_pyfunction!(mint_registry_credentials, m)?)?;
    m.add_function(wrap_pyfunction!(resolve_credentials, m)?)?;
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
