//! File-backed credential store: `credentials.json` (mode 0600) and
//! `credentials_index.json`.
//!
//! A port of the Python in `quiltx.auth.store` (`_read_fallback` /
//! `_write_fallback` / `_read_index` / `_write_index` / `_add_to_index` /
//! `_remove_from_index`, and the file-backend half of `get` / `store` /
//! `delete` / `catalog_list`). The OS keyring backend stays in Python. The
//! replaced functions live in `tests/oracle.py` for the parity tests.
//!
//! Writes match the Python byte for byte (`json.dumps` with `ensure_ascii` and,
//! for the fallback file, `indent=2`) and the same directory and file modes:
//! the fallback file is 0600, its parent directory is 0700, and the index is
//! written with the process umask (Python's `Path.write_text`). Writes go to a
//! temp file in the same directory and are renamed into place. On Windows the
//! files use CRLF, as Python's text-mode writes did.
//!
//! A missing file, or invalid JSON that Python's `json.loads` already treated
//! as empty, still reads as empty. A file that exists but is invalid UTF-8, or
//! that Python's `json.loads` would accept but this parser cannot (`NaN`/
//! `Infinity`, a lone surrogate, nesting deeper than 128), raises so a later
//! write cannot replace it. That decision is made by calling `json.loads`, not
//! by matching parser error strings. Out-of-range floats and large integers
//! are read.

#[cfg(unix)]
use std::fs::File;
use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
#[cfg(windows)]
use std::time::Duration;
use std::time::{SystemTime, UNIX_EPOCH};

use pyo3::prelude::*;

use crate::paths;
use serde_json::{Map, Number, Value};

/// Why an API key was refused; the message is Python's `ValueError`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoreError(pub String);

/// A file-store operation failed by validation or I/O.
#[derive(Debug)]
pub enum StoreOpError {
    Validation(StoreError),
    Io(io::Error),
    /// Python `AttributeError`: "'{typ}' object has no attribute '{attr}'".
    Attribute {
        typ: &'static str,
        attr: &'static str,
    },
    /// Python `TypeError` message.
    Type(String),
    /// Invalid UTF-8 in a file that exists; mapped to `UnicodeDecodeError`.
    Utf8(std::string::FromUtf8Error),
    /// JSON that Python's `json.loads` would accept but this parser cannot.
    Value(String),
    /// A Python exception from the `keyring` package, re-raised as-is.
    Py(PyErr),
}

impl From<StoreError> for StoreOpError {
    fn from(e: StoreError) -> Self {
        StoreOpError::Validation(e)
    }
}

impl From<io::Error> for StoreOpError {
    fn from(e: io::Error) -> Self {
        StoreOpError::Io(e)
    }
}

/// Python's `str.isspace()` for one character, same set as `dns::is_py_space`.
fn is_py_space(c: char) -> bool {
    matches!(
        c,
        '\u{9}'..='\u{d}'
            | '\u{1c}'..='\u{20}'
            | '\u{85}'
            | '\u{a0}'
            | '\u{1680}'
            | '\u{2000}'..='\u{200a}'
            | '\u{2028}'
            | '\u{2029}'
            | '\u{202f}'
            | '\u{205f}'
            | '\u{3000}'
    )
}

/// Python's `str.strip()` with no argument.
fn py_strip(s: &str) -> &str {
    s.trim_matches(is_py_space)
}

/// The JSON object stored for one catalog, after the `qk_` checks.
pub fn credential_payload(
    api_key: &str,
    name: Option<&str>,
    expires_at: Option<i64>,
) -> Result<Map<String, Value>, StoreError> {
    let api_key = py_strip(api_key);
    if api_key.is_empty() {
        return Err(StoreError("API key is empty".into()));
    }
    if !api_key.starts_with("qk_") {
        return Err(StoreError(
            "API key does not start with 'qk_'. Quilt API keys begin with \
             'qk_' — paste the secret shown after creating a key in the \
             catalog UI under Profile → API Keys."
                .into(),
        ));
    }
    let mut payload = Map::new();
    payload.insert("api_key".into(), Value::String(api_key.to_string()));
    payload.insert(
        "name".into(),
        match name {
            Some(n) => Value::String(n.to_string()),
            None => Value::Null,
        },
    );
    payload.insert(
        "expires_at".into(),
        match expires_at {
            Some(ts) => Value::Number(ts.into()),
            None => Value::Null,
        },
    );
    Ok(payload)
}

/// Parsed `credentials.json`. A missing file, or invalid JSON that Python
/// already treated as empty, is `{}`. Valid JSON that is not an object (for
/// example `[]`) is returned as-is, as Python's `json.loads` did.
pub fn read_fallback_value(path: &Path) -> Result<Value, StoreOpError> {
    match read_json(path)? {
        Some(value) => Ok(value),
        None => Ok(Value::Object(Map::new())),
    }
}

/// The mapping in `credentials.json`, or `{}` if the file is missing, was
/// invalid JSON that Python treated as empty, or is not an object. Prefer
/// [`as_mapping`] when the Python would raise `AttributeError` on a non-dict.
pub fn read_fallback(path: &Path) -> Result<Map<String, Value>, StoreOpError> {
    match read_fallback_value(path)? {
        Value::Object(map) => Ok(map),
        _ => Ok(Map::new()),
    }
}

fn json_type_name(value: &Value) -> &'static str {
    match value {
        Value::Null => "NoneType",
        Value::Bool(_) => "bool",
        Value::Number(n) if n.is_i64() || n.is_u64() => "int",
        Value::Number(_) => "float",
        Value::String(_) => "str",
        Value::Array(_) => "list",
        Value::Object(_) => "dict",
    }
}

/// The object in a fallback file, or `AttributeError` if it is some other JSON.
pub fn as_mapping(path: &Path, attr: &'static str) -> Result<Map<String, Value>, StoreOpError> {
    let value = read_fallback_value(path)?;
    match value {
        Value::Object(map) => Ok(map),
        other => Err(StoreOpError::Attribute {
            typ: json_type_name(&other),
            attr,
        }),
    }
}

fn assign_mapping(path: &Path) -> Result<Map<String, Value>, StoreOpError> {
    let value = read_fallback_value(path)?;
    match value {
        Value::Object(map) => Ok(map),
        Value::Array(_) => Err(StoreOpError::Type(
            "list indices must be integers or slices, not str".into(),
        )),
        other => Err(StoreOpError::Type(format!(
            "'{}' object does not support item assignment",
            json_type_name(&other)
        ))),
    }
}

/// Write `credentials.json` with `indent=2` and mode 0600.
pub fn write_fallback(path: &Path, data: &Map<String, Value>) -> io::Result<()> {
    let bytes = dumps(&Value::Object(data.clone()), Some(2)).into_bytes();
    write_private(path, &bytes)
}

/// Read `credentials_index.json`; a missing file, invalid JSON that Python
/// treated as empty, or a non-list is `[]`. Non-string list elements are dropped.
pub fn read_index(path: &Path) -> Result<Vec<String>, StoreOpError> {
    match read_json(path)? {
        Some(Value::Array(items)) => Ok(items
            .into_iter()
            .filter_map(|v| v.as_str().map(str::to_string))
            .collect()),
        _ => Ok(Vec::new()),
    }
}

/// Write `credentials_index.json` compactly, at the process umask (not 0600).
pub fn write_index(path: &Path, entries: &[String]) -> io::Result<()> {
    let values: Vec<Value> = entries.iter().map(|s| Value::String(s.clone())).collect();
    let bytes = dumps(&Value::Array(values), None).into_bytes();
    write_index_file(path, &bytes)
}

/// Append *dns* to the index if it is not already present.
pub fn add_to_index(path: &Path, dns: &str) -> Result<(), StoreOpError> {
    let mut entries = read_index(path)?;
    if !entries.iter().any(|e| e == dns) {
        entries.push(dns.to_string());
        write_index(path, &entries)?;
    }
    Ok(())
}

/// Remove the first occurrence of *dns* from the index, if any.
pub fn remove_from_index(path: &Path, dns: &str) -> Result<(), StoreOpError> {
    let mut entries = read_index(path)?;
    if let Some(i) = entries.iter().position(|e| e == dns) {
        entries.remove(i);
        write_index(path, &entries)?;
    }
    Ok(())
}

/// Return the entry for *dns*, or `None` if it is missing or has no `api_key`.
///
/// A top-level JSON value that is not an object raises the same `AttributeError`
/// Python raised (`.get` on a non-dict).
pub fn get_fallback(path: &Path, dns: &str) -> Result<Option<Map<String, Value>>, StoreOpError> {
    Ok(entry_if_api_key(as_mapping(path, "get")?.get(dns)))
}

/// Validate *api_key* and write the entry for *dns* into the fallback file.
pub fn store_fallback(
    path: &Path,
    dns: &str,
    api_key: &str,
    name: Option<&str>,
    expires_at: Option<i64>,
) -> Result<(), StoreOpError> {
    let payload = credential_payload(api_key, name, expires_at)?;
    let mut data = assign_mapping(path)?;
    data.insert(dns.to_string(), Value::Object(payload));
    write_fallback(path, &data)?;
    Ok(())
}

/// Delete *dns* from the fallback file (idempotent; no write if it is absent).
pub fn delete_fallback(path: &Path, dns: &str) -> Result<(), StoreOpError> {
    let mut data = read_fallback(path)?;
    if data.remove(dns).is_some() {
        write_fallback(path, &data)?;
    }
    Ok(())
}

/// One `(dns, entry)` row from the fallback file.
pub type FallbackEntry = (String, Map<String, Value>);

/// Entries that have an `api_key`, in file order.
pub fn list_fallback(path: &Path) -> Result<Vec<FallbackEntry>, StoreOpError> {
    Ok(as_mapping(path, "items")?
        .into_iter()
        .filter_map(|(dns, value)| entry_if_api_key(Some(&value)).map(|entry| (dns, entry)))
        .collect())
}

/// The OS keyring operations used by [`get_credential`] and friends.
///
/// The production backend is the Python `keyring` package (so existing
/// entries and tests that patch `keyring.get_password` keep working).
pub trait KeyringBackend {
    fn get_password(&self, service: &str, username: &str) -> Result<Option<String>, StoreOpError>;
    fn set_password(
        &self,
        service: &str,
        username: &str,
        password: &str,
    ) -> Result<(), StoreOpError>;
    fn delete_password(&self, service: &str, username: &str) -> Result<(), StoreOpError>;
}

/// Public `get`: keyring or the 0600 file, chosen by *use_keyring*.
pub fn get_credential(
    dns: &str,
    use_keyring: bool,
    fallback_path: &Path,
    keyring: &dyn KeyringBackend,
) -> Result<Option<Map<String, Value>>, StoreOpError> {
    if use_keyring {
        get_keyring(dns, keyring)
    } else {
        get_fallback(fallback_path, dns)
    }
}

/// Public `store`: validate the key, then write to the keyring (and index)
/// or the file fallback.
#[allow(clippy::too_many_arguments)]
pub fn store_credential(
    dns: &str,
    api_key: &str,
    name: Option<&str>,
    expires_at: Option<i64>,
    use_keyring: bool,
    fallback_path: &Path,
    index_path: &Path,
    keyring: &dyn KeyringBackend,
) -> Result<(), StoreOpError> {
    if use_keyring {
        let payload = credential_payload(api_key, name, expires_at)?;
        let serialized = dumps(&Value::Object(payload), None);
        let (service, username) = paths::keyring_entry(dns);
        keyring.set_password(service, &username, &serialized)?;
        add_to_index(index_path, dns)?;
        Ok(())
    } else {
        store_fallback(fallback_path, dns, api_key, name, expires_at)
    }
}

/// Public `delete` (idempotent).
pub fn delete_credential(
    dns: &str,
    use_keyring: bool,
    fallback_path: &Path,
    index_path: &Path,
    keyring: &dyn KeyringBackend,
) -> Result<(), StoreOpError> {
    if use_keyring {
        let (service, username) = paths::keyring_entry(dns);
        keyring.delete_password(service, &username)?;
        remove_from_index(index_path, dns)?;
        Ok(())
    } else {
        delete_fallback(fallback_path, dns)
    }
}

/// Public `catalog_list`.
pub fn list_credentials(
    use_keyring: bool,
    fallback_path: &Path,
    index_path: &Path,
    keyring: &dyn KeyringBackend,
) -> Result<Vec<FallbackEntry>, StoreOpError> {
    if use_keyring {
        let mut results = Vec::new();
        for dns in read_index(index_path)? {
            match get_keyring(&dns, keyring) {
                Ok(Some(entry)) => results.push((dns, entry)),
                Ok(None) => {}
                Err(StoreOpError::Value(_)) => {
                    // Skip a corrupt entry so one bad catalog does not hide the
                    // rest; get still raises, so a later store cannot silently
                    // replace it.
                    eprintln!(
                        "WARNING: skipping corrupt keyring entry for {dns}; run `quiltx catalog login --catalog {dns}` or `quiltx catalog forget {dns}`."
                    );
                }
                Err(err) => return Err(err),
            }
        }
        Ok(results)
    } else {
        list_fallback(fallback_path)
    }
}

fn corrupt_keyring_error(dns: &str) -> StoreOpError {
    StoreOpError::Value(format!(
        "keyring entry for {dns} is not valid JSON; run `quiltx catalog login --catalog {dns}` or `quiltx catalog forget {dns}`"
    ))
}

fn get_keyring(
    dns: &str,
    keyring: &dyn KeyringBackend,
) -> Result<Option<Map<String, Value>>, StoreOpError> {
    let (service, username) = paths::keyring_entry(dns);
    let Some(raw) = keyring.get_password(service, &username)? else {
        return Ok(None);
    };
    // A corrupt entry must raise, not look missing: the old Python returned
    // None on `JSONDecodeError`, and a later `store` would replace it.
    let value = match parse_json_text(&raw) {
        Ok(Some(value)) => value,
        Ok(None) | Err(StoreOpError::Value(_)) => {
            return Err(corrupt_keyring_error(dns));
        }
        Err(err) => return Err(err),
    };
    Ok(entry_if_api_key(Some(&value)))
}

fn entry_if_api_key(value: Option<&Value>) -> Option<Map<String, Value>> {
    match value {
        Some(Value::Object(map)) if map.contains_key("api_key") => Some(map.clone()),
        _ => None,
    }
}

/// `Ok(None)` is a missing file, or invalid JSON that Python's `json.loads`
/// would reject (`JSONDecodeError` → empty). Anything else that cannot be
/// parsed is an error, so a later write cannot replace the file.
fn read_json(path: &Path) -> Result<Option<Value>, StoreOpError> {
    let bytes = match fs::read(path) {
        Ok(bytes) => bytes,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e.into()),
    };
    let text = String::from_utf8(bytes).map_err(StoreOpError::Utf8)?;
    parse_json_text(&text)
}

fn parse_json_text(text: &str) -> Result<Option<Value>, StoreOpError> {
    match serde_json::from_str(text) {
        Ok(value) => Ok(Some(value)),
        Err(e) => {
            if python_json_loads_ok(text)? {
                Err(StoreOpError::Value(e.to_string()))
            } else {
                Ok(None)
            }
        }
    }
}

/// Whether Python's `json.loads` would accept *text*. `JSONDecodeError` is
/// "reject" (the oracle then returns empty); any other failure is an error.
fn python_json_loads_ok(text: &str) -> Result<bool, StoreOpError> {
    // Idempotent: a no-op when this is called from a loaded extension, and
    // required when `cargo test` embeds Python.
    Python::initialize();
    Python::attach(|py| -> PyResult<bool> {
        let json = py.import("json")?;
        match json.getattr("loads")?.call1((text,)) {
            Ok(_) => Ok(true),
            Err(err) => {
                let decode_error = json.getattr("JSONDecodeError")?;
                if err.is_instance(py, &decode_error) {
                    Ok(false)
                } else {
                    Err(err)
                }
            }
        }
    })
    .map_err(|e| StoreOpError::Value(e.to_string()))
}

/// Python on Windows opens these files in text mode (`os.open` without
/// `O_BINARY`, and `Path.write_text`), so `\n` is stored as CRLF. Match that
/// so a rewrite does not change a file Python already wrote.
fn with_python_newlines(bytes: &[u8]) -> Vec<u8> {
    if cfg!(windows) {
        let mut out = Vec::with_capacity(bytes.len());
        for &b in bytes {
            if b == b'\n' {
                out.push(b'\r');
            }
            out.push(b);
        }
        out
    } else {
        bytes.to_vec()
    }
}

/// Create the immediate parent at 0700 (grandparents use the default mode),
/// then write *bytes* to a temp file at 0600 and rename over *path*.
fn write_private(path: &Path, bytes: &[u8]) -> io::Result<()> {
    write_atomic(path, bytes, true)
}

/// `Path.write_text`: same parent-directory rules, file mode from the umask,
/// temp file plus rename.
fn write_index_file(path: &Path, bytes: &[u8]) -> io::Result<()> {
    write_atomic(path, bytes, false)
}

fn write_atomic(path: &Path, bytes: &[u8], private: bool) -> io::Result<()> {
    ensure_parent(path)?;
    let tmp = tmp_sibling(path);
    let result = (|| {
        {
            let mut opts = OpenOptions::new();
            opts.write(true).create_new(true);
            if private {
                #[cfg(unix)]
                {
                    use std::os::unix::fs::OpenOptionsExt;
                    opts.mode(0o600);
                }
            }
            let mut file = opts.open(&tmp)?;
            file.write_all(&with_python_newlines(bytes))?;
            file.sync_all()?;
            drop(file);
        }
        if private {
            let _ = chmod(&tmp, 0o600);
        }
        persist_tmp(&tmp, path)?;
        // Directory fsync is best-effort so a later chmod still runs.
        let _ = sync_parent(path);
        if private {
            let _ = chmod(path, 0o600);
        }
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&tmp);
    }
    result
}

fn tmp_sibling(path: &Path) -> PathBuf {
    static SEQ: AtomicU64 = AtomicU64::new(0);
    let seq = SEQ.fetch_add(1, Ordering::Relaxed);
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| "file".into());
    path.with_file_name(format!(
        ".{}.{}.{}.{}.tmp",
        name,
        std::process::id(),
        nanos,
        seq
    ))
}

fn persist_tmp(tmp: &Path, dest: &Path) -> io::Result<()> {
    // `fs::rename` replaces the destination on Windows (no delete first: a
    // failed replace must not drop the existing file).
    #[cfg(windows)]
    {
        const SHARING_VIOLATION: i32 = 32;
        const ACCESS_DENIED: i32 = 5;
        let mut delay = Duration::from_millis(10);
        for attempt in 0..5 {
            match fs::rename(tmp, dest) {
                Ok(()) => return Ok(()),
                Err(e)
                    if attempt < 4
                        && matches!(e.raw_os_error(), Some(SHARING_VIOLATION | ACCESS_DENIED)) =>
                {
                    std::thread::sleep(delay);
                    delay *= 2;
                }
                Err(e) => return Err(e),
            }
        }
        unreachable!("loop always returns")
    }
    #[cfg(not(windows))]
    fs::rename(tmp, dest)
}

fn sync_parent(path: &Path) -> io::Result<()> {
    #[cfg(unix)]
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            let _ = File::open(parent).and_then(|f| f.sync_all());
        }
    }
    let _ = path;
    Ok(())
}

fn ensure_parent(path: &Path) -> io::Result<()> {
    let Some(parent) = path.parent() else {
        return Ok(());
    };
    if parent.as_os_str().is_empty() || parent == Path::new(".") {
        return Ok(());
    }
    if !parent.exists() {
        if let Some(grand) = parent.parent() {
            if !grand.as_os_str().is_empty() && grand != Path::new(".") && !grand.exists() {
                fs::create_dir_all(grand)?;
            }
        }
        mkdir_mode(parent, 0o700)?;
    }
    let _ = chmod(parent, 0o700);
    Ok(())
}

fn mkdir_mode(path: &Path, mode: u32) -> io::Result<()> {
    match mkdir_mode_inner(path, mode) {
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists && path.is_dir() => Ok(()),
        other => other,
    }
}

#[cfg(unix)]
fn mkdir_mode_inner(path: &Path, mode: u32) -> io::Result<()> {
    use std::os::unix::fs::DirBuilderExt;
    fs::DirBuilder::new().mode(mode).create(path)
}

#[cfg(not(unix))]
fn mkdir_mode_inner(path: &Path, _mode: u32) -> io::Result<()> {
    fs::create_dir(path)
}

fn chmod(path: &Path, mode: u32) -> io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(mode))
    }
    #[cfg(not(unix))]
    {
        let _ = (path, mode);
        Ok(())
    }
}

/// `json.dumps(value)` (`ensure_ascii=True`), with `indent` if given.
pub fn dumps(value: &Value, indent: Option<usize>) -> String {
    let mut out = String::new();
    write_value(&mut out, value, indent, 0);
    out
}

fn write_value(out: &mut String, value: &Value, indent: Option<usize>, level: usize) {
    match value {
        Value::Null => out.push_str("null"),
        Value::Bool(true) => out.push_str("true"),
        Value::Bool(false) => out.push_str("false"),
        Value::Number(n) => write_number(out, n),
        Value::String(s) => write_string(out, s),
        Value::Array(items) => write_array(out, items, indent, level),
        Value::Object(map) => write_object(out, map, indent, level),
    }
}

fn write_number(out: &mut String, n: &Number) {
    if let Some(i) = n.as_i64() {
        out.push_str(&i.to_string());
    } else if let Some(u) = n.as_u64() {
        out.push_str(&u.to_string());
    } else if number_is_integer(n) {
        out.push_str(&n.to_string());
    } else if let Some(f) = n.as_f64().filter(|f| f.is_finite()) {
        out.push_str(&python_float(f));
    } else {
        // Keep the original token for out-of-range values such as `1e400`, so
        // a rewrite stays readable (`Infinity` cannot live in `Value`).
        out.push_str(&n.to_string());
    }
}

/// A JSON number token with no decimal point or exponent, e.g. a 400-digit int.
pub(crate) fn number_is_integer(n: &Number) -> bool {
    let s = n.to_string();
    let digits = s.strip_prefix('-').unwrap_or(&s);
    !digits.is_empty() && digits.bytes().all(|b| b.is_ascii_digit())
}

/// Python `json.loads` overflow: `1e400` becomes `inf`.
pub(crate) fn number_as_python_float(n: &Number) -> Option<f64> {
    n.as_f64().or_else(|| n.to_string().parse().ok())
}

/// Close enough to `json.dumps` for the floats a credentials file might hold.
fn python_float(f: f64) -> String {
    if f.is_nan() {
        return "NaN".into();
    }
    if f.is_infinite() {
        return if f.is_sign_positive() {
            "Infinity"
        } else {
            "-Infinity"
        }
        .into();
    }
    // `json.dumps(1.0)` is `1.0`; `json.dumps(1e-7)` is `1e-07`.
    // Debug format of a finite f64 is close to Python's `repr`, which json.dumps uses.
    let s = format!("{f:?}");
    if s.contains('.') || s.contains('e') || s.contains('E') {
        s
    } else {
        format!("{s}.0")
    }
}

fn write_string(out: &mut String, s: &str) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\u{08}' => out.push_str("\\b"),
            '\u{0c}' => out.push_str("\\f"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 || c == '\u{7f}' => {
                out.push_str(&format!("\\u{:04x}", c as u32));
            }
            c if (c as u32) < 0x80 => out.push(c),
            c => {
                let mut buf = [0u16; 2];
                for unit in c.encode_utf16(&mut buf) {
                    out.push_str(&format!("\\u{:04x}", *unit));
                }
            }
        }
    }
    out.push('"');
}

fn write_object(out: &mut String, map: &Map<String, Value>, indent: Option<usize>, level: usize) {
    if map.is_empty() {
        out.push_str("{}");
        return;
    }
    out.push('{');
    if let Some(n) = indent {
        let inner = level + 1;
        let mut first = true;
        for (k, v) in map {
            if !first {
                out.push(',');
            }
            first = false;
            out.push('\n');
            push_indent(out, n * inner);
            write_string(out, k);
            out.push_str(": ");
            write_value(out, v, indent, inner);
        }
        out.push('\n');
        push_indent(out, n * level);
        out.push('}');
    } else {
        let mut first = true;
        for (k, v) in map {
            if !first {
                out.push_str(", ");
            }
            first = false;
            write_string(out, k);
            out.push_str(": ");
            write_value(out, v, indent, level);
        }
        out.push('}');
    }
}

fn write_array(out: &mut String, items: &[Value], indent: Option<usize>, level: usize) {
    if items.is_empty() {
        out.push_str("[]");
        return;
    }
    out.push('[');
    if let Some(n) = indent {
        let inner = level + 1;
        let mut first = true;
        for v in items {
            if !first {
                out.push(',');
            }
            first = false;
            out.push('\n');
            push_indent(out, n * inner);
            write_value(out, v, indent, inner);
        }
        out.push('\n');
        push_indent(out, n * level);
        out.push(']');
    } else {
        let mut first = true;
        for v in items {
            if !first {
                out.push_str(", ");
            }
            first = false;
            write_value(out, v, indent, level);
        }
        out.push(']');
    }
}

fn push_indent(out: &mut String, n: usize) {
    for _ in 0..n {
        out.push(' ');
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    fn scratch(name: &str) -> PathBuf {
        static SEQ: AtomicU64 = AtomicU64::new(0);
        let dir = std::env::temp_dir().join(format!(
            "quiltx-store-{}-{}-{}",
            std::process::id(),
            SEQ.fetch_add(1, Ordering::Relaxed),
            name
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn cleanup(dir: &Path) {
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn dumps_matches_python_indent_and_ascii() {
        let mut inner = Map::new();
        inner.insert("api_key".into(), Value::String("qk_abc".into()));
        inner.insert("name".into(), Value::Null);
        inner.insert("expires_at".into(), Value::Null);
        let mut data = Map::new();
        data.insert("nightly.quilttest.com".into(), Value::Object(inner));
        let got = dumps(&Value::Object(data), Some(2));
        let want = "{\n  \"nightly.quilttest.com\": {\n    \"api_key\": \"qk_abc\",\n    \"name\": null,\n    \"expires_at\": null\n  }\n}";
        assert_eq!(got, want);
    }

    #[test]
    fn dumps_escapes_non_ascii_as_python_does() {
        assert_eq!(
            dumps(&Value::String("naïve 😀".into()), None),
            "\"na\\u00efve \\ud83d\\ude00\""
        );
        assert_eq!(
            dumps(&Value::String("\u{00}\u{1f} \u{7f}".into()), None),
            "\"\\u0000\\u001f \\u007f\""
        );
    }

    #[test]
    fn dumps_index_is_compact() {
        let items = vec![
            Value::String("a.example.com".into()),
            Value::String("b.example.com".into()),
        ];
        assert_eq!(
            dumps(&Value::Array(items), None),
            "[\"a.example.com\", \"b.example.com\"]"
        );
        assert_eq!(dumps(&Value::Array(vec![]), None), "[]");
    }

    #[test]
    fn empty_key_and_missing_prefix_are_value_errors() {
        assert_eq!(
            credential_payload("  ", None, None).unwrap_err().0,
            "API key is empty"
        );
        assert_eq!(
            credential_payload("", None, None).unwrap_err().0,
            "API key is empty"
        );
        let err = credential_payload("not-a-key", None, None).unwrap_err().0;
        assert!(err.contains("does not start with 'qk_'"), "{err}");
    }

    #[test]
    fn store_get_delete_round_trip() {
        let dir = scratch("round");
        let path = dir.join("credentials.json");
        store_fallback(&path, "a.example.com", "qk_a", Some("alice"), Some(9)).unwrap();
        store_fallback(&path, "b.example.com", "  qk_b  ", None, None).unwrap();
        let a = get_fallback(&path, "a.example.com").unwrap().unwrap();
        assert_eq!(a.get("api_key"), Some(&Value::String("qk_a".into())));
        assert_eq!(a.get("name"), Some(&Value::String("alice".into())));
        assert_eq!(a.get("expires_at"), Some(&Value::Number(9.into())));
        assert_eq!(
            get_fallback(&path, "b.example.com")
                .unwrap()
                .unwrap()
                .get("api_key"),
            Some(&Value::String("qk_b".into()))
        );
        let listed: Vec<String> = list_fallback(&path)
            .unwrap()
            .into_iter()
            .map(|(d, _)| d)
            .collect();
        assert_eq!(listed, ["a.example.com", "b.example.com"]);
        delete_fallback(&path, "a.example.com").unwrap();
        assert!(get_fallback(&path, "a.example.com").unwrap().is_none());
        delete_fallback(&path, "a.example.com").unwrap();
        cleanup(&dir);
    }

    #[test]
    fn missing_or_malformed_or_legacy_entries_read_as_empty() {
        let dir = scratch("empty");
        let path = dir.join("credentials.json");
        assert!(get_fallback(&path, "x").unwrap().is_none());
        assert!(list_fallback(&path).unwrap().is_empty());
        fs::write(&path, "not-json").unwrap();
        assert!(get_fallback(&path, "x").unwrap().is_none());
        fs::write(&path, "[]").unwrap();
        match get_fallback(&path, "x") {
            Err(StoreOpError::Attribute {
                typ: "list",
                attr: "get",
            }) => {}
            other => panic!("expected AttributeError on a list file, got {other:?}"),
        }
        fs::write(
            &path,
            r#"{"old.example.com": {"username": "u", "secret": "s"}}"#,
        )
        .unwrap();
        assert!(get_fallback(&path, "old.example.com").unwrap().is_none());
        assert!(list_fallback(&path).unwrap().is_empty());
        cleanup(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn fallback_file_and_parent_have_private_modes() {
        let dir = scratch("modes");
        let nested = dir.join("data");
        let path = nested.join("credentials.json");
        store_fallback(&path, "a.example.com", "qk_a", None, None).unwrap();
        use std::os::unix::fs::PermissionsExt;
        let file_mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        let dir_mode = fs::metadata(&nested).unwrap().permissions().mode() & 0o777;
        assert_eq!(file_mode, 0o600, "file {file_mode:o}");
        assert_eq!(dir_mode, 0o700, "dir {dir_mode:o}");
        cleanup(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn a_preexisting_looser_file_is_tightened() {
        let dir = scratch("loosen");
        let path = dir.join("credentials.json");
        fs::write(&path, b"{}").unwrap();
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        store_fallback(&path, "a.example.com", "qk_a", None, None).unwrap();
        let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
        cleanup(&dir);
    }

    #[test]
    fn index_add_and_remove_are_idempotent_and_preserve_order() {
        let dir = scratch("index");
        let path = dir.join("credentials_index.json");
        assert!(read_index(&path).unwrap().is_empty());
        add_to_index(&path, "a.example.com").unwrap();
        add_to_index(&path, "b.example.com").unwrap();
        add_to_index(&path, "a.example.com").unwrap();
        assert_eq!(
            read_index(&path).unwrap(),
            ["a.example.com", "b.example.com"]
        );
        assert_eq!(
            fs::read_to_string(&path).unwrap(),
            "[\"a.example.com\", \"b.example.com\"]"
        );
        remove_from_index(&path, "a.example.com").unwrap();
        remove_from_index(&path, "a.example.com").unwrap();
        assert_eq!(read_index(&path).unwrap(), ["b.example.com"]);
        fs::write(&path, "{}").unwrap();
        assert!(read_index(&path).unwrap().is_empty());
        cleanup(&dir);
    }

    #[test]
    fn store_writes_python_shaped_bytes() {
        let dir = scratch("bytes");
        let path = dir.join("credentials.json");
        store_fallback(&path, "nightly.quilttest.com", "qk_abc", None, None).unwrap();
        let got = fs::read(&path).unwrap();
        let want = super::with_python_newlines(
            b"{\n  \"nightly.quilttest.com\": {\n    \"api_key\": \"qk_abc\",\n    \"name\": null,\n    \"expires_at\": null\n  }\n}",
        );
        assert_eq!(got, want);
        cleanup(&dir);
    }

    #[test]
    fn python_newlines_match_text_mode() {
        let input = b"{\n  \"a\": 1\n}";
        let got = super::with_python_newlines(input);
        if cfg!(windows) {
            assert_eq!(got, b"{\r\n  \"a\": 1\r\n}");
        } else {
            assert_eq!(got, input);
        }
    }

    #[test]
    fn invalid_utf8_raises_and_does_not_overwrite() {
        let dir = scratch("utf8");
        let path = dir.join("credentials.json");
        let body = b"{\"keep\": 1, \"x\": \"\xff\"}";
        fs::write(&path, body).unwrap();
        assert!(matches!(
            read_fallback_value(&path),
            Err(StoreOpError::Utf8(_))
        ));
        assert!(matches!(
            store_fallback(&path, "x.example.com", "qk_x", None, None),
            Err(StoreOpError::Utf8(_))
        ));
        assert!(matches!(
            delete_fallback(&path, "keep"),
            Err(StoreOpError::Utf8(_))
        ));
        assert_eq!(fs::read(&path).unwrap(), body);
        cleanup(&dir);
    }

    #[test]
    fn nan_and_infinity_raise_and_do_not_overwrite() {
        let dir = scratch("nan");
        for body in [
            r#"{"keep": {"api_key": "qk_keep", "name": null, "expires_at": NaN}}"#,
            r#"{"keep": {"api_key": "qk_keep", "name": null, "expires_at": Infinity}}"#,
            r#"{"keep": {"api_key": "qk_keep", "name": null, "expires_at": -Infinity}}"#,
        ] {
            let path = dir.join("credentials.json");
            fs::write(&path, body).unwrap();
            match read_fallback_value(&path) {
                Err(StoreOpError::Value(_)) => {}
                other => panic!("expected Value error, got {other:?}"),
            }
            match store_fallback(&path, "x.example.com", "qk_x", None, None) {
                Err(StoreOpError::Value(_)) => {}
                other => panic!("expected Value error on store, got {other:?}"),
            }
            assert_eq!(fs::read_to_string(&path).unwrap(), body);
        }
        cleanup(&dir);
    }

    #[test]
    fn invalid_json_that_python_treats_as_empty_still_reads_empty() {
        let dir = scratch("badjson");
        let path = dir.join("credentials.json");
        fs::write(&path, "not-json").unwrap();
        assert_eq!(
            read_fallback_value(&path).unwrap(),
            Value::Object(Map::new())
        );
        store_fallback(&path, "x.example.com", "qk_x", None, None).unwrap();
        assert!(get_fallback(&path, "x.example.com").unwrap().is_some());
        cleanup(&dir);
    }

    #[test]
    fn write_leaves_no_temp_file() {
        let dir = scratch("atomic");
        let path = dir.join("credentials.json");
        store_fallback(&path, "a.example.com", "qk_a", None, None).unwrap();
        let leftovers: Vec<_> = fs::read_dir(&dir)
            .unwrap()
            .filter_map(|e| e.ok())
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .filter(|n| n.contains(".tmp"))
            .collect();
        assert!(leftovers.is_empty(), "{leftovers:?}");
        cleanup(&dir);
    }

    #[test]
    fn lone_surrogates_raise_and_do_not_overwrite() {
        let dir = scratch("surrogate");
        for body in [
            r#"{"a":"\ud800"}"#,
            r#"{"a":"\ud800abc"}"#,
            r#"{"\ud800":1}"#,
        ] {
            let path = dir.join("credentials.json");
            fs::write(&path, body).unwrap();
            match read_fallback_value(&path) {
                Err(StoreOpError::Value(_)) => {}
                other => panic!("expected Value error for {body}, got {other:?}"),
            }
            match store_fallback(&path, "x.example.com", "qk_x", None, None) {
                Err(StoreOpError::Value(_)) => {}
                other => panic!("expected Value error on store for {body}, got {other:?}"),
            }
            assert_eq!(fs::read_to_string(&path).unwrap(), body);
        }
        cleanup(&dir);
    }

    #[test]
    fn out_of_range_numbers_are_readable() {
        let dir = scratch("bignum");
        let path = dir.join("credentials.json");
        fs::write(&path, r#"{"n": 1e400}"#).unwrap();
        let v = read_fallback_value(&path).unwrap();
        let n = number_as_python_float(v.get("n").unwrap().as_number().unwrap()).unwrap();
        assert!(n.is_infinite() && n.is_sign_positive(), "{n}");
        fs::write(&path, r#"{"n": -1e400}"#).unwrap();
        let v = read_fallback_value(&path).unwrap();
        let n = number_as_python_float(v.get("n").unwrap().as_number().unwrap()).unwrap();
        assert!(n.is_infinite() && n.is_sign_negative(), "{n}");
        let big = "1".repeat(400);
        fs::write(&path, format!(r#"{{"n": {big}}}"#)).unwrap();
        let v = read_fallback_value(&path).unwrap();
        let got = v.get("n").unwrap().as_number().unwrap().to_string();
        assert_eq!(got, big);
        store_fallback(&path, "x.example.com", "qk_x", None, None).unwrap();
        let v = read_fallback_value(&path).unwrap();
        assert_eq!(v.get("n").unwrap().as_number().unwrap().to_string(), big);
        assert!(get_fallback(&path, "x.example.com").unwrap().is_some());
        cleanup(&dir);
    }

    #[test]
    fn invalid_or_truncated_json_still_reads_empty() {
        let dir = scratch("trunc");
        let path = dir.join("credentials.json");
        for body in ["not-json", "-NaN", r#"{"a":NaN"#] {
            fs::write(&path, body).unwrap();
            assert_eq!(
                read_fallback_value(&path).unwrap(),
                Value::Object(Map::new()),
                "{body}"
            );
        }
        cleanup(&dir);
    }

    struct MemoryKeyring {
        map: std::sync::Mutex<std::collections::HashMap<(String, String), String>>,
    }

    impl MemoryKeyring {
        fn new() -> Self {
            Self {
                map: std::sync::Mutex::new(std::collections::HashMap::new()),
            }
        }
    }

    impl KeyringBackend for MemoryKeyring {
        fn get_password(
            &self,
            service: &str,
            username: &str,
        ) -> Result<Option<String>, StoreOpError> {
            Ok(self
                .map
                .lock()
                .unwrap()
                .get(&(service.to_string(), username.to_string()))
                .cloned())
        }

        fn set_password(
            &self,
            service: &str,
            username: &str,
            password: &str,
        ) -> Result<(), StoreOpError> {
            self.map.lock().unwrap().insert(
                (service.to_string(), username.to_string()),
                password.to_string(),
            );
            Ok(())
        }

        fn delete_password(&self, service: &str, username: &str) -> Result<(), StoreOpError> {
            self.map
                .lock()
                .unwrap()
                .remove(&(service.to_string(), username.to_string()));
            Ok(())
        }
    }

    #[test]
    fn keyring_store_get_delete_list_round_trip() {
        let dir = scratch("kr");
        let fallback = dir.join("credentials.json");
        let index = dir.join("credentials_index.json");
        let kr = MemoryKeyring::new();
        store_credential(
            "a.example.com",
            "qk_a",
            Some("alice"),
            Some(9),
            true,
            &fallback,
            &index,
            &kr,
        )
        .unwrap();
        store_credential(
            "b.example.com",
            "  qk_b  ",
            None,
            None,
            true,
            &fallback,
            &index,
            &kr,
        )
        .unwrap();
        assert!(
            !fallback.exists(),
            "keyring path must not write the file store"
        );
        let a = get_credential("a.example.com", true, &fallback, &kr)
            .unwrap()
            .unwrap();
        assert_eq!(a.get("api_key"), Some(&Value::String("qk_a".into())));
        assert_eq!(a.get("name"), Some(&Value::String("alice".into())));
        let listed: Vec<String> = list_credentials(true, &fallback, &index, &kr)
            .unwrap()
            .into_iter()
            .map(|(d, _)| d)
            .collect();
        assert_eq!(listed, ["a.example.com", "b.example.com"]);
        let raw = kr.get_password("quiltx", "a.example.com").unwrap().unwrap();
        assert_eq!(
            raw,
            r#"{"api_key": "qk_a", "name": "alice", "expires_at": 9}"#
        );
        delete_credential("a.example.com", true, &fallback, &index, &kr).unwrap();
        assert!(get_credential("a.example.com", true, &fallback, &kr)
            .unwrap()
            .is_none());
        delete_credential("a.example.com", true, &fallback, &index, &kr).unwrap();
        let listed: Vec<String> = list_credentials(true, &fallback, &index, &kr)
            .unwrap()
            .into_iter()
            .map(|(d, _)| d)
            .collect();
        assert_eq!(listed, ["b.example.com"]);
        cleanup(&dir);
    }

    #[test]
    fn corrupt_keyring_entry_raises_and_is_not_treated_as_missing() {
        let dir = scratch("kr-bad");
        let fallback = dir.join("credentials.json");
        let kr = MemoryKeyring::new();
        kr.set_password("quiltx", "x.example.com", "not-json")
            .unwrap();
        match get_credential("x.example.com", true, &fallback, &kr) {
            Err(StoreOpError::Value(msg)) => {
                assert!(msg.contains("x.example.com"), "{msg}");
                assert!(msg.contains("not valid JSON"), "{msg}");
                assert!(
                    msg.contains("quiltx catalog login --catalog x.example.com"),
                    "{msg}"
                );
                assert!(msg.contains("quiltx catalog forget x.example.com"), "{msg}");
            }
            other => panic!("expected Value error, got {other:?}"),
        }
        // A missing entry is still None.
        assert!(get_credential("missing.example.com", true, &fallback, &kr)
            .unwrap()
            .is_none());
        // The corrupt payload is still there (get did not clear it).
        assert_eq!(
            kr.get_password("quiltx", "x.example.com")
                .unwrap()
                .as_deref(),
            Some("not-json")
        );
        cleanup(&dir);
    }

    #[test]
    fn list_skips_a_corrupt_keyring_entry() {
        let dir = scratch("kr-list-bad");
        let fallback = dir.join("credentials.json");
        let index = dir.join("credentials_index.json");
        let kr = MemoryKeyring::new();
        store_credential(
            "good.example.com",
            "qk_good",
            None,
            None,
            true,
            &fallback,
            &index,
            &kr,
        )
        .unwrap();
        add_to_index(&index, "bad.example.com").unwrap();
        kr.set_password("quiltx", "bad.example.com", "not-json")
            .unwrap();
        let listed: Vec<String> = list_credentials(true, &fallback, &index, &kr)
            .unwrap()
            .into_iter()
            .map(|(d, _)| d)
            .collect();
        assert_eq!(listed, ["good.example.com"]);
        assert_eq!(
            kr.get_password("quiltx", "bad.example.com")
                .unwrap()
                .as_deref(),
            Some("not-json")
        );
        cleanup(&dir);
    }

    #[test]
    fn store_and_delete_replace_a_corrupt_keyring_entry() {
        let dir = scratch("kr-replace-bad");
        let fallback = dir.join("credentials.json");
        let index = dir.join("credentials_index.json");
        let kr = MemoryKeyring::new();
        kr.set_password("quiltx", "x.example.com", "not-json")
            .unwrap();
        add_to_index(&index, "x.example.com").unwrap();
        store_credential(
            "x.example.com",
            "qk_new",
            None,
            None,
            true,
            &fallback,
            &index,
            &kr,
        )
        .unwrap();
        let entry = get_credential("x.example.com", true, &fallback, &kr)
            .unwrap()
            .unwrap();
        assert_eq!(entry.get("api_key"), Some(&Value::String("qk_new".into())));
        kr.set_password("quiltx", "x.example.com", "not-json")
            .unwrap();
        delete_credential("x.example.com", true, &fallback, &index, &kr).unwrap();
        assert!(get_credential("x.example.com", true, &fallback, &kr)
            .unwrap()
            .is_none());
        assert!(kr
            .get_password("quiltx", "x.example.com")
            .unwrap()
            .is_none());
        cleanup(&dir);
    }

    #[test]
    fn file_fallback_is_used_when_keyring_is_off() {
        let dir = scratch("kr-off");
        let fallback = dir.join("credentials.json");
        let index = dir.join("credentials_index.json");
        let kr = MemoryKeyring::new();
        store_credential(
            "a.example.com",
            "qk_a",
            None,
            None,
            false,
            &fallback,
            &index,
            &kr,
        )
        .unwrap();
        assert!(fallback.exists());
        assert!(kr
            .get_password("quiltx", "a.example.com")
            .unwrap()
            .is_none());
        assert!(get_credential("a.example.com", false, &fallback, &kr)
            .unwrap()
            .is_some());
        cleanup(&dir);
    }
}
