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
//! the fallback file is opened at 0600, its parent directory is 0700, and the
//! index is written with the process umask (Python's `Path.write_text`). Missing
//! or unreadable files, and malformed JSON, read as empty, as they did in
//! Python.

use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::path::Path;

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

/// Parsed `credentials.json`. A missing, unreadable, or malformed file is `{}`.
/// Valid JSON that is not an object (for example `[]`) is returned as-is, as
/// Python's `json.loads` did.
pub fn read_fallback_value(path: &Path) -> Value {
    match read_json(path) {
        Ok(value) => value,
        _ => Value::Object(Map::new()),
    }
}

/// The mapping in `credentials.json`, or `{}` if the file is missing, unreadable,
/// malformed, or not an object. Prefer [`as_mapping`] when the Python would
/// raise `AttributeError` on a non-dict.
pub fn read_fallback(path: &Path) -> Map<String, Value> {
    match read_fallback_value(path) {
        Value::Object(map) => map,
        _ => Map::new(),
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
    let value = read_fallback_value(path);
    match value {
        Value::Object(map) => Ok(map),
        other => Err(StoreOpError::Attribute {
            typ: json_type_name(&other),
            attr,
        }),
    }
}

fn assign_mapping(path: &Path) -> Result<Map<String, Value>, StoreOpError> {
    let value = read_fallback_value(path);
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

/// Read `credentials_index.json`; a missing, unreadable, or non-list file is `[]`.
pub fn read_index(path: &Path) -> Vec<String> {
    match read_json(path) {
        Ok(Value::Array(items)) => items
            .into_iter()
            .filter_map(|v| v.as_str().map(str::to_string))
            .collect(),
        _ => Vec::new(),
    }
}

/// Write `credentials_index.json` compactly, at the process umask (not 0600).
pub fn write_index(path: &Path, entries: &[String]) -> io::Result<()> {
    let values: Vec<Value> = entries.iter().map(|s| Value::String(s.clone())).collect();
    let bytes = dumps(&Value::Array(values), None).into_bytes();
    write_index_file(path, &bytes)
}

/// Append *dns* to the index if it is not already present.
pub fn add_to_index(path: &Path, dns: &str) -> io::Result<()> {
    let mut entries = read_index(path);
    if !entries.iter().any(|e| e == dns) {
        entries.push(dns.to_string());
        write_index(path, &entries)?;
    }
    Ok(())
}

/// Remove the first occurrence of *dns* from the index, if any.
pub fn remove_from_index(path: &Path, dns: &str) -> io::Result<()> {
    let mut entries = read_index(path);
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
pub fn delete_fallback(path: &Path, dns: &str) -> io::Result<()> {
    let mut data = read_fallback(path);
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

fn entry_if_api_key(value: Option<&Value>) -> Option<Map<String, Value>> {
    match value {
        Some(Value::Object(map)) if map.contains_key("api_key") => Some(map.clone()),
        _ => None,
    }
}

fn read_json(path: &Path) -> io::Result<Value> {
    let text = fs::read_to_string(path)?;
    serde_json::from_str(&text).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
}

/// Create the immediate parent at 0700 (grandparents use the default mode),
/// then write *bytes* opening the file at 0600, matching `_write_fallback`.
fn write_private(path: &Path, bytes: &[u8]) -> io::Result<()> {
    ensure_parent(path)?;
    let mut opts = OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut file = opts.open(path)?;
    file.write_all(bytes)?;
    // The file may have pre-existed at looser permissions (older quiltx).
    drop(file);
    let _ = chmod(path, 0o600);
    Ok(())
}

/// `Path.write_text`: same parent-directory rules, file mode from the umask.
fn write_index_file(path: &Path, bytes: &[u8]) -> io::Result<()> {
    ensure_parent(path)?;
    let mut file = File::create(path)?;
    file.write_all(bytes)?;
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
    } else if let Some(f) = n.as_f64() {
        out.push_str(&python_float(f));
    } else {
        out.push_str(&n.to_string());
    }
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
        assert!(read_index(&path).is_empty());
        add_to_index(&path, "a.example.com").unwrap();
        add_to_index(&path, "b.example.com").unwrap();
        add_to_index(&path, "a.example.com").unwrap();
        assert_eq!(read_index(&path), ["a.example.com", "b.example.com"]);
        assert_eq!(
            fs::read_to_string(&path).unwrap(),
            "[\"a.example.com\", \"b.example.com\"]"
        );
        remove_from_index(&path, "a.example.com").unwrap();
        remove_from_index(&path, "a.example.com").unwrap();
        assert_eq!(read_index(&path), ["b.example.com"]);
        fs::write(&path, "{}").unwrap();
        assert!(read_index(&path).is_empty());
        cleanup(&dir);
    }

    #[test]
    fn store_writes_python_shaped_bytes() {
        let dir = scratch("bytes");
        let path = dir.join("credentials.json");
        store_fallback(&path, "nightly.quilttest.com", "qk_abc", None, None).unwrap();
        let got = fs::read_to_string(&path).unwrap();
        let want = "{\n  \"nightly.quilttest.com\": {\n    \"api_key\": \"qk_abc\",\n    \"name\": null,\n    \"expires_at\": null\n  }\n}";
        assert_eq!(got, want);
        cleanup(&dir);
    }
}
