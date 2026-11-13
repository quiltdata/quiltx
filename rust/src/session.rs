//! STS credentials exchange: `GET /api/auth/get_credentials`.
//!
//! A port of the HTTP and mapping in
//! `quiltx.auth.session._mint_registry_credentials`. URL construction,
//! payload mapping, and fail-closed checks live here. The HTTP transport
//! is an [`HttpClient`] so tests can inject recorded responses; the
//! production client is the Python helper in `quiltx.auth.session`
//! (`_get_json`), which uses quilt3's authenticated session so existing
//! tests that replace `quilt3.session` keep working.
//!
//! STS credentials are minted in memory and are never written to disk.
//! Building a botocore session and refusing the ambient AWS chain stay
//! in Python.

use serde_json::{Map, Value};

use crate::registry;

/// A failed STS mint. Mapped to
/// `quiltx.auth.session.CatalogCredentialsError`.
#[derive(Debug)]
pub enum SessionError {
    Credentials(String),
    Py(pyo3::PyErr),
}

/// GET JSON, as used by the STS credentials endpoint.
pub trait HttpClient {
    fn get_json(&self, url: &str) -> Result<Value, SessionError>;
}

fn rstrip_slash(s: &str) -> &str {
    s.trim_end_matches('/')
}

fn nonempty_string(value: Option<&Value>) -> Option<&str> {
    match value {
        Some(Value::String(s)) if !s.is_empty() => Some(s.as_str()),
        _ => None,
    }
}

/// True when *s* is a datetime string with an explicit offset (or `Z`).
/// Uses Python's `datetime.fromisoformat` so the rule matches the runtime
/// that will later consume `expiry_time`. A naive or unparseable value
/// is rejected.
fn expiration_is_aware(s: &str) -> bool {
    use pyo3::prelude::*;

    let normalized = if s.ends_with('Z') || s.ends_with('z') {
        format!("{}+00:00", &s[..s.len() - 1])
    } else {
        s.to_string()
    };
    Python::initialize();
    Python::attach(|py| {
        let datetime = match py.import("datetime").and_then(|m| m.getattr("datetime")) {
            Ok(dt) => dt,
            Err(err) => {
                err.restore(py);
                let _ = PyErr::take(py);
                return false;
            }
        };
        match datetime.call_method1("fromisoformat", (normalized.as_str(),)) {
            Ok(dt) => match dt.getattr("tzinfo") {
                Ok(tz) => !tz.is_none(),
                Err(err) => {
                    err.restore(py);
                    let _ = PyErr::take(py);
                    false
                }
            },
            Err(err) => {
                err.restore(py);
                let _ = PyErr::take(py);
                false
            }
        }
    })
}

fn no_usable(registry_url: &str, detail: &str) -> SessionError {
    SessionError::Credentials(format!(
        "registry {registry_url} returned no usable credentials: {detail}"
    ))
}

/// Fetch temporary STS credentials from `<registry_url>/api/auth/get_credentials`.
///
/// Returns the same dict quiltx already builds (`access_key`, `secret_key`,
/// `token`, `expiry_time`). A body that is not a JSON object, a field that
/// is missing, empty, or the wrong type, or an `Expiration` that is not a
/// timezone-aware datetime string, raises — it must not be treated as
/// usable credentials a later caller could use.
pub fn mint_registry_credentials(
    registry_url: &str,
    http: &dyn HttpClient,
) -> Result<Map<String, Value>, SessionError> {
    let url = format!("{}/api/auth/get_credentials", rstrip_slash(registry_url));
    let payload = http.get_json(&url)?;
    let Some(obj) = payload.as_object() else {
        return Err(SessionError::Credentials(format!(
            "registry {registry_url} returned no usable credentials: unexpected response from {url}: {}",
            registry::json_type_and_length(&payload)
        )));
    };

    let access_key = nonempty_string(obj.get("AccessKeyId"))
        .ok_or_else(|| no_usable(registry_url, "AccessKeyId must be a non-empty string"))?;
    let secret_key = nonempty_string(obj.get("SecretAccessKey"))
        .ok_or_else(|| no_usable(registry_url, "SecretAccessKey must be a non-empty string"))?;
    let token = nonempty_string(obj.get("SessionToken"))
        .ok_or_else(|| no_usable(registry_url, "SessionToken must be a non-empty string"))?;
    let expiry = nonempty_string(obj.get("Expiration")).ok_or_else(|| {
        no_usable(
            registry_url,
            "Expiration must be a timezone-aware datetime string",
        )
    })?;
    if !expiration_is_aware(expiry) {
        return Err(no_usable(
            registry_url,
            "Expiration must be a timezone-aware datetime string",
        ));
    }

    let mut out = Map::new();
    out.insert("access_key".into(), Value::String(access_key.to_string()));
    out.insert("secret_key".into(), Value::String(secret_key.to_string()));
    out.insert("token".into(), Value::String(token.to_string()));
    out.insert("expiry_time".into(), Value::String(expiry.to_string()));
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::collections::HashMap;

    #[derive(Default)]
    struct MemoryHttp {
        get: HashMap<String, Value>,
    }

    impl MemoryHttp {
        fn get(mut self, url: &str, body: Value) -> Self {
            self.get.insert(url.to_string(), body);
            self
        }
    }

    impl HttpClient for MemoryHttp {
        fn get_json(&self, url: &str) -> Result<Value, SessionError> {
            match self.get.get(url) {
                Some(v) => Ok(v.clone()),
                None => Err(SessionError::Credentials(format!("no recording for {url}"))),
            }
        }
    }

    fn happy_body() -> Value {
        json!({
            "AccessKeyId": "ASIA",
            "SecretAccessKey": "secret",
            "SessionToken": "token",
            "Expiration": "2030-01-01T00:00:00Z",
        })
    }

    fn mint_with(body: Value) -> Result<Map<String, Value>, SessionError> {
        let http = MemoryHttp::default().get(
            "https://registry.example.com/api/auth/get_credentials",
            body,
        );
        mint_registry_credentials("https://registry.example.com", &http)
    }

    fn assert_unusable(body: Value, field: &str) {
        match mint_with(body) {
            Err(SessionError::Credentials(msg)) => {
                assert!(
                    msg.starts_with(
                        "registry https://registry.example.com returned no usable credentials"
                    ),
                    "{msg}"
                );
                assert!(msg.contains(field), "{msg}");
            }
            other => panic!("expected Credentials error, got {other:?}"),
        }
    }

    #[test]
    fn mint_maps_the_registry_payload() {
        let http = MemoryHttp::default().get(
            "https://registry.example.com/api/auth/get_credentials",
            happy_body(),
        );
        let got = mint_registry_credentials("https://registry.example.com/", &http).unwrap();
        assert_eq!(got.get("access_key").unwrap(), "ASIA");
        assert_eq!(got.get("secret_key").unwrap(), "secret");
        assert_eq!(got.get("token").unwrap(), "token");
        assert_eq!(got.get("expiry_time").unwrap(), "2030-01-01T00:00:00Z");
    }

    #[test]
    fn mint_accepts_an_offset_expiration() {
        let mut body = happy_body();
        body["Expiration"] = json!("2030-01-01T00:00:00+00:00");
        let got = mint_with(body).unwrap();
        assert_eq!(got.get("expiry_time").unwrap(), "2030-01-01T00:00:00+00:00");
    }

    #[test]
    fn incomplete_payload_raises() {
        assert_unusable(json!({"AccessKeyId": "ASIA"}), "SecretAccessKey");
    }

    #[test]
    fn null_empty_and_wrong_typed_fields_raise() {
        for (field, bad, mention) in [
            ("AccessKeyId", Value::Null, "AccessKeyId"),
            ("AccessKeyId", json!(""), "AccessKeyId"),
            ("AccessKeyId", json!(1), "AccessKeyId"),
            ("AccessKeyId", json!(true), "AccessKeyId"),
            ("SecretAccessKey", Value::Null, "SecretAccessKey"),
            ("SecretAccessKey", json!(""), "SecretAccessKey"),
            ("SecretAccessKey", json!(1), "SecretAccessKey"),
            ("SessionToken", Value::Null, "SessionToken"),
            ("SessionToken", json!(""), "SessionToken"),
            ("SessionToken", json!([]), "SessionToken"),
        ] {
            let mut body = happy_body();
            body[field] = bad;
            assert_unusable(body, mention);
        }
    }

    #[test]
    fn expiration_must_be_an_aware_datetime_string() {
        for bad in [
            Value::Null,
            json!(""),
            json!(1_730_000_000),
            json!(true),
            json!("2030-01-01T00:00:00"),
            json!("not-a-date"),
            json!("NaN"),
        ] {
            let mut body = happy_body();
            body["Expiration"] = bad;
            assert_unusable(body, "Expiration");
        }
    }

    #[test]
    fn non_object_body_fails_closed_and_echoes_only_type_and_length() {
        let cases = [
            (json!([]), "list of length 0"),
            (Value::Null, "None"),
            (json!("qk_should_not_leak"), "str of length 18"),
            (json!("ok"), "str of length 2"),
            (json!(1), "int"),
            (json!(true), "bool"),
            (json!(""), "str of length 0"),
            (
                json!([{"SecretAccessKey": "leak_me", "message": "bad\u{2028}key"}]),
                "list of length 1",
            ),
        ];
        for (body, typ) in cases {
            match mint_with(body.clone()) {
                Err(SessionError::Credentials(msg)) => {
                    assert!(
                        msg.starts_with(
                            "registry https://registry.example.com returned no usable credentials: unexpected response from https://registry.example.com/api/auth/get_credentials:"
                        ),
                        "{msg}"
                    );
                    assert!(msg.contains(typ), "{msg}");
                    assert!(!msg.contains("qk_should_not_leak"), "{msg}");
                    assert!(!msg.contains("leak_me"), "{msg}");
                    assert!(!msg.contains("\\u2028"), "{msg}");
                    assert!(!msg.contains("bad"), "{msg}");
                }
                other => panic!("expected Credentials error for {body}, got {other:?}"),
            }
        }
    }
}
