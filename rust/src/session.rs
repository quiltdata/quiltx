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

const FIELD_MAP: &[(&str, &str)] = &[
    ("AccessKeyId", "access_key"),
    ("SecretAccessKey", "secret_key"),
    ("SessionToken", "token"),
    ("Expiration", "expiry_time"),
];

fn no_usable(registry_url: &str) -> SessionError {
    SessionError::Credentials(format!(
        "registry {registry_url} returned no usable credentials"
    ))
}

/// Fetch temporary STS credentials from `<registry_url>/api/auth/get_credentials`.
///
/// Returns the same dict quiltx already builds (`access_key`, `secret_key`,
/// `token`, `expiry_time`). A body that is not a JSON object, or that is
/// missing a required field, raises — it must not be treated as empty
/// credentials a later caller could use.
pub fn mint_registry_credentials(
    registry_url: &str,
    http: &dyn HttpClient,
) -> Result<Map<String, Value>, SessionError> {
    let url = format!("{}/api/auth/get_credentials", rstrip_slash(registry_url));
    let payload = http.get_json(&url)?;
    let Some(obj) = payload.as_object() else {
        return Err(SessionError::Credentials(format!(
            "registry {registry_url} returned no usable credentials: unexpected response from {url}: {}",
            registry::python_repr_redacted(&payload)
        )));
    };
    let mut out = Map::new();
    for &(src, dest) in FIELD_MAP {
        match obj.get(src) {
            Some(value) => {
                out.insert(dest.to_string(), value.clone());
            }
            None => return Err(no_usable(registry_url)),
        }
    }
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
    fn incomplete_payload_raises() {
        let http = MemoryHttp::default().get(
            "https://registry.example.com/api/auth/get_credentials",
            json!({"AccessKeyId": "ASIA"}),
        );
        match mint_registry_credentials("https://registry.example.com", &http) {
            Err(SessionError::Credentials(msg)) => {
                assert_eq!(
                    msg,
                    "registry https://registry.example.com returned no usable credentials"
                );
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn non_object_body_fails_closed_and_redacts() {
        let cases = [
            json!([]),
            Value::Null,
            json!("qk_should_not_leak"),
            json!("ok"),
            json!(1),
            json!(true),
            json!(""),
        ];
        for body in cases {
            let http = MemoryHttp::default().get(
                "https://registry.example.com/api/auth/get_credentials",
                body.clone(),
            );
            match mint_registry_credentials("https://registry.example.com", &http) {
                Err(SessionError::Credentials(msg)) => {
                    assert!(
                        msg.starts_with(
                            "registry https://registry.example.com returned no usable credentials: unexpected response from https://registry.example.com/api/auth/get_credentials:"
                        ),
                        "{msg}"
                    );
                    assert!(!msg.contains("qk_should_not_leak"), "{msg}");
                    if body.as_str() == Some("qk_should_not_leak") {
                        assert!(msg.contains("<redacted>"), "{msg}");
                    }
                }
                other => panic!("expected Credentials error for {body}, got {other:?}"),
            }
        }
    }

    #[test]
    fn error_text_uses_python_repr_and_redacts_sensitive_keys() {
        // A non-object we can't actually put keys in; use a one-element
        // array whose item has secrets, to confirm the echoed body is
        // redacted and C1 / Zl are escaped like Python.
        let body = json!([{
            "SecretAccessKey": "leak_me",
            "message": "bad\u{2028}key\u{80}end",
            "hint": "not a secret"
        }]);
        let http = MemoryHttp::default().get(
            "https://registry.example.com/api/auth/get_credentials",
            body,
        );
        match mint_registry_credentials("https://registry.example.com", &http) {
            Err(SessionError::Credentials(msg)) => {
                assert!(!msg.contains("leak_me"), "{msg}");
                assert!(msg.contains("<redacted>"), "{msg}");
                assert!(msg.contains("\\u2028"), "{msg}");
                assert!(msg.contains("\\x80"), "{msg}");
                assert!(msg.contains("not a secret"), "{msg}");
            }
            other => panic!("{other:?}"),
        }
    }
}
