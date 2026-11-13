//! Registry HTTP: resolve the catalog's registry URL, log in, mint a `qk_`
//! API key, and validate one.
//!
//! A port of `quiltx.auth.registry`. The URL construction, payloads, and
//! response handling live here. The HTTP transport is an [`HttpClient`] so
//! tests can inject recorded responses; the production client is the Python
//! `urllib` helpers in `quiltx.auth.registry` (so `SSL_CERT_FILE` /
//! `REQUESTS_CA_BUNDLE` and tests that patch `_get_json` / `_post_json` /
//! `_post_form` keep working).

use pyo3::prelude::*;
use pyo3::types::PyString;
use serde_json::{json, Map, Value};

const API_KEY_CREATE_MUTATION: &str = "\
mutation apiKeyCreate($input: APIKeyCreateInput!) {
  apiKeyCreate(input: $input) {
    __typename
    ... on APIKeyCreated {
      apiKey { id name expiresAt }
      secret
    }
    ... on InvalidInput {
      errors { path message name }
    }
  }
}";

const VALIDATE_QUERY: &str = "query apiKeysList { apiKeysList(input: {}) { apiKeys { id } } }";

/// An unrecoverable failure during U/P → `qk_` bootstrap, or a failed
/// config/auth request. Mapped to `quiltx.auth.registry.CatalogAuthError`.
#[derive(Debug)]
pub enum RegistryError {
    Auth(String),
    Py(pyo3::PyErr),
}

/// GET/POST JSON and form-urlencoded POST, as used by the registry API.
pub trait HttpClient {
    fn get_json(&self, url: &str) -> Result<Value, RegistryError>;
    fn post_json(
        &self,
        url: &str,
        payload: &Value,
        bearer: Option<&str>,
    ) -> Result<Value, RegistryError>;
    fn post_form(&self, url: &str, payload: &Map<String, Value>) -> Result<Value, RegistryError>;
}

fn rstrip_slash(s: &str) -> &str {
    s.trim_end_matches('/')
}

/// `if not value` for a JSON field, then `str(value)` as Python would.
fn nonempty_python_str(value: Option<&Value>) -> Option<String> {
    let value = value?;
    match value {
        Value::Null => None,
        Value::Bool(false) => None,
        Value::String(s) if s.is_empty() => None,
        Value::String(s) => Some(s.clone()),
        Value::Bool(true) => Some("True".into()),
        Value::Number(n) => {
            let s = n.to_string();
            if s.is_empty() || s == "0" {
                None
            } else {
                Some(s)
            }
        }
        Value::Array(a) if a.is_empty() => None,
        Value::Object(m) if m.is_empty() => None,
        other => Some(other.to_string()),
    }
}

fn python_repr_str(s: &str) -> String {
    // Delegate to Python's own repr() so C0/C1, bidi marks, Zl/Zp,
    // and anything else Python escapes are covered exactly.
    Python::initialize();
    Python::attach(|py| {
        PyString::new(py, s)
            .repr()
            .expect("Python repr of a str")
            .to_string()
    })
}

fn python_repr(value: &Value) -> String {
    match value {
        Value::Null => "None".into(),
        Value::Bool(true) => "True".into(),
        Value::Bool(false) => "False".into(),
        Value::Number(n) => n.to_string(),
        Value::String(s) => python_repr_str(s),
        Value::Array(items) => {
            let parts: Vec<String> = items.iter().map(python_repr).collect();
            format!("[{}]", parts.join(", "))
        }
        Value::Object(map) => {
            let parts: Vec<String> = map
                .iter()
                .map(|(k, v)| format!("{}: {}", python_repr_str(k), python_repr(v)))
                .collect();
            format!("{{{}}}", parts.join(", "))
        }
    }
}

/// True when a JSON key looks like a credential field.
/// Matches `secret`, `token`, `password`, and `api_key` / `apikey`
/// as substrings, case-insensitively (`api_?key` after lowercasing).
fn is_sensitive_key(key: &str) -> bool {
    let k = key.to_ascii_lowercase();
    k.contains("secret")
        || k.contains("token")
        || k.contains("password")
        || k.contains("apikey")
        || k.contains("api_key")
}

const REDACTED: &str = "<redacted>";

/// Redact credential material so an error message cannot leak a `qk_`
/// key, token, or password. Applied to GraphQL errors, InvalidInput
/// payloads, and any other echoed registry body.
fn redact_secrets(value: &Value) -> Value {
    match value {
        Value::Object(map) => {
            let mut out = Map::new();
            for (k, v) in map {
                if is_sensitive_key(k) {
                    out.insert(k.clone(), Value::String(REDACTED.into()));
                } else {
                    out.insert(k.clone(), redact_secrets(v));
                }
            }
            Value::Object(out)
        }
        Value::Array(items) => Value::Array(items.iter().map(redact_secrets).collect()),
        Value::String(s) if s.starts_with("qk_") => Value::String(REDACTED.into()),
        other => other.clone(),
    }
}

fn python_repr_redacted(value: &Value) -> String {
    python_repr(&redact_secrets(value))
}

fn python_keys_list(value: &Value) -> String {
    match value.as_object() {
        Some(map) => {
            let parts: Vec<String> = map.keys().map(|k| python_repr_str(k)).collect();
            format!("[{}]", parts.join(", "))
        }
        None => "[]".into(),
    }
}

fn as_object(value: &Value) -> Option<&Map<String, Value>> {
    value.as_object()
}

fn mapping_or_empty(value: Option<&Value>) -> Map<String, Value> {
    match value {
        Some(Value::Object(map)) if !map.is_empty() => map.clone(),
        Some(Value::Null) | None => Map::new(),
        Some(Value::Bool(false)) => Map::new(),
        Some(Value::Object(map)) => map.clone(),
        _ => Map::new(),
    }
}

/// Resolve the registry API base URL for *catalog_url*.
///
/// Reads `registryUrl` from `<catalog_url>/config.json`. If that field is
/// missing or empty, fall back to the catalog URL (single-host dev). A
/// failed fetch, or a body that is not a JSON object, raises — it must not
/// be treated as a missing field, or a later login could hit the wrong host.
pub fn resolve_registry_url(
    catalog_url: &str,
    http: &dyn HttpClient,
) -> Result<String, RegistryError> {
    let base = rstrip_slash(catalog_url);
    let url = format!("{base}/config.json");
    let config = http.get_json(&url)?;
    let Some(obj) = as_object(&config) else {
        return Err(RegistryError::Auth(format!(
            "config.json from {url} is not a JSON object; cannot resolve the registry URL"
        )));
    };
    match nonempty_python_str(obj.get("registryUrl")) {
        Some(registry) => Ok(rstrip_slash(&registry).to_string()),
        None => Ok(base.to_string()),
    }
}

/// POST `{username, password}` to `<registry_url>/api/login`.
pub fn acquire_refresh_token(
    registry_url: &str,
    username: &str,
    password: &str,
    http: &dyn HttpClient,
) -> Result<String, RegistryError> {
    let url = format!("{}/api/login", rstrip_slash(registry_url));
    let response = http.post_json(
        &url,
        &json!({"username": username, "password": password}),
        None,
    )?;
    match nonempty_python_str(as_object(&response).and_then(|m| m.get("refresh_token"))) {
        Some(token) => Ok(token),
        None => Err(RegistryError::Auth(format!(
            "No refresh_token in login response from {url}. Response keys: {}",
            python_keys_list(&response)
        ))),
    }
}

/// Trade the short-lived refresh_token for an access_token (`/api/token`, form-encoded).
pub fn exchange_refresh_token_for_access_token(
    registry_url: &str,
    refresh_token: &str,
    http: &dyn HttpClient,
) -> Result<String, RegistryError> {
    let url = format!("{}/api/token", rstrip_slash(registry_url));
    let mut payload = Map::new();
    payload.insert(
        "refresh_token".into(),
        Value::String(refresh_token.to_string()),
    );
    let response = http.post_form(&url, &payload)?;
    match nonempty_python_str(as_object(&response).and_then(|m| m.get("access_token"))) {
        Some(token) => Ok(token),
        None => Err(RegistryError::Auth(format!(
            "No access_token in token response from {url}. Response keys: {}",
            python_keys_list(&response)
        ))),
    }
}

/// Mint a long-lived `qk_` API key via GraphQL `apiKeyCreate`.
pub fn create_api_key(
    registry_url: &str,
    access_token: &str,
    name: &str,
    expires_in_days: i64,
    http: &dyn HttpClient,
) -> Result<Map<String, Value>, RegistryError> {
    let url = format!("{}/graphql", rstrip_slash(registry_url));
    let payload = json!({
        "query": API_KEY_CREATE_MUTATION,
        "operationName": "apiKeyCreate",
        "variables": {"input": {"name": name, "expiresInDays": expires_in_days}},
    });
    let response = http.post_json(&url, &payload, Some(access_token))?;
    if let Some(errors) = response.get("errors") {
        if !is_falsy(errors) {
            return Err(RegistryError::Auth(format!(
                "GraphQL errors: {}",
                python_repr_redacted(errors)
            )));
        }
    }
    let data = mapping_or_empty(response.get("data"));
    let Some(result) = data.get("apiKeyCreate") else {
        return Err(RegistryError::Auth(format!(
            "Unexpected GraphQL response from {url}: {}",
            python_repr_redacted(&response)
        )));
    };
    if is_falsy(result) {
        return Err(RegistryError::Auth(format!(
            "Unexpected GraphQL response from {url}: {}",
            python_repr_redacted(&response)
        )));
    }
    let typename_value = result.get("__typename");
    let typename = typename_value.and_then(Value::as_str).unwrap_or("");
    if typename == "APIKeyCreated" {
        let secret = nonempty_python_str(result.get("secret")).ok_or_else(|| {
            RegistryError::Auth("apiKeyCreate succeeded but returned no secret".into())
        })?;
        let api_key = mapping_or_empty(result.get("apiKey"));
        let name_out = nonempty_python_str(api_key.get("name")).unwrap_or_else(|| name.to_string());
        let mut out = Map::new();
        out.insert("secret".into(), Value::String(secret));
        out.insert("name".into(), Value::String(name_out));
        out.insert(
            "expires_at".into(),
            api_key.get("expiresAt").cloned().unwrap_or(Value::Null),
        );
        return Ok(out);
    }
    if typename == "InvalidInput" {
        return Err(RegistryError::Auth(format!(
            "Catalog rejected apiKeyCreate input: {}",
            result
                .get("errors")
                .map(python_repr_redacted)
                .unwrap_or_else(|| "None".into())
        )));
    }
    Err(RegistryError::Auth(format!(
        "Unexpected apiKeyCreate result type {}: {}",
        typename_value
            .map(python_repr)
            .unwrap_or_else(|| "None".into()),
        python_repr_redacted(result)
    )))
}

/// Round-trip the registry with *api_key* to confirm it is accepted.
pub fn validate_api_key(
    registry_url: &str,
    api_key: &str,
    http: &dyn HttpClient,
) -> Result<(), RegistryError> {
    let url = format!("{}/graphql", rstrip_slash(registry_url));
    let payload = json!({"query": VALIDATE_QUERY, "operationName": "apiKeysList"});
    let response = http.post_json(&url, &payload, Some(api_key))?;
    // Fail closed: a 200 body that is not an object ( [], null, a string,
    // a number, true, "" ) must not count the key as valid.
    let Some(obj) = as_object(&response) else {
        return Err(RegistryError::Auth(format!(
            "Unexpected response from {url}: {}",
            python_repr_redacted(&response)
        )));
    };
    if let Some(errors) = obj.get("errors") {
        if !is_falsy(errors) {
            return Err(RegistryError::Auth(format!(
                "Catalog rejected API key: {}",
                python_repr_redacted(errors)
            )));
        }
    }
    Ok(())
}

fn is_falsy(value: &Value) -> bool {
    match value {
        Value::Null => true,
        Value::Bool(false) => true,
        Value::String(s) if s.is_empty() => true,
        Value::Array(a) if a.is_empty() => true,
        Value::Object(m) if m.is_empty() => true,
        Value::Number(n) => n.as_f64() == Some(0.0) || n.to_string() == "0",
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    enum Recorded {
        Json(Value),
        Auth(String),
    }

    #[derive(Default)]
    struct MemoryHttp {
        get: HashMap<String, Recorded>,
        post_json: HashMap<String, Recorded>,
        post_form: HashMap<String, Recorded>,
        json_calls: std::sync::Mutex<Vec<(String, Value, Option<String>)>>,
        form_calls: std::sync::Mutex<Vec<(String, Map<String, Value>)>>,
    }

    impl MemoryHttp {
        fn get(mut self, url: &str, body: Value) -> Self {
            self.get.insert(url.to_string(), Recorded::Json(body));
            self
        }
        fn post(mut self, url: &str, body: Value) -> Self {
            self.post_json.insert(url.to_string(), Recorded::Json(body));
            self
        }
        fn post_err(mut self, url: &str, msg: &str) -> Self {
            self.post_json
                .insert(url.to_string(), Recorded::Auth(msg.into()));
            self
        }
        fn form(mut self, url: &str, body: Value) -> Self {
            self.post_form.insert(url.to_string(), Recorded::Json(body));
            self
        }
    }

    fn take(map: &HashMap<String, Recorded>, url: &str) -> Result<Value, RegistryError> {
        match map.get(url) {
            Some(Recorded::Json(v)) => Ok(v.clone()),
            Some(Recorded::Auth(msg)) => Err(RegistryError::Auth(msg.clone())),
            None => panic!("unexpected request to {url}"),
        }
    }

    impl HttpClient for MemoryHttp {
        fn get_json(&self, url: &str) -> Result<Value, RegistryError> {
            take(&self.get, url)
        }
        fn post_json(
            &self,
            url: &str,
            payload: &Value,
            bearer: Option<&str>,
        ) -> Result<Value, RegistryError> {
            self.json_calls.lock().unwrap().push((
                url.to_string(),
                payload.clone(),
                bearer.map(str::to_string),
            ));
            take(&self.post_json, url)
        }
        fn post_form(
            &self,
            url: &str,
            payload: &Map<String, Value>,
        ) -> Result<Value, RegistryError> {
            self.form_calls
                .lock()
                .unwrap()
                .push((url.to_string(), payload.clone()));
            take(&self.post_form, url)
        }
    }

    fn created(secret: &str, name: &str, expires: &str) -> Value {
        json!({
            "data": {
                "apiKeyCreate": {
                    "__typename": "APIKeyCreated",
                    "apiKey": {"id": "ak-1", "name": name, "expiresAt": expires},
                    "secret": secret,
                }
            }
        })
    }

    #[test]
    fn resolve_reads_registry_url_and_strips_a_slash() {
        let http = MemoryHttp::default().get(
            "https://catalog.example.com/config.json",
            json!({"registryUrl": "https://reg.example.com/"}),
        );
        assert_eq!(
            resolve_registry_url("https://catalog.example.com/", &http).unwrap(),
            "https://reg.example.com"
        );
    }

    #[test]
    fn resolve_falls_back_when_registry_url_is_missing() {
        let http = MemoryHttp::default().get("http://localhost/config.json", json!({"foo": 1}));
        assert_eq!(
            resolve_registry_url("http://localhost/", &http).unwrap(),
            "http://localhost"
        );
    }

    #[test]
    fn resolve_does_not_fall_back_when_config_fetch_fails() {
        let http = MemoryHttp {
            get: HashMap::from([(
                "https://catalog.example.com/config.json".into(),
                Recorded::Auth(
                    "Request to https://catalog.example.com/config.json failed (404): missing"
                        .into(),
                ),
            )]),
            ..Default::default()
        };
        match resolve_registry_url("https://catalog.example.com", &http) {
            Err(RegistryError::Auth(msg)) => {
                assert!(msg.contains("404"), "{msg}");
                assert!(!msg.contains("is not a JSON object"), "{msg}");
            }
            other => panic!("expected Auth error, got {other:?}"),
        }
    }

    #[test]
    fn resolve_does_not_treat_a_non_object_config_as_missing() {
        let http = MemoryHttp::default().get(
            "https://catalog.example.com/config.json",
            json!(["not", "a", "map"]),
        );
        match resolve_registry_url("https://catalog.example.com", &http) {
            Err(RegistryError::Auth(msg)) => {
                assert!(msg.contains("not a JSON object"), "{msg}");
                assert!(msg.contains("config.json"), "{msg}");
            }
            other => panic!("expected Auth error, got {other:?}"),
        }
    }

    #[test]
    fn acquire_refresh_token_reads_the_token() {
        let http = MemoryHttp::default().post(
            "https://catalog.example.com/api/login",
            json!({"refresh_token": "rt-abc"}),
        );
        assert_eq!(
            acquire_refresh_token("https://catalog.example.com", "admin", "hunter2", &http)
                .unwrap(),
            "rt-abc"
        );
        let calls = http.json_calls.lock().unwrap();
        assert_eq!(
            calls[0].1,
            json!({"username": "admin", "password": "hunter2"})
        );
    }

    #[test]
    fn acquire_refresh_token_missing_token_raises() {
        let http = MemoryHttp::default().post(
            "https://catalog.example.com/api/login",
            json!({"foo": "bar"}),
        );
        match acquire_refresh_token("https://catalog.example.com", "a", "b", &http) {
            Err(RegistryError::Auth(msg)) => {
                assert!(msg.contains("No refresh_token"), "{msg}");
                assert!(msg.contains("foo"), "{msg}");
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn exchange_uses_the_form_endpoint() {
        let http = MemoryHttp::default().form(
            "https://catalog.example.com/api/token",
            json!({"access_token": "at-xyz"}),
        );
        assert_eq!(
            exchange_refresh_token_for_access_token("https://catalog.example.com", "rt-abc", &http)
                .unwrap(),
            "at-xyz"
        );
        let calls = http.form_calls.lock().unwrap();
        assert_eq!(
            calls[0].1.get("refresh_token"),
            Some(&Value::String("rt-abc".into()))
        );
    }

    #[test]
    fn create_api_key_happy_path() {
        let http = MemoryHttp::default().post(
            "https://catalog.example.com/graphql",
            created(
                "qk_thesecret",
                "quiltx-host-20260504",
                "2027-05-04T00:00:00Z",
            ),
        );
        let out = create_api_key(
            "https://catalog.example.com",
            "at-xyz",
            "quiltx-host-20260504",
            365,
            &http,
        )
        .unwrap();
        assert_eq!(
            out.get("secret"),
            Some(&Value::String("qk_thesecret".into()))
        );
        assert_eq!(
            out.get("expires_at"),
            Some(&Value::String("2027-05-04T00:00:00Z".into()))
        );
        let calls = http.json_calls.lock().unwrap();
        assert_eq!(calls[0].2.as_deref(), Some("at-xyz"));
        assert_eq!(
            calls[0].1["variables"],
            json!({"input": {"name": "quiltx-host-20260504", "expiresInDays": 365}})
        );
        assert_eq!(calls[0].1["query"], API_KEY_CREATE_MUTATION);
    }

    #[test]
    fn create_api_key_invalid_input_and_graphql_errors() {
        let http = MemoryHttp::default().post(
            "https://catalog.example.com/graphql",
            json!({"data": {"apiKeyCreate": {"__typename": "InvalidInput", "errors": [{"path": "name"}]}}}),
        );
        match create_api_key("https://catalog.example.com", "at", "dup", 90, &http) {
            Err(RegistryError::Auth(msg)) => {
                assert!(msg.contains("rejected apiKeyCreate"), "{msg}")
            }
            other => panic!("{other:?}"),
        }
        let http = MemoryHttp::default().post(
            "https://catalog.example.com/graphql",
            json!({"errors": [{"message": "Unauthorized"}]}),
        );
        match create_api_key("https://catalog.example.com", "at", "x", 90, &http) {
            Err(RegistryError::Auth(msg)) => assert!(msg.contains("GraphQL errors"), "{msg}"),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn create_api_key_missing_secret_raises() {
        let http = MemoryHttp::default().post(
            "https://catalog.example.com/graphql",
            json!({"data": {"apiKeyCreate": {"__typename": "APIKeyCreated", "apiKey": {}, "secret": null}}}),
        );
        match create_api_key("https://catalog.example.com", "at", "x", 90, &http) {
            Err(RegistryError::Auth(msg)) => assert!(msg.contains("no secret"), "{msg}"),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn validate_api_key_happy_and_rejected() {
        let http = MemoryHttp::default().post(
            "https://reg.example.com/graphql",
            json!({"data": {"apiKeysList": {"apiKeys": []}}}),
        );
        validate_api_key("https://reg.example.com", "qk_test", &http).unwrap();
        let http = MemoryHttp::default().post(
            "https://reg.example.com/graphql",
            json!({"errors": [{"message": "Unauthorized"}]}),
        );
        match validate_api_key("https://reg.example.com", "qk_bad", &http) {
            Err(RegistryError::Auth(msg)) => assert!(msg.contains("rejected API key"), "{msg}"),
            other => panic!("{other:?}"),
        }
        let http = MemoryHttp::default().post_err(
            "https://reg.example.com/graphql",
            "Auth request to https://reg.example.com/graphql failed (401): Unauthorized",
        );
        match validate_api_key("https://reg.example.com", "qk_bad", &http) {
            Err(RegistryError::Auth(msg)) => assert!(msg.contains("401"), "{msg}"),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn validate_api_key_rejects_a_non_object_body() {
        let cases = [
            json!([]),
            Value::Null,
            json!("ok"),
            json!(1),
            json!(true),
            json!(""),
        ];
        for body in cases {
            let http = MemoryHttp::default().post("https://reg.example.com/graphql", body.clone());
            match validate_api_key("https://reg.example.com", "qk_test", &http) {
                Err(RegistryError::Auth(msg)) => {
                    assert!(
                        msg.starts_with(
                            "Unexpected response from https://reg.example.com/graphql:"
                        ),
                        "{msg}"
                    );
                    assert!(
                        msg.contains(&python_repr(&body)),
                        "{msg} vs {}",
                        python_repr(&body)
                    );
                }
                other => panic!("expected Auth error for {body}, got {other:?}"),
            }
        }
    }

    #[test]
    fn python_repr_escapes_controls_and_quotes_like_python() {
        assert_eq!(python_repr_str("hello"), "'hello'");
        assert_eq!(python_repr_str("it's"), "\"it's\"");
        assert_eq!(python_repr_str("a\"b"), "'a\"b'");
        assert_eq!(python_repr_str("a'b\"c"), "'a\\'b\"c'");
        assert_eq!(python_repr_str("line\nbreak"), "'line\\nbreak'");
        assert_eq!(python_repr_str("tab\there"), "'tab\\there'");
        assert_eq!(python_repr_str("cr\r"), "'cr\\r'");
        assert_eq!(python_repr_str("bell\u{07}"), "'bell\\x07'");
        assert_eq!(python_repr_str("null\u{00}"), "'null\\x00'");
        assert_eq!(python_repr_str("back\\slash"), "'back\\\\slash'");
        assert_eq!(python_repr_str(""), "''");
        assert_eq!(python_repr_str("del\u{7f}"), "'del\\x7f'");
        assert_eq!(
            python_repr(&json!({"errors": [{"message": "no\nkey and it's \"quoted\""}]})),
            "{'errors': [{'message': 'no\\nkey and it\\'s \"quoted\"'}]}"
        );
    }

    #[test]
    fn unexpected_create_result_redacts_the_secret_and_uses_none_for_missing_typename() {
        let http = MemoryHttp::default().post(
            "https://catalog.example.com/graphql",
            json!({"data": {"apiKeyCreate": {"secret": "qk_should_not_leak", "foo": 1}}}),
        );
        match create_api_key("https://catalog.example.com", "at", "x", 90, &http) {
            Err(RegistryError::Auth(msg)) => {
                assert!(
                    msg.contains("Unexpected apiKeyCreate result type None:"),
                    "{msg}"
                );
                assert!(!msg.contains("qk_should_not_leak"), "{msg}");
                assert!(msg.contains("<redacted>"), "{msg}");
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn error_text_escapes_newlines_in_graphql_errors() {
        let http = MemoryHttp::default().post(
            "https://catalog.example.com/graphql",
            json!({"errors": [{"message": "no\nkey and it's \"quoted\""}]}),
        );
        match create_api_key("https://catalog.example.com", "at", "x", 90, &http) {
            Err(RegistryError::Auth(msg)) => {
                assert!(msg.contains("GraphQL errors:"), "{msg}");
                assert!(
                    msg.contains("{'message': 'no\\nkey and it\\'s \"quoted\"'}"),
                    "{msg}"
                );
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn non_string_registry_url_is_stringified() {
        // Current behaviour, not a host / https check: a number or bool is
        // stringified the way Python's str() would be, then used as the base.
        let http = MemoryHttp::default().get(
            "https://catalog.example.com/config.json",
            json!({"registryUrl": 123}),
        );
        assert_eq!(
            resolve_registry_url("https://catalog.example.com", &http).unwrap(),
            "123"
        );
        let http = MemoryHttp::default().get(
            "https://catalog.example.com/config.json",
            json!({"registryUrl": true}),
        );
        assert_eq!(
            resolve_registry_url("https://catalog.example.com", &http).unwrap(),
            "True"
        );
    }

    #[test]
    fn python_repr_uses_python_for_c1_bidi_and_line_separators() {
        // C1, bidi marks, Zl/Zp: whatever Python's repr emits, we emit.
        Python::initialize();
        let cases = [
            "\u{80}",
            "\u{9f}",
            "\u{202e}",
            "\u{2028}",
            "\u{2029}",
            "\u{200e}",
            "\u{200f}",
            "hello\u{2028}world",
        ];
        for s in cases {
            let expected = Python::attach(|py| {
                PyString::new(py, s)
                    .repr()
                    .expect("Python repr")
                    .to_string()
            });
            assert_eq!(python_repr_str(s), expected, "{s:?}");
        }
    }

    #[test]
    fn error_text_redacts_qk_values_and_sensitive_keys() {
        // GraphQL errors: a qk_ message, plus token/password/apiKey fields.
        let http = MemoryHttp::default().post(
            "https://catalog.example.com/graphql",
            json!({"errors": [{
                "message": "qk_should_not_leak",
                "access_token": "refresh_abc",
                "PASSWORD": "hunter2",
                "apiKey": "qk_also_hidden",
                "SessionToken": "sts_tok",
                "hint": "not a secret"
            }]}),
        );
        match create_api_key("https://catalog.example.com", "at", "x", 90, &http) {
            Err(RegistryError::Auth(msg)) => {
                assert!(msg.contains("GraphQL errors:"), "{msg}");
                assert!(!msg.contains("qk_should_not_leak"), "{msg}");
                assert!(!msg.contains("qk_also_hidden"), "{msg}");
                assert!(!msg.contains("refresh_abc"), "{msg}");
                assert!(!msg.contains("hunter2"), "{msg}");
                assert!(!msg.contains("sts_tok"), "{msg}");
                assert!(msg.contains("<redacted>"), "{msg}");
                assert!(msg.contains("not a secret"), "{msg}");
            }
            other => panic!("{other:?}"),
        }

        // InvalidInput: same redaction on the errors list.
        let http = MemoryHttp::default().post(
            "https://catalog.example.com/graphql",
            json!({"data": {"apiKeyCreate": {
                "__typename": "InvalidInput",
                "errors": [{
                    "path": "name",
                    "message": "qk_in_the_message",
                    "token": "refresh_me"
                }]
            }}}),
        );
        match create_api_key("https://catalog.example.com", "at", "x", 90, &http) {
            Err(RegistryError::Auth(msg)) => {
                assert!(
                    msg.contains("Catalog rejected apiKeyCreate input:"),
                    "{msg}"
                );
                assert!(!msg.contains("qk_in_the_message"), "{msg}");
                assert!(!msg.contains("refresh_me"), "{msg}");
                assert!(msg.contains("<redacted>"), "{msg}");
            }
            other => panic!("{other:?}"),
        }
    }
}
