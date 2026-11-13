//! API-key resolution ladder.
//!
//! A port of the non-interactive decision in `quiltx.auth.resolve`.
//! Reading flags, environment variables, the credential store, and the
//! TTY, and running the interactive `mint_api_key` flow, stay in Python.
//! This module takes those already-read inputs and returns the same
//! result or error message the Python ladder produced.

/// The public outcome of the resolve ladder, before any interactive mint.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResolveResult {
    Found {
        api_key: String,
        source: &'static str,
    },
    /// CLI only: no flag/env/store key, and prompting is allowed.
    NeedInteractive {
        rejected: bool,
    },
    Error(String),
}

fn nonempty(value: Option<&str>) -> Option<&str> {
    value.filter(|s| !s.is_empty())
}

fn cli_error(dns: &str) -> String {
    format!(
        "No API key available for {dns}. \
         Provide --api-key, set QUILTX_API_KEY, \
         or run `quiltx catalog api-key --catalog {dns}` interactively."
    )
}

fn api_error(dns: &str) -> String {
    format!(
        "No API key available for {dns}. \
         Pass api_key=... to Catalog.from_dns, set QUILTX_API_KEY, \
         or run a CLI command first to store one."
    )
}

/// Resolve an API key from already-read sources.
///
/// `provided` is the `--api-key` flag or the `api_key=` kwarg. `stored_key`
/// is `Some` only when a store entry exists (even if the key is empty).
/// `mode` is `"cli"` or `"api"`.
pub fn resolve_credentials(
    dns: &str,
    provided: Option<&str>,
    env_key: Option<&str>,
    stored_key: Option<&str>,
    skip_keyring: bool,
    allow_interactive: bool,
    mode: &str,
) -> ResolveResult {
    if let Some(api_key) = nonempty(provided) {
        return ResolveResult::Found {
            api_key: api_key.to_string(),
            source: "flag",
        };
    }
    if let Some(api_key) = nonempty(env_key) {
        return ResolveResult::Found {
            api_key: api_key.to_string(),
            source: "env",
        };
    }
    if !skip_keyring {
        if let Some(api_key) = stored_key {
            return ResolveResult::Found {
                api_key: api_key.to_string(),
                source: "keyring",
            };
        }
    }
    if mode == "cli" && allow_interactive {
        return ResolveResult::NeedInteractive {
            rejected: skip_keyring,
        };
    }
    ResolveResult::Error(if mode == "cli" {
        cli_error(dns)
    } else {
        api_error(dns)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flag_wins_over_env_and_store() {
        let got = resolve_credentials(
            "nightly.example",
            Some("qk_flag"),
            Some("qk_env"),
            Some("qk_stored"),
            false,
            false,
            "cli",
        );
        assert_eq!(
            got,
            ResolveResult::Found {
                api_key: "qk_flag".into(),
                source: "flag",
            }
        );
    }

    #[test]
    fn empty_provided_falls_through_to_env() {
        let got = resolve_credentials(
            "nightly.example",
            Some(""),
            Some("qk_env"),
            Some("qk_stored"),
            false,
            false,
            "cli",
        );
        assert_eq!(
            got,
            ResolveResult::Found {
                api_key: "qk_env".into(),
                source: "env",
            }
        );
    }

    #[test]
    fn stored_key_is_used_even_when_empty() {
        let got = resolve_credentials("nightly.example", None, None, Some(""), false, false, "api");
        assert_eq!(
            got,
            ResolveResult::Found {
                api_key: "".into(),
                source: "keyring",
            }
        );
    }

    #[test]
    fn skip_keyring_ignores_a_stored_key() {
        match resolve_credentials(
            "nightly.example",
            None,
            None,
            Some("qk_stored"),
            true,
            false,
            "api",
        ) {
            ResolveResult::Error(msg) => {
                assert!(msg.contains("No API key available for nightly.example"));
                assert!(msg.contains("Pass api_key=..."));
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn cli_interactive_asks_for_a_mint() {
        assert_eq!(
            resolve_credentials("nightly.example", None, None, None, false, true, "cli"),
            ResolveResult::NeedInteractive { rejected: false }
        );
        assert_eq!(
            resolve_credentials("nightly.example", None, None, Some("qk"), true, true, "cli"),
            ResolveResult::NeedInteractive { rejected: true }
        );
    }

    #[test]
    fn cli_headless_error_names_the_catalog_and_how_to_fix_it() {
        match resolve_credentials("nightly.example", None, None, None, false, false, "cli") {
            ResolveResult::Error(msg) => {
                assert_eq!(
                    msg,
                    "No API key available for nightly.example. \
                     Provide --api-key, set QUILTX_API_KEY, \
                     or run `quiltx catalog api-key --catalog nightly.example` interactively."
                );
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn api_never_asks_for_a_mint() {
        match resolve_credentials("nightly.example", None, None, None, false, true, "api") {
            ResolveResult::Error(msg) => {
                assert_eq!(
                    msg,
                    "No API key available for nightly.example. \
                     Pass api_key=... to Catalog.from_dns, set QUILTX_API_KEY, \
                     or run a CLI command first to store one."
                );
            }
            other => panic!("{other:?}"),
        }
    }
}
