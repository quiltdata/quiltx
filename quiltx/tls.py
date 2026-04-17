"""TLS configuration overrides for environments with corporate proxies or self-signed certs."""

from __future__ import annotations

import os
import sys


def apply_tls_overrides(ca_bundle: str | None = None, insecure: bool = False) -> None:
    """Apply process-wide TLS settings before HTTP clients are initialized.

    Args:
        ca_bundle: Path to a PEM file with additional trusted CAs (e.g. a corporate root).
        insecure: If True, disable TLS certificate verification entirely. Use only on
            trusted networks; a loud warning is printed to stderr.
    """
    if ca_bundle:
        if not os.path.isfile(ca_bundle):
            raise FileNotFoundError(f"CA bundle not found: {ca_bundle}")
        os.environ["SSL_CERT_FILE"] = ca_bundle
        os.environ["REQUESTS_CA_BUNDLE"] = ca_bundle
        os.environ["CURL_CA_BUNDLE"] = ca_bundle

    if insecure:
        import ssl

        print(
            "WARNING: TLS certificate verification disabled (--insecure). "
            "Only use on trusted networks.",
            file=sys.stderr,
        )
        ssl._create_default_https_context = ssl._create_unverified_context  # type: ignore[assignment]

        try:
            import urllib3

            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        except ImportError:
            pass

        try:
            import requests  # type: ignore

            _orig = requests.Session.merge_environment_settings

            def _merge(self, url, proxies, stream, verify, cert):
                settings = _orig(self, url, proxies, stream, verify, cert)
                settings["verify"] = False
                return settings

            requests.Session.merge_environment_settings = _merge
        except ImportError:
            pass
