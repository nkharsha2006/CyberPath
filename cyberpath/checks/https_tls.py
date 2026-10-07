import socket
import ssl


class HTTPSTLSConfigurationCheck:
    """Inspect the TLS configuration of an HTTPS service."""

    def __init__(self, timeout=10):
        self.timeout = timeout

    def check(self, url):
        """
        Establish a TLS connection and inspect the
        negotiated TLS version and cipher.
        """

        try:
            hostname, port = self.parse_url(url)

            tls_data = self.inspect_tls(
                hostname,
                port,
            )

        except (OSError, ValueError, ssl.SSLError) as error:
            return {
                "rule": "HTTPS_TLS_CONFIGURATION",
                "status": "INCONCLUSIVE",
                "target": url,
                "error": str(error),
                "findings": [],
            }

        findings = []

        tls_version = tls_data.get(
            "tls_version"
        )

        cipher = tls_data.get(
            "cipher"
        )

        if tls_version in {
            "TLSv1",
            "TLSv1.1",
            "SSLv3",
            "SSLv2",
        }:

            findings.append({
                "check": "TLS_VERSION",
                "status": "WEAK",
                "severity": "HIGH",
                "value": tls_version,
                "description": (
                    f"The server negotiated the weak "
                    f"TLS protocol version {tls_version}."
                ),
            })

        elif tls_version:

            findings.append({
                "check": "TLS_VERSION",
                "status": "ACCEPTABLE",
                "severity": "INFO",
                "value": tls_version,
                "description": (
                    f"The server negotiated "
                    f"{tls_version}."
                ),
            })

        else:

            findings.append({
                "check": "TLS_VERSION",
                "status": "INCONCLUSIVE",
                "severity": "INFO",
                "value": None,
                "description": (
                    "The negotiated TLS version "
                    "could not be determined."
                ),
            })

        if cipher:

            cipher_name = cipher[0]

            findings.append({
                "check": "TLS_CIPHER",
                "status": "OBSERVED",
                "severity": "INFO",
                "value": cipher_name,
                "description": (
                    f"The negotiated TLS cipher was "
                    f"{cipher_name}."
                ),
            })

        else:

            findings.append({
                "check": "TLS_CIPHER",
                "status": "INCONCLUSIVE",
                "severity": "INFO",
                "value": None,
                "description": (
                    "The negotiated TLS cipher "
                    "could not be determined."
                ),
            })

        return {
            "rule": "HTTPS_TLS_CONFIGURATION",
            "status": "COMPLETED",
            "target": url,
            "tls": tls_data,
            "findings": findings,
        }

    def parse_url(self, url):
        """Extract hostname and port from an HTTPS URL."""

        if not url.startswith("https://"):
            raise ValueError(
                "HTTPS_TLS_CONFIGURATION requires "
                "an HTTPS URL."
            )

        address = url[len("https://"):]

        if "/" in address:
            address = address.split("/", 1)[0]

        if ":" in address:

            hostname, port = address.rsplit(
                ":",
                1,
            )

            return hostname, int(port)

        return address, 443

    def inspect_tls(self, hostname, port):
        """Create a TLS connection and inspect it."""

        context = ssl.create_default_context()

        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

        with socket.create_connection(
            (hostname, port),
            timeout=self.timeout,
        ) as sock:

            with context.wrap_socket(
                sock,
                server_hostname=hostname,
            ) as tls_socket:

                return {
                    "tls_version": (
                        tls_socket.version()
                    ),
                    "cipher": (
                        tls_socket.cipher()
                    ),
                }