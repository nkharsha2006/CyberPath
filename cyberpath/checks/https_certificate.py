import socket
import ssl
from datetime import datetime


class HTTPSCertificateCheck:
    """Inspect the TLS certificate of an HTTPS service."""

    def __init__(self, timeout=10):
        self.timeout = timeout

    def check(self, url):
        """
        Safely retrieve and inspect the TLS certificate.

        Expected URL format:
        https://hostname:port
        """

        try:
            hostname, port = self.parse_url(url)

            certificate_data = self.get_certificate(
                hostname,
                port,
            )

        except (OSError, ValueError, ssl.SSLError) as error:
            return {
                "rule": "HTTPS_CERTIFICATE",
                "status": "INCONCLUSIVE",
                "target": url,
                "error": str(error),
                "findings": [],
            }

        findings = []

        not_after = certificate_data.get(
            "not_after"
        )

        if not_after:

            try:
                expiry_date = datetime.strptime(
                    not_after,
                    "%b %d %H:%M:%S %Y %Z",
                )

                now = datetime.utcnow()

                if expiry_date < now:

                    findings.append({
                        "check": "CERTIFICATE_EXPIRY",
                        "status": "EXPIRED",
                        "severity": "HIGH",
                        "description": (
                            "The TLS certificate has expired."
                        ),
                    })

                else:

                    findings.append({
                        "check": "CERTIFICATE_EXPIRY",
                        "status": "VALID",
                        "severity": "INFO",
                        "description": (
                            "The TLS certificate has not expired."
                        ),
                    })

            except ValueError:

                findings.append({
                    "check": "CERTIFICATE_EXPIRY",
                    "status": "INCONCLUSIVE",
                    "severity": "INFO",
                    "description": (
                        "The certificate expiry date "
                        "could not be parsed."
                    ),
                })

        return {
            "rule": "HTTPS_CERTIFICATE",
            "status": "COMPLETED",
            "target": url,
            "certificate": certificate_data,
            "findings": findings,
        }

    def parse_url(self, url):
        """Extract hostname and port from an HTTPS URL."""

        if not url.startswith("https://"):
            raise ValueError(
                "HTTPS_CERTIFICATE requires an HTTPS URL."
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

    def get_certificate(self, hostname, port):
        """Retrieve the peer TLS certificate."""

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

                certificate = tls_socket.getpeercert()

                if not certificate:
                    raise ssl.SSLError(
                        "No TLS certificate was returned."
                    )

                return {
                    "subject": self.get_subject(
                        certificate
                    ),
                    "issuer": self.get_issuer(
                        certificate
                    ),
                    "serial_number": certificate.get(
                        "serialNumber"
                    ),
                    "version": certificate.get(
                        "version"
                    ),
                    "not_before": certificate.get(
                        "notBefore"
                    ),
                    "not_after": certificate.get(
                        "notAfter"
                    ),
                    "san": self.get_san(
                        certificate
                    ),
                }

    def get_subject(self, certificate):
        """Extract certificate subject."""

        subject = {}

        for item in certificate.get(
            "subject",
            (),
        ):

            for key, value in item:
                subject[key] = value

        return subject

    def get_issuer(self, certificate):
        """Extract certificate issuer."""

        issuer = {}

        for item in certificate.get(
            "issuer",
            (),
        ):

            for key, value in item:
                issuer[key] = value

        return issuer

    def get_san(self, certificate):
        """Extract Subject Alternative Names."""

        san = []

        for item in certificate.get(
            "subjectAltName",
            (),
        ):

            san.append({
                "type": item[0],
                "value": item[1],
            })

        return san
