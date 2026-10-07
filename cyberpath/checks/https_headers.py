import requests


class HTTPSSecurityHeadersCheck:
    """Check important security headers on HTTPS services."""

    REQUIRED_HEADERS = {
        "Strict-Transport-Security": {
            "severity": "MEDIUM",
            "description": (
                "Helps enforce HTTPS connections."
            ),
        },
        "Content-Security-Policy": {
            "severity": "MEDIUM",
            "description": (
                "Helps reduce the risk of content injection attacks."
            ),
        },
        "X-Content-Type-Options": {
            "severity": "LOW",
            "description": (
                "Helps prevent MIME-type sniffing."
            ),
        },
        "X-Frame-Options": {
            "severity": "LOW",
            "description": (
                "Helps protect against clickjacking."
            ),
        },
        "Referrer-Policy": {
            "severity": "LOW",
            "description": (
                "Controls how much referrer information is sent."
            ),
        },
    }

    def __init__(self, timeout=10):
        self.timeout = timeout

    def check(self, url):
        """
        Perform a safe HTTPS HEAD request and inspect
        the returned security headers.
        """

        try:
            response = requests.head(
                url,
                timeout=self.timeout,
                allow_redirects=True,
                verify=False,
            )

        except requests.RequestException as error:
            return {
                "rule": "HTTPS_SECURITY_HEADERS",
                "status": "INCONCLUSIVE",
                "target": url,
                "error": str(error),
                "findings": [],
            }

        findings = []

        headers = {
            key.lower(): value
            for key, value in response.headers.items()
        }

        for header, information in self.REQUIRED_HEADERS.items():

            if header.lower() not in headers:

                findings.append({
                    "header": header,
                    "status": "MISSING",
                    "severity": information["severity"],
                    "description": information["description"],
                })

            else:

                findings.append({
                    "header": header,
                    "status": "PRESENT",
                    "severity": "INFO",
                    "description": information["description"],
                })

        return {
            "rule": "HTTPS_SECURITY_HEADERS",
            "status": "COMPLETED",
            "target": url,
            "http_status": response.status_code,
            "final_url": response.url,
            "findings": findings,
        }