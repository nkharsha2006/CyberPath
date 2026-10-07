import requests


class HTTPInformationDisclosureCheck:
    """Check for exposed server and technology information."""

    DISCLOSURE_HEADERS = {
        "Server": {
            "severity": "LOW",
            "description": (
                "The Server header may disclose information "
                "about the web server software."
            ),
        },
        "X-Powered-By": {
            "severity": "LOW",
            "description": (
                "The X-Powered-By header may disclose "
                "information about application technology."
            ),
        },
    }

    def __init__(self, timeout=10):
        self.timeout = timeout

    def check(self, url):
        """
        Perform a safe HTTP GET request and inspect
        response headers for technology disclosure.
        """

        try:
            response = requests.get(
                url,
                timeout=self.timeout,
                allow_redirects=True,
                stream=True,
            )

        except requests.RequestException as error:
            return {
                "rule": "HTTP_INFORMATION_DISCLOSURE",
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

        for header, information in self.DISCLOSURE_HEADERS.items():

            value = headers.get(header.lower())

            if value:

                findings.append({
                    "header": header,
                    "value": value,
                    "status": "DISCLOSED",
                    "severity": information["severity"],
                    "description": information["description"],
                })

            else:

                findings.append({
                    "header": header,
                    "value": None,
                    "status": "NOT_OBSERVED",
                    "severity": "INFO",
                    "description": information["description"],
                })

        response.close()

        return {
            "rule": "HTTP_INFORMATION_DISCLOSURE",
            "status": "COMPLETED",
            "target": url,
            "http_status": response.status_code,
            "final_url": response.url,
            "findings": findings,
        }