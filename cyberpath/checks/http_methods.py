import requests


class HTTPMethodsCheck:
    """Safely inspect HTTP methods advertised by a server."""

    def __init__(self, timeout=10):
        self.timeout = timeout

    def check(self, url):
        """
        Send an OPTIONS request and inspect the Allow header.
        This is a read-only check.
        """

        try:
            response = requests.options(
                url,
                timeout=self.timeout,
                allow_redirects=True,
            )

        except requests.RequestException as error:
            return {
                "rule": "HTTP_METHODS",
                "status": "INCONCLUSIVE",
                "target": url,
                "error": str(error),
                "findings": [],
            }

        allow_header = response.headers.get("Allow")

        methods = []

        if allow_header:
            methods = [
                method.strip().upper()
                for method in allow_header.split(",")
                if method.strip()
            ]

        return {
            "rule": "HTTP_METHODS",
            "status": "COMPLETED",
            "target": url,
            "http_status": response.status_code,
            "final_url": response.url,
            "allow_header": allow_header,
            "methods": methods,
            "findings": [],
        }