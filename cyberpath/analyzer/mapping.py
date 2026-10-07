class SecurityMapping:
    """Map CyberPath findings to security standards."""

    MAPPINGS = {
        "Strict-Transport-Security": {
            "owasp": "A05:2025 - Security Misconfiguration",
            "cwe": "CWE-319 - Cleartext Transmission of Sensitive Information",
        },

        "Content-Security-Policy": {
            "owasp": "A05:2025 - Security Misconfiguration",
            "cwe": "CWE-693 - Protection Mechanism Failure",
        },

        "X-Content-Type-Options": {
            "owasp": "A05:2025 - Security Misconfiguration",
            "cwe": "CWE-693 - Protection Mechanism Failure",
        },

        "X-Frame-Options": {
            "owasp": "A05:2025 - Security Misconfiguration",
            "cwe": "CWE-693 - Protection Mechanism Failure",
        },

        "Referrer-Policy": {
            "owasp": "A05:2025 - Security Misconfiguration",
            "cwe": "CWE-693 - Protection Mechanism Failure",
        },
    }

    @classmethod
    def get_mapping(cls, header):
        """Return OWASP and CWE information for a header."""

        return cls.MAPPINGS.get(
            header,
            {
                "owasp": "Not mapped",
                "cwe": "Not mapped",
            },
        )