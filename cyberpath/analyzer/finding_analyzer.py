from cyberpath.analyzer.mapping import SecurityMapping


class FindingAnalyzer:
    """Analyze raw security-check results."""

    def __init__(self, check_result):
        self.check_result = check_result

    def analyze(self):
        """Convert raw security-check evidence into structured findings."""

        rule = self.check_result.get("rule")
        status = self.check_result.get("status")

        if status == "INCONCLUSIVE":
            return {
                "rule": rule,
                "target": self.check_result.get("target"),
                "status": "INCONCLUSIVE",
                "confidence": "LOW",
                "findings": [],
                "error": self.check_result.get("error"),
            }

        if rule == "HTTP_SECURITY_HEADERS":
            findings = self.analyze_security_headers()

        elif rule == "HTTP_METHODS":
            findings = self.analyze_http_methods()

        elif rule == "HTTP_INFORMATION_DISCLOSURE":
            findings = self.analyze_information_disclosure()

        elif rule == "HTTPS_SECURITY_HEADERS":
            findings = self.analyze_https_security_headers()

        elif rule == "HTTPS_CERTIFICATE":
            findings = self.analyze_https_certificate()

        elif rule == "HTTPS_TLS_CONFIGURATION":
            findings = self.analyze_https_tls_configuration()

        elif rule == "SSH_VERSION":
            findings = self.analyze_ssh_version()

        elif rule == "SSH_CONFIGURATION":
            findings = self.analyze_ssh_configuration()

        else:
            findings = []

        return {
            "rule": rule,
            "target": self.check_result.get("target"),
            "status": "COMPLETED",
            "confidence": self.get_overall_confidence(
                findings
            ),
            "findings": findings,
        }

    def analyze_security_headers(self):
        """Analyze HTTP security-header results."""

        findings = []

        for item in self.check_result.get(
            "findings",
            [],
        ):

            header = item.get("header")
            header_status = item.get("status")
            severity = item.get("severity")

            mapping = SecurityMapping.get_mapping(
                header
            )

            if header_status == "MISSING":

                findings.append({
                    "title": (
                        f"Missing {header} security header"
                    ),
                    "status": "POTENTIAL",
                    "severity": severity,
                    "confidence": "MEDIUM",
                    "evidence": {
                        "header": header,
                        "observed": "MISSING",
                    },
                    "description": item.get(
                        "description"
                    ),
                    "remediation": self.get_remediation(
                        header
                    ),
                    "owasp": mapping["owasp"],
                    "cwe": mapping["cwe"],
                })

            elif header_status == "PRESENT":

                findings.append({
                    "title": (
                        f"{header} security header present"
                    ),
                    "status": "PASS",
                    "severity": "INFO",
                    "confidence": "HIGH",
                    "evidence": {
                        "header": header,
                        "observed": "PRESENT",
                    },
                    "description": item.get(
                        "description"
                    ),
                    "remediation": None,
                    "owasp": mapping["owasp"],
                    "cwe": mapping["cwe"],
                })

        return findings

    def analyze_http_methods(self):
        """Analyze HTTP methods advertised by the server."""

        methods = self.check_result.get(
            "methods",
            [],
        )

        findings = []

        risky_methods = {
            "TRACE": {
                "severity": "LOW",
                "description": (
                    "TRACE is advertised by the server. "
                    "Review whether this method is required."
                ),
            },
            "PUT": {
                "severity": "LOW",
                "description": (
                    "PUT is advertised by the server. "
                    "Verify that authorization controls are "
                    "properly enforced."
                ),
            },
            "DELETE": {
                "severity": "LOW",
                "description": (
                    "DELETE is advertised by the server. "
                    "Verify that authorization controls are "
                    "properly enforced."
                ),
            },
        }

        for method, information in risky_methods.items():

            if method in methods:

                findings.append({
                    "title": (
                        f"HTTP method {method} is advertised"
                    ),
                    "status": "POTENTIAL",
                    "severity": information["severity"],
                    "confidence": "LOW",
                    "evidence": {
                        "method": method,
                        "observed": "ADVERTISED",
                        "allow_header": (
                            self.check_result.get(
                                "allow_header"
                            )
                        ),
                    },
                    "description": information["description"],
                    "remediation": (
                        f"Disable {method} if it is not "
                        "required. If required, verify "
                        "strong authorization controls."
                    ),
                    "owasp": (
                        "A05:2025 - Security Misconfiguration"
                    ),
                    "cwe": (
                        "CWE-749 - Exposed Dangerous Method "
                        "or Function"
                    ),
                })

        if not methods:

            findings.append({
                "title": "HTTP Allow methods not observed",
                "status": "INFO",
                "severity": "INFO",
                "confidence": "MEDIUM",
                "evidence": {
                    "allow_header": (
                        self.check_result.get(
                            "allow_header"
                        )
                    ),
                    "observed_methods": [],
                },
                "description": (
                    "No HTTP methods were observed in "
                    "the Allow header."
                ),
                "remediation": None,
                "owasp": "Not mapped",
                "cwe": "Not mapped",
            })

        return findings

    def analyze_information_disclosure(self):
        """Analyze exposed server and technology information."""

        findings = []

        for item in self.check_result.get(
            "findings",
            [],
        ):

            header = item.get("header")
            value = item.get("value")
            status = item.get("status")

            if status == "DISCLOSED":

                findings.append({
                    "title": (
                        f"Information disclosure through "
                        f"{header} header"
                    ),
                    "status": "POTENTIAL",
                    "severity": item.get(
                        "severity",
                        "LOW",
                    ),
                    "confidence": "MEDIUM",
                    "evidence": {
                        "header": header,
                        "observed": value,
                    },
                    "description": item.get(
                        "description"
                    ),
                    "remediation": (
                        f"Review whether the {header} header "
                        "needs to be exposed. Remove or minimize "
                        "unnecessary software and technology "
                        "information."
                    ),
                    "owasp": (
                        "A05:2025 - Security Misconfiguration"
                    ),
                    "cwe": (
                        "CWE-200 - Exposure of Sensitive "
                        "Information to an Unauthorized Actor"
                    ),
                })

            elif status == "NOT_OBSERVED":

                findings.append({
                    "title": (
                        f"{header} information not observed"
                    ),
                    "status": "PASS",
                    "severity": "INFO",
                    "confidence": "MEDIUM",
                    "evidence": {
                        "header": header,
                        "observed": "NOT_OBSERVED",
                    },
                    "description": item.get(
                        "description"
                    ),
                    "remediation": None,
                    "owasp": "Not mapped",
                    "cwe": "Not mapped",
                })

        return findings

    def analyze_https_security_headers(self):
        """Analyze HTTPS security-header results."""

        findings = []

        for item in self.check_result.get(
            "findings",
            [],
        ):

            header = item.get("header")
            header_status = item.get("status")
            severity = item.get("severity")

            if header_status == "MISSING":

                findings.append({
                    "title": (
                        f"Missing {header} security header "
                        "on HTTPS service"
                    ),
                    "status": "POTENTIAL",
                    "severity": severity,
                    "confidence": "MEDIUM",
                    "evidence": {
                        "header": header,
                        "observed": "MISSING",
                    },
                    "description": item.get(
                        "description"
                    ),
                    "remediation": (
                        f"Configure {header} appropriately "
                        "on the HTTPS service."
                    ),
                    "owasp": (
                        "A05:2025 - Security Misconfiguration"
                    ),
                    "cwe": (
                        "CWE-693 - Protection Mechanism Failure"
                    ),
                })

            elif header_status == "PRESENT":

                findings.append({
                    "title": (
                        f"{header} security header present "
                        "on HTTPS service"
                    ),
                    "status": "PASS",
                    "severity": "INFO",
                    "confidence": "HIGH",
                    "evidence": {
                        "header": header,
                        "observed": "PRESENT",
                    },
                    "description": item.get(
                        "description"
                    ),
                    "remediation": None,
                    "owasp": (
                        "A05:2025 - Security Misconfiguration"
                    ),
                    "cwe": (
                        "CWE-693 - Protection Mechanism Failure"
                    ),
                })

        return findings

    def analyze_https_certificate(self):
        """Analyze HTTPS certificate results."""

        findings = []

        certificate = self.check_result.get(
            "certificate",
            {},
        )

        for item in self.check_result.get(
            "findings",
            [],
        ):

            check = item.get("check")
            status = item.get("status")

            if check == "CERTIFICATE_EXPIRY":

                if status == "EXPIRED":

                    findings.append({
                        "title": (
                            "HTTPS certificate is expired"
                        ),
                        "status": "FAIL",
                        "severity": "HIGH",
                        "confidence": "HIGH",
                        "evidence": {
                            "not_after": certificate.get(
                                "not_after"
                            ),
                        },
                        "description": item.get(
                            "description"
                        ),
                        "remediation": (
                            "Renew and correctly deploy the "
                            "TLS certificate before its expiry."
                        ),
                        "owasp": (
                            "A05:2025 - Security Misconfiguration"
                        ),
                        "cwe": (
                            "CWE-298 - Improper Validation "
                            "of Certificate Expiration"
                        ),
                    })

                elif status == "VALID":

                    findings.append({
                        "title": (
                            "HTTPS certificate is not expired"
                        ),
                        "status": "PASS",
                        "severity": "INFO",
                        "confidence": "HIGH",
                        "evidence": {
                            "not_after": certificate.get(
                                "not_after"
                            ),
                        },
                        "description": item.get(
                            "description"
                        ),
                        "remediation": None,
                        "owasp": "Not mapped",
                        "cwe": "Not mapped",
                    })

        return findings

    def analyze_https_tls_configuration(self):
        """Analyze HTTPS TLS configuration results."""

        findings = []

        for item in self.check_result.get(
            "findings",
            [],
        ):

            check = item.get("check")
            status = item.get("status")
            value = item.get("value")

            if check == "TLS_VERSION":

                if status == "WEAK":

                    findings.append({
                        "title": (
                            f"Weak TLS protocol version: {value}"
                        ),
                        "status": "FAIL",
                        "severity": "HIGH",
                        "confidence": "HIGH",
                        "evidence": {
                            "tls_version": value,
                        },
                        "description": item.get(
                            "description"
                        ),
                        "remediation": (
                            "Disable obsolete TLS protocol "
                            "versions and require modern TLS."
                        ),
                        "owasp": (
                            "A02:2025 - Cryptographic Failures"
                        ),
                        "cwe": (
                            "CWE-326 - Inadequate Encryption Strength"
                        ),
                    })

                elif status == "ACCEPTABLE":

                    findings.append({
                        "title": (
                            f"TLS protocol negotiated: {value}"
                        ),
                        "status": "PASS",
                        "severity": "INFO",
                        "confidence": "HIGH",
                        "evidence": {
                            "tls_version": value,
                        },
                        "description": item.get(
                            "description"
                        ),
                        "remediation": None,
                        "owasp": "Not mapped",
                        "cwe": "Not mapped",
                    })

                else:

                    findings.append({
                        "title": (
                            "TLS protocol version could "
                            "not be determined"
                        ),
                        "status": "INCONCLUSIVE",
                        "severity": "INFO",
                        "confidence": "LOW",
                        "evidence": {
                            "tls_version": value,
                        },
                        "description": item.get(
                            "description"
                        ),
                        "remediation": None,
                        "owasp": "Not mapped",
                        "cwe": "Not mapped",
                    })

            elif check == "TLS_CIPHER":

                if status == "OBSERVED":

                    findings.append({
                        "title": (
                            f"TLS cipher observed: {value}"
                        ),
                        "status": "INFO",
                        "severity": "INFO",
                        "confidence": "HIGH",
                        "evidence": {
                            "cipher": value,
                        },
                        "description": item.get(
                            "description"
                        ),
                        "remediation": None,
                        "owasp": "Not mapped",
                        "cwe": "Not mapped",
                    })

                else:

                    findings.append({
                        "title": (
                            "TLS cipher could not "
                            "be determined"
                        ),
                        "status": "INCONCLUSIVE",
                        "severity": "INFO",
                        "confidence": "LOW",
                        "evidence": {
                            "cipher": value,
                        },
                        "description": item.get(
                            "description"
                        ),
                        "remediation": None,
                        "owasp": "Not mapped",
                        "cwe": "Not mapped",
                    })

        return findings

    def analyze_ssh_version(self):
        """Analyze SSH server identification information."""

        findings = []

        banner = self.check_result.get(
            "banner"
        )

        if not banner:
            return findings

        findings.append({
            "title": "SSH server identification observed",
            "status": "INFO",
            "severity": "INFO",
            "confidence": "HIGH",
            "evidence": {
                "banner": banner,
            },
            "description": (
                "The SSH server exposed its identification "
                "banner. This information can help identify "
                "the SSH implementation and version."
            ),
            "remediation": (
                "Review whether exposing detailed SSH "
                "implementation information is necessary."
            ),
            "owasp": (
                "A05:2025 - Security Misconfiguration"
            ),
            "cwe": (
                "CWE-200 - Exposure of Sensitive "
                "Information to an Unauthorized Actor"
            ),
        })

        return findings

    def analyze_ssh_configuration(self):
        """Analyze SSH configuration evidence."""

        findings = []

        for item in self.check_result.get(
            "findings",
            [],
        ):

            check = item.get("check")
            status = item.get("status")
            value = item.get("value")

            if check == "SSH_PROTOCOL_VERSION":

                if status == "PASS":

                    findings.append({
                        "title": (
                            "SSH-2.0 protocol is in use"
                        ),
                        "status": "PASS",
                        "severity": "INFO",
                        "confidence": "HIGH",
                        "evidence": {
                            "protocol": value,
                        },
                        "description": item.get(
                            "description"
                        ),
                        "remediation": None,
                        "owasp": "Not mapped",
                        "cwe": "Not mapped",
                    })

                elif status == "WEAK":

                    findings.append({
                        "title": (
                            "Obsolete SSH protocol version detected"
                        ),
                        "status": "FAIL",
                        "severity": "HIGH",
                        "confidence": "HIGH",
                        "evidence": {
                            "protocol": value,
                        },
                        "description": item.get(
                            "description"
                        ),
                        "remediation": (
                            "Disable obsolete SSH protocol "
                            "versions and require SSH-2."
                        ),
                        "owasp": (
                            "A02:2025 - Cryptographic Failures"
                        ),
                        "cwe": (
                            "Not mapped"
                        ),
                    })

                else:

                    findings.append({
                        "title": (
                            "SSH protocol version could "
                            "not be determined"
                        ),
                        "status": "INCONCLUSIVE",
                        "severity": "INFO",
                        "confidence": "LOW",
                        "evidence": {
                            "protocol": value,
                        },
                        "description": item.get(
                            "description"
                        ),
                        "remediation": None,
                        "owasp": "Not mapped",
                        "cwe": "Not mapped",
                    })

            elif check == "SSH_SERVER_IDENTIFICATION":

                if status == "OBSERVED":

                    findings.append({
                        "title": (
                            "SSH server identification observed"
                        ),
                        "status": "INFO",
                        "severity": "INFO",
                        "confidence": "HIGH",
                        "evidence": {
                            "banner": value,
                        },
                        "description": item.get(
                            "description"
                        ),
                        "remediation": (
                            "Review whether detailed SSH "
                            "implementation information "
                            "needs to be exposed."
                        ),
                        "owasp": (
                            "A05:2025 - Security Misconfiguration"
                        ),
                        "cwe": (
                            "CWE-200 - Exposure of Sensitive "
                            "Information to an Unauthorized Actor"
                        ),
                    })

        return findings

    def get_overall_confidence(self, findings):
        """Calculate overall confidence."""

        if not findings:
            return "LOW"

        confidence_values = {
            "HIGH": 3,
            "MEDIUM": 2,
            "LOW": 1,
        }

        highest = max(
            confidence_values.get(
                finding.get("confidence"),
                1,
            )
            for finding in findings
        )

        if highest == 3:
            return "HIGH"

        if highest == 2:
            return "MEDIUM"

        return "LOW"

    def get_remediation(self, header):
        """Return remediation advice for a missing header."""

        remediation = {
            "Strict-Transport-Security": (
                "Configure Strict-Transport-Security "
                "after HTTPS is correctly deployed."
            ),

            "Content-Security-Policy": (
                "Define and deploy an appropriate "
                "Content-Security-Policy."
            ),

            "X-Content-Type-Options": (
                "Configure X-Content-Type-Options "
                "with the value nosniff."
            ),

            "X-Frame-Options": (
                "Configure X-Frame-Options or an appropriate "
                "CSP frame-ancestors policy."
            ),

            "Referrer-Policy": (
                "Configure an appropriate Referrer-Policy "
                "for the application."
            ),
        }

        return remediation.get(
            header,
            "Review and configure the appropriate "
            "security header.",
        )
