from cyberpath.checks.http_headers import HTTPSecurityHeadersCheck
from cyberpath.checks.http_methods import HTTPMethodsCheck
from cyberpath.checks.http_information import (
    HTTPInformationDisclosureCheck
)
from cyberpath.checks.https_headers import (
    HTTPSSecurityHeadersCheck
)
from cyberpath.checks.https_certificate import (
    HTTPSCertificateCheck
)
from cyberpath.checks.https_tls import (
    HTTPSTLSConfigurationCheck
)
from cyberpath.checks.ssh_version import (
    SSHVersionCheck
)
from cyberpath.checks.ssh_configuration import (
    SSHConfigurationCheck
)


class CheckExecutor:
    """Execute CyberPath security checks."""

    def __init__(self):
        self.checks = {
            "HTTP_SECURITY_HEADERS": (
                HTTPSecurityHeadersCheck()
            ),

            "HTTP_METHODS": (
                HTTPMethodsCheck()
            ),

            "HTTP_INFORMATION_DISCLOSURE": (
                HTTPInformationDisclosureCheck()
            ),

            "HTTPS_SECURITY_HEADERS": (
                HTTPSSecurityHeadersCheck()
            ),

            "HTTPS_CERTIFICATE": (
                HTTPSCertificateCheck()
            ),

            "HTTPS_TLS_CONFIGURATION": (
                HTTPSTLSConfigurationCheck()
            ),

            "SSH_VERSION": (
                SSHVersionCheck()
            ),

            "SSH_CONFIGURATION": (
                SSHConfigurationCheck()
            ),
        }

    def execute_rule(
        self,
        rule,
        target,
        port=None,
    ):
        """Execute one security rule against a target."""

        print(
            f"[DEBUG] Executing {rule} against {target}"
        )

        checker = self.checks.get(rule)

        if checker is None:
            return {
                "rule": rule,
                "status": "NOT_TESTED",
                "target": target,
                "findings": [],
                "error": (
                    "No checker registered for this rule."
                ),
            }

        if rule in {
            "SSH_VERSION",
            "SSH_CONFIGURATION",
        }:

            if port is None:
                return {
                    "rule": rule,
                    "status": "INCONCLUSIVE",
                    "target": target,
                    "findings": [],
                    "error": (
                        "SSH port was not provided."
                    ),
                }

            return checker.check(
                target,
                port,
            )

        return checker.check(target)

    def execute_rules(
        self,
        rules,
        target,
        port=None,
    ):
        """Execute multiple security rules."""

        results = []

        for rule in rules:

            result = self.execute_rule(
                rule,
                target,
                port,
            )

            results.append(result)

        return results
