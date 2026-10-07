class RuleEngine:
    """Select security checks based on target context."""

    def __init__(self, context):
        self.context = context

    def get_rules(self):
        """Return security rules applicable to the target."""

        rules = []

        applicable_checks = self.context.get(
            "applicable_checks", []
        )

        if "HTTP" in applicable_checks:
            rules.extend([
                "HTTP_SECURITY_HEADERS",
                "HTTP_METHODS",
                "HTTP_INFORMATION_DISCLOSURE",
            ])

        if "HTTPS" in applicable_checks:
            rules.extend([
                "HTTPS_TLS_CONFIGURATION",
                "HTTPS_SECURITY_HEADERS",
                "HTTPS_CERTIFICATE",
            ])

        if "SSH" in applicable_checks:
            rules.extend([
                "SSH_VERSION",
                "SSH_CONFIGURATION",
            ])

        return rules

    def build_execution_plan(self):
        """Build the security-check execution plan."""

        rules = self.get_rules()

        return {
            "total_rules": len(rules),
            "rules": rules,
        }