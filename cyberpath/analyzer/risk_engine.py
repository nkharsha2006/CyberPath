class RiskEngine:
    """Calculate risk scores and priorities for security findings."""

    SEVERITY_SCORES = {
        "CRITICAL": 10,
        "HIGH": 8,
        "MEDIUM": 5,
        "LOW": 2,
        "INFO": 0,
    }

    CONFIDENCE_MULTIPLIERS = {
        "HIGH": 1.0,
        "MEDIUM": 0.75,
        "LOW": 0.5,
    }

    def __init__(self, analysis):
        self.analysis = analysis

    def calculate_score(self, severity, confidence):
        """Calculate a risk score from severity and confidence."""

        severity_score = self.SEVERITY_SCORES.get(
            severity.upper(),
            0,
        )

        confidence_multiplier = self.CONFIDENCE_MULTIPLIERS.get(
            confidence.upper(),
            0.5,
        )

        return round(
            severity_score * confidence_multiplier,
            2,
        )

    def get_priority(self, score):
        """Convert the numerical risk score into a priority."""

        if score >= 8:
            return "CRITICAL"

        if score >= 6:
            return "HIGH"

        if score >= 3:
            return "MEDIUM"

        if score > 0:
            return "LOW"

        return "INFO"

    def analyze(self):
        """Add risk score and priority to every finding."""

        findings = []

        for finding in self.analysis.get("findings", []):

            severity = finding.get(
                "severity",
                "INFO",
            )

            confidence = finding.get(
                "confidence",
                "LOW",
            )

            score = self.calculate_score(
                severity,
                confidence,
            )

            priority = self.get_priority(score)

            enriched_finding = dict(finding)

            enriched_finding["risk_score"] = score
            enriched_finding["priority"] = priority

            findings.append(enriched_finding)

        return {
            "rule": self.analysis.get("rule"),
            "target": self.analysis.get("target"),
            "status": self.analysis.get("status"),
            "confidence": self.analysis.get("confidence"),
            "findings": findings,
        }