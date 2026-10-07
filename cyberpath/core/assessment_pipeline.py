from cyberpath.input.nmap_xml_parser import NmapXMLParser
from cyberpath.analyzer.normalizer import TargetNormalizer
from cyberpath.analyzer.context import TargetContext
from cyberpath.analyzer.rule_engine import RuleEngine
from cyberpath.core.check_executor import CheckExecutor
from cyberpath.analyzer.finding_analyzer import FindingAnalyzer
from cyberpath.analyzer.risk_engine import RiskEngine


class AssessmentPipeline:
    """Run the CyberPath security assessment pipeline."""

    def __init__(self, xml_file):
        self.xml_file = xml_file

    def run(self):
        """Execute the complete assessment pipeline."""

        parser = NmapXMLParser(self.xml_file)
        scan_data = parser.parse()

        normalizer = TargetNormalizer()
        normalized_data = normalizer.normalize(
            scan_data
        )

        context_engine = TargetContext(
            normalized_data
        )

        context = context_engine.build_context()

        rule_engine = RuleEngine(context)

        execution_plan = (
            rule_engine.build_execution_plan()
        )

        rules = execution_plan["rules"]

        executor = CheckExecutor()

        check_results = []

        for service in context["open_services"]:

            service_name = service.get(
                "service"
            )

            host = service.get(
                "host"
            )

            port = service.get(
                "port"
            )

            protocol = service.get(
                "protocol",
                "tcp",
            )

            if service_name == "http":

                target = (
                    f"http://{host}:{port}"
                )

                applicable_rules = [
                    rule
                    for rule in rules
                    if rule.startswith("HTTP_")
                ]

                service_results = (
                    executor.execute_rules(
                        applicable_rules,
                        target,
                        port,
                    )
                )

                check_results.extend(
                    service_results
                )

            elif service_name == "https":

                target = (
                    f"https://{host}:{port}"
                )

                applicable_rules = [
                    rule
                    for rule in rules
                    if rule.startswith("HTTPS_")
                ]

                service_results = (
                    executor.execute_rules(
                        applicable_rules,
                        target,
                        port,
                    )
                )

                check_results.extend(
                    service_results
                )

            elif service_name == "ssh":

                target = host

                applicable_rules = [
                    rule
                    for rule in rules
                    if rule.startswith("SSH_")
                ]

                service_results = (
                    executor.execute_rules(
                        applicable_rules,
                        target,
                        port,
                    )
                )

                check_results.extend(
                    service_results
                )

        analyses = []

        for check_result in check_results:

            analyzer = FindingAnalyzer(
                check_result
            )

            analysis = analyzer.analyze()

            analyses.append(
                analysis
            )

        risk_results = []

        for analysis in analyses:

            risk_engine = RiskEngine(
                analysis
            )

            risk_result = risk_engine.analyze()

            risk_results.append(
                risk_result
            )

        return {
            "scanner": scan_data.get(
                "scanner"
            ),
            "context": context,
            "execution_plan": execution_plan,
            "check_results": check_results,
            "analyses": analyses,
            "risk_results": risk_results,
        }